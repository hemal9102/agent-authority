"""
Agent Authority Core RFC Scanner Engine
Deterministic asynchronous network, protocol, and AST evaluation.
"""

import time
import ssl
import socket
import re
import json
import urllib.parse
from typing import Dict, Any, List, Optional
import httpx
from bs4 import BeautifulSoup

USER_AGENT = "AgentAuthorityBot/1.0 (+https://github.com/hemal9102/agent-authority; standards-grounded diagnostic)"

# AI retrieval user-agent product tokens evaluated against robots.txt (RFC 9309).
AI_AGENT_TOKENS = ["GPTBot", "ClaudeBot", "PerplexityBot", "Google-Extended", "CCBot"]


def robots_allows(robots_text: str, agent: str, path: str = "/") -> bool:
    """
    Evaluate whether `agent` is allowed to fetch `path` under RFC 9309.

    Implements the Robots Exclusion Protocol matching semantics (RFC 9309 Sec.
    2.2.1 grouping and Sec. 2.2.2 longest-match):
      * Records are grouped by case-insensitive User-agent product token.
      * A group whose token exactly matches the agent wins; otherwise the
        '*' group applies; if neither exists, access is allowed.
      * Within the applicable group, the Allow/Disallow rule with the longest
        matching path prefix wins. On an equal-length tie, Allow wins.
      * '*' wildcards and a trailing '$' end-anchor in rule paths are honored.
      * An empty Disallow value means "allow everything".
    Returns True (allowed) or False (disallowed).
    """
    if not robots_text:
        return True

    groups = []            # list of (set_of_agent_tokens_lower, [(is_allow, path)])
    cur_agents = []
    cur_rules = []
    seen_rule_in_group = False

    def flush():
        nonlocal cur_agents, cur_rules, seen_rule_in_group
        if cur_agents:
            groups.append((set(cur_agents), cur_rules))
        cur_agents, cur_rules, seen_rule_in_group = [], [], False

    for raw in robots_text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field, _, value = line.partition(":")
        field = field.strip().lower()
        value = value.strip()
        if field == "user-agent":
            # A user-agent line after rules starts a new group.
            if seen_rule_in_group:
                flush()
            cur_agents.append(value.lower())
        elif field in ("allow", "disallow"):
            seen_rule_in_group = True
            cur_rules.append((field == "allow", value))
        # Other fields (Sitemap, Crawl-delay, etc.) are ignored for matching.
    flush()

    # Match on the leading product token (RFC 9309 Sec. 2.2.1), case-insensitive,
    # so a versioned/compound UA string ("GPTBot/1.2") still maps to its group.
    agent_l = agent.lower().split("/", 1)[0].split()[0] if agent.strip() else ""
    rules = None
    for agents, grules in groups:          # exact token match first
        if agent_l in agents:
            rules = grules
            break
    if rules is None:                      # fall back to the '*' group
        for agents, grules in groups:
            if "*" in agents:
                rules = grules
                break
    if rules is None:                      # no applicable group => allowed
        return True

    def _canon(s: str) -> str:
        """Canonicalize percent-escapes of UNRESERVED octets (RFC 9309 Sec.
        2.2.2 / RFC 3986): decode only %XX for ALPHA/DIGIT/-/./_/~ so that
        '/%7Ejoe' and '/~joe' compare equal. Reserved octets (e.g. %2F) are
        left encoded so path structure is preserved."""
        def repl(m):
            o = int(m.group(1), 16)
            c = chr(o)
            if c.isalnum() or c in "-._~":
                return c
            return "%" + m.group(1).upper()
        return re.sub(r"%([0-9A-Fa-f]{2})", repl, s)

    def rule_matches(pattern: str, target: str):
        """Return matched length if pattern matches target prefix, else -1.
        Length is the ORIGINAL pattern length (RFC 9309 counts pattern octets)."""
        if pattern == "":
            return -1
        regex = re.escape(_canon(pattern)).replace(r"\*", ".*")
        if regex.endswith(r"\$"):
            regex = regex[:-2] + "$"
        return len(pattern) if re.match(regex, _canon(target)) else -1

    best_len = -1
    best_allow = True
    for is_allow, pattern in rules:
        if pattern == "" and not is_allow:
            # "Disallow:" with empty value explicitly allows everything.
            if 0 > best_len:
                best_len, best_allow = 0, True
            continue
        mlen = rule_matches(pattern, path)
        if mlen > best_len or (mlen == best_len and is_allow):
            best_len, best_allow = mlen, is_allow
    return best_allow if best_len >= 0 else True

def probe_ssl_handshake(hostname: str, port: int = 443) -> Dict[str, Any]:
    """
    Direct low-level TLS handshake probe using standard library ssl.
    Bypasses high-level HTTP client abstractions to guarantee accurate RFC 8446 verification.
    """
    context = ssl.create_default_context()
    t0 = time.perf_counter()
    try:
        with socket.create_connection((hostname, port), timeout=3.5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
                version = ssock.version()
                cipher = ssock.cipher()
                return {
                    "reachable": True,
                    "tls_version": version,
                    "is_tls_13": version == "TLSv1.3",
                    "cipher": cipher[0] if cipher else None,
                    "handshake_ms": elapsed_ms
                }
    except Exception as e:
        return {
            "reachable": False,
            "tls_version": None,
            "is_tls_13": False,
            "error": str(e),
            "handshake_ms": round((time.perf_counter() - t0) * 1000, 2)
        }

def parse_link_headers(link_headers: List[str]) -> Dict[str, List[Dict[str, str]]]:
    """
    Parses RFC 8288 Web Linking headers into structured relations.
    Supports comma-separated link values and parameterized link targets.
    """
    relations = {}
    for header in link_headers:
        parts = re.split(r',\s*(?=<)', header)
        for part in parts:
            match = re.match(r'<([^>]+)>(.*)', part.strip())
            if not match:
                continue
            uri, params_str = match.groups()
            params = {}
            for p in re.findall(r'([a-zA-Z*_-]+)\s*=\s*(?:"([^"]*)"|([^;\s,]+))', params_str):
                key = p[0].lower()
                val = p[1] if p[1] else p[2]
                params[key] = val
            rel = params.get("rel", "alternate").lower()
            if rel not in relations:
                relations[rel] = []
            relations[rel].append({"target": uri, "params": params})
    return relations

def evaluate_jsonld_ast(scripts: List[str]) -> Dict[str, Any]:
    """
    Deterministic evaluation of W3C JSON-LD 1.1 AST without black-box booleans.
    Scores 4 concrete grammatical sub-checks:
      1. Valid JSON parse (RFC 8259)
      2. W3C @context referencing schema.org
      3. Structural entity typing (@type present on nodes)
      4. RFC 3986 absolute URI validation for sameAs entity bindings
    """
    summary = {
        "blocks_count": len(scripts),
        "parses_json": False,
        "valid_context": False,
        "nodes_typed": False,
        "sameas_count": 0,
        "absolute_sameas_uris": False,
        "types_found": [],
        "entities": []
    }
    if not scripts:
        return summary

    all_nodes = []
    any_valid_json = False
    context_found = False

    for raw in scripts:
        try:
            data = json.loads(raw)
            any_valid_json = True
        except (json.JSONDecodeError, TypeError):
            continue

        # Extract @context
        if isinstance(data, dict):
            ctx = data.get("@context", "")
            if "schema.org" in str(ctx):
                context_found = True
            if "@graph" in data and isinstance(data["@graph"], list):
                all_nodes.extend(data["@graph"])
            else:
                all_nodes.append(data)
        elif isinstance(data, list):
            all_nodes.extend(data)

    summary["parses_json"] = any_valid_json
    summary["valid_context"] = context_found

    if all_nodes:
        types = set()
        all_typed = True
        sameas_uris = []
        for node in all_nodes:
            if isinstance(node, dict):
                t = node.get("@type")
                if t:
                    if isinstance(t, list):
                        types.update(t)
                    else:
                        types.add(str(t))
                else:
                    all_typed = False
                
                sa = node.get("sameAs", [])
                if isinstance(sa, str):
                    sameas_uris.append(sa)
                elif isinstance(sa, list):
                    sameas_uris.extend([item for item in sa if isinstance(item, str)])

        summary["types_found"] = sorted(list(types))
        summary["nodes_typed"] = all_typed and len(types) > 0
        summary["sameas_count"] = len(sameas_uris)
        if sameas_uris:
            summary["absolute_sameas_uris"] = all(
                u.startswith("http://") or u.startswith("https://") for u in sameas_uris
            )

    return summary

class AsyncRFCScanner:
    """
    Production-grade asynchronous diagnostic scanner.
    Implements resilient redirect following, HEAD->GET fallback, and detailed RFC telemetry.
    """
    def __init__(self, timeout: float = 8.0, max_redirects: int = 5):
        self.timeout = timeout
        self.max_redirects = max_redirects

    async def scan_domain(self, target: str) -> Dict[str, Any]:
        target = target.strip()
        if not target.startswith("http://") and not target.startswith("https://"):
            target = "https://" + target

        parsed_url = urllib.parse.urlparse(target)
        hostname = parsed_url.hostname or target
        
        telemetry = {
            "input_target": target,
            "hostname": hostname,
            "scan_timestamp": time.time(),
            "redirect_chain": [],
            "final_url": target,
            "ssl_telemetry": {},
            "root_status": None,
            "ttfb_ms": None,
            "headers": {},
            "link_relations": {},
            "robots_telemetry": {},
            "llmstxt_telemetry": {},
            "api_catalog_telemetry": {},
            "jsonld_telemetry": {},
            "content_density": {},
            "errors": []
        }

        # 1. Low-level SSL handshake probe
        telemetry["ssl_telemetry"] = probe_ssl_handshake(hostname)

        # 2. Resilient Root Page Prober (Primary HTML representation)
        client_headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br"
        }

        async with httpx.AsyncClient(
            follow_redirects=True,
            max_redirects=self.max_redirects,
            timeout=self.timeout,
            headers=client_headers,
            verify=False
        ) as client:
            t0 = time.perf_counter()
            try:
                # Attempt GET directly to measure true response payload & density
                resp = await client.get(target)
                telemetry["ttfb_ms"] = round((time.perf_counter() - t0) * 1000, 2)
                telemetry["root_status"] = resp.status_code
                telemetry["final_url"] = str(resp.url)
                
                # Record redirect hops
                if resp.history:
                    for h in resp.history:
                        telemetry["redirect_chain"].append({
                            "status": h.status_code,
                            "url": str(h.url)
                        })

                # Headers capture & normalization
                headers_dict = {k.lower(): v for k, v in resp.headers.items()}
                telemetry["headers"] = headers_dict

                # Parse RFC 8288 Link headers
                raw_links = resp.headers.get_list("link")
                telemetry["link_relations"] = parse_link_headers(raw_links)

                # Content Density & DOM AST
                html_bytes = resp.content
                raw_len = len(html_bytes)
                soup = BeautifulSoup(resp.text, "html.parser")

                # JSON-LD AST extraction
                jsonld_scripts = []
                for s in soup.find_all("script", type="application/ld+json"):
                    content = s.get_text(strip=True)
                    if content:
                        jsonld_scripts.append(content)
                telemetry["jsonld_telemetry"] = evaluate_jsonld_ast(jsonld_scripts)

                # Text-to-markup density
                visible_text = soup.get_text(separator=" ", strip=True)
                words = len(visible_text.split())
                density_ratio = round((len(visible_text) / raw_len * 100), 2) if raw_len > 0 else 0
                telemetry["content_density"] = {
                    "payload_bytes": raw_len,
                    "visible_words": words,
                    "density_ratio_pct": density_ratio
                }

            except httpx.HTTPError as e:
                telemetry["errors"].append(f"Root probe error: {str(e)}")
                telemetry["root_status"] = 0

            # 3. Parallel probing of standard discovery paths
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            if telemetry["final_url"] != target:
                final_p = urllib.parse.urlparse(telemetry["final_url"])
                base_url = f"{final_p.scheme}://{final_p.netloc}"

            # Robots.txt probe (RFC 9309) -- full longest-match evaluation.
            try:
                r_resp = await client.get(f"{base_url}/robots.txt")
                exists = r_resp.status_code == 200
                body = r_resp.text if exists else ""
                # Per-token allow decision for the site root, per RFC 9309.
                per_agent = {
                    token: robots_allows(body, token, "/")
                    for token in AI_AGENT_TOKENS
                }
                telemetry["robots_telemetry"] = {
                    "status": r_resp.status_code,
                    "exists": exists,
                    "body_snippet": body[:500],
                    "agents_evaluated": AI_AGENT_TOKENS,
                    "agent_allowed": per_agent,
                    "blocked_agents": [t for t, ok in per_agent.items() if not ok],
                    # Back-compat keys retained for the scorer.
                    "allows_gptbot": per_agent.get("GPTBot", True),
                    "allows_claudebot": per_agent.get("ClaudeBot", True),
                    "allows_perplexity": per_agent.get("PerplexityBot", True),
                }
            except Exception as e:
                telemetry["robots_telemetry"] = {"exists": False, "error": str(e)}

            # /llms.txt probe (Community Standard)
            try:
                l_resp = await client.get(f"{base_url}/llms.txt")
                telemetry["llmstxt_telemetry"] = {
                    "status": l_resp.status_code,
                    "exists": l_resp.status_code == 200,
                    "length": len(l_resp.text) if l_resp.status_code == 200 else 0
                }
            except Exception as e:
                telemetry["llmstxt_telemetry"] = {"exists": False, "error": str(e)}

            # /.well-known/api-catalog probe (RFC 9727)
            try:
                api_resp = await client.get(f"{base_url}/.well-known/api-catalog")
                content_type = api_resp.headers.get("content-type", "")
                # RFC 9727: the catalog's primary representation is
                # application/linkset+json. Require the media type, not just a 200.
                is_linkset = ("application/linkset+json" in content_type
                              and api_resp.status_code == 200)
                telemetry["api_catalog_telemetry"] = {
                    "status": api_resp.status_code,
                    "exists": api_resp.status_code == 200,
                    "content_type": content_type,
                    "is_linkset": is_linkset
                }
            except Exception as e:
                telemetry["api_catalog_telemetry"] = {"exists": False, "error": str(e)}

        return telemetry
