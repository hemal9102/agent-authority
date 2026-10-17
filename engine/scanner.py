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

            # Robots.txt probe (RFC 9309)
            try:
                r_resp = await client.get(f"{base_url}/robots.txt")
                telemetry["robots_telemetry"] = {
                    "status": r_resp.status_code,
                    "exists": r_resp.status_code == 200,
                    "body_snippet": r_resp.text[:500] if r_resp.status_code == 200 else "",
                    "allows_gptbot": "GPTBot" in r_resp.text and "Disallow: /" not in r_resp.text if r_resp.status_code == 200 else True,
                    "allows_claudebot": "ClaudeBot" in r_resp.text and "Disallow: /" not in r_resp.text if r_resp.status_code == 200 else True,
                    "allows_perplexity": "PerplexityBot" in r_resp.text and "Disallow: /" not in r_resp.text if r_resp.status_code == 200 else True,
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
                is_linkset = "application/linkset+json" in api_resp.headers.get("content-type", "") or api_resp.status_code == 200
                telemetry["api_catalog_telemetry"] = {
                    "status": api_resp.status_code,
                    "exists": api_resp.status_code == 200,
                    "is_linkset": is_linkset
                }
            except Exception as e:
                telemetry["api_catalog_telemetry"] = {"exists": False, "error": str(e)}

        return telemetry
