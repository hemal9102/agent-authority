"""
Agent Authority Deterministic Scoring Algorithm
Pure functional implementation of the 4 RFC-grounded pillars.
"""

from typing import Dict, Any, List

# Authoritative Weight Distribution
WEIGHTS = {
    "discoverability": 0.30,
    "semantic_grounding": 0.30,
    "content_efficiency": 0.25,
    "transport": 0.15
}

def score_telemetry(t: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pure mathematical evaluation over captured telemetry.
    Returns:
      overall_score (0-100)
      pillar_scores {discoverability, semantic_grounding, content_efficiency, transport}
      ledger [list of individual check objects]
    """
    ledger = []
    
    # ----------------------------------------------------
    # PILLAR 1: AGENT DISCOVERABILITY (Weight: 30%)
    # ----------------------------------------------------
    p1_points = 0
    p1_max = 100
    
    # Check 1.1: RFC 9309 (Robots Exclusion Protocol)
    robots = t.get("robots_telemetry", {})
    if robots.get("exists"):
        if robots.get("allows_gptbot", True) and robots.get("allows_claudebot", True) and robots.get("allows_perplexity", True):
            p1_points += 25
            ledger.append({
                "pillar": "discoverability",
                "status": "PASS",
                "title": "Robots Exclusion Policy Allows AI Retrievers",
                "rfc_ref": "RFC 9309",
                "rfc_url": "https://www.rfc-editor.org/rfc/rfc9309",
                "observation": "Robots.txt is active and allows standard generative AI user-agents.",
                "fix_snippet": "# robots.txt\nUser-agent: GPTBot\nAllow: /\nUser-agent: ClaudeBot\nAllow: /"
            })
        else:
            p1_points += 10
            ledger.append({
                "pillar": "discoverability",
                "status": "WARN",
                "title": "Robots.txt Blocks Select AI Agents",
                "rfc_ref": "RFC 9309",
                "rfc_url": "https://www.rfc-editor.org/rfc/rfc9309",
                "observation": "One or more autonomous retrieval crawlers are explicitly disallowed.",
                "fix_snippet": "User-agent: GPTBot\nAllow: /\nUser-agent: PerplexityBot\nAllow: /"
            })
    else:
        ledger.append({
            "pillar": "discoverability",
            "status": "FAIL",
            "title": "Missing robots.txt Policy",
            "rfc_ref": "RFC 9309",
            "rfc_url": "https://www.rfc-editor.org/rfc/rfc9309",
            "observation": "No robots.txt was detected at the origin root.",
            "fix_snippet": "User-agent: *\nAllow: /\nSitemap: https://yourdomain.com/sitemap.xml"
        })

    # Check 1.2: RFC 8288 Web Linking for Context Manifest (llms.txt)
    links = t.get("link_relations", {})
    has_describedby = "describedby" in links
    has_llmstxt_probe = t.get("llmstxt_telemetry", {}).get("exists")
    
    if has_describedby and has_llmstxt_probe:
        p1_points += 35
        ledger.append({
            "pillar": "discoverability",
            "status": "PASS",
            "title": "Context Manifest Advertised via RFC 8288",
            "rfc_ref": "RFC 8288",
            "rfc_url": "https://www.rfc-editor.org/rfc/rfc8288",
            "observation": "Link: </llms.txt>; rel=\"describedby\" header declared and endpoint verified.",
            "fix_snippet": "Link: </llms.txt>; rel=\"describedby\"; type=\"text/plain\""
        })
    elif has_llmstxt_probe:
        p1_points += 20
        ledger.append({
            "pillar": "discoverability",
            "status": "WARN",
            "title": "Context Manifest Exists but Lacks RFC 8288 Header",
            "rfc_ref": "RFC 8288",
            "rfc_url": "https://www.rfc-editor.org/rfc/rfc8288",
            "observation": "/llms.txt is present but not advertised in HTTP Link response headers.",
            "fix_snippet": "# Cloudflare Worker / Nginx Header:\nadd_header Link '</llms.txt>; rel=\"describedby\"; type=\"text/plain\"';"
        })
    else:
        ledger.append({
            "pillar": "discoverability",
            "status": "FAIL",
            "title": "Missing RFC 8288 Context Manifest",
            "rfc_ref": "RFC 8288",
            "rfc_url": "https://www.rfc-editor.org/rfc/rfc8288",
            "observation": "No machine-readable /llms.txt manifest advertised.",
            "fix_snippet": "Link: </llms.txt>; rel=\"describedby\"; type=\"text/plain\""
        })

    # Check 1.3: RFC 9727 (api-catalog) & RFC 8615
    has_api_catalog = "api-catalog" in links or t.get("api_catalog_telemetry", {}).get("exists")
    if has_api_catalog:
        p1_points += 25
        ledger.append({
            "pillar": "discoverability",
            "status": "PASS",
            "title": "API Catalog Advertised (RFC 9727)",
            "rfc_ref": "RFC 9727",
            "rfc_url": "https://www.rfc-editor.org/info/rfc9727/",
            "observation": "Endpoint /.well-known/api-catalog or Link rel=\"api-catalog\" detected.",
            "fix_snippet": "Link: </.well-known/api-catalog>; rel=\"api-catalog\""
        })
    else:
        ledger.append({
            "pillar": "discoverability",
            "status": "FAIL",
            "title": "Missing RFC 9727 API Catalog",
            "rfc_ref": "RFC 9727",
            "rfc_url": "https://www.rfc-editor.org/info/rfc9727/",
            "observation": "Autonomous agents cannot discover machine-callable API specifications.",
            "fix_snippet": "Link: </.well-known/api-catalog>; rel=\"api-catalog\""
        })

    # Check 1.4: Service Documentation Linking (RFC 8631)
    if "service-doc" in links or "service-desc" in links:
        p1_points += 15
        ledger.append({
            "pillar": "discoverability",
            "status": "PASS",
            "title": "Service Documentation Link Declared (RFC 8631)",
            "rfc_ref": "RFC 8631",
            "rfc_url": "https://www.rfc-editor.org/rfc/rfc8631",
            "observation": "Explicit rel=\"service-doc\" provides machine guidance to agents.",
            "fix_snippet": "Link: </services>; rel=\"service-doc\""
        })
    else:
        ledger.append({
            "pillar": "discoverability",
            "status": "WARN",
            "title": "No Service Documentation Relation Declared",
            "rfc_ref": "RFC 8631",
            "rfc_url": "https://www.rfc-editor.org/rfc/rfc8631",
            "observation": "Optional rel=\"service-doc\" not advertised.",
            "fix_snippet": "Link: </docs>; rel=\"service-doc\""
        })

    # ----------------------------------------------------
    # PILLAR 2: SEMANTIC ENTITY GROUNDING (Weight: 30%)
    # ----------------------------------------------------
    p2_points = 0
    jsonld = t.get("jsonld_telemetry", {})
    
    # 2.1 JSON Parse
    if jsonld.get("parses_json"):
        p2_points += 25
        ledger.append({
            "pillar": "semantic_grounding",
            "status": "PASS",
            "title": "W3C JSON-LD Graph Parsed Successfully",
            "rfc_ref": "W3C JSON-LD 1.1",
            "rfc_url": "https://www.w3.org/TR/json-ld11/",
            "observation": f"Extracted valid JSON-LD AST across {jsonld.get('blocks_count', 1)} block(s).",
            "fix_snippet": "<script type=\"application/ld+json\">{\"@context\": \"https://schema.org\"}</script>"
        })
    else:
        ledger.append({
            "pillar": "semantic_grounding",
            "status": "FAIL",
            "title": "Missing or Malformed JSON-LD",
            "rfc_ref": "W3C JSON-LD 1.1",
            "rfc_url": "https://www.w3.org/TR/json-ld11/",
            "observation": "No parseable JSON-LD graph detected. LLMs must guess entity relationships.",
            "fix_snippet": "<script type=\"application/ld+json\">{\n  \"@context\": \"https://schema.org\",\n  \"@type\": \"Organization\"\n}</script>"
        })

    # 2.2 Schema.org Context
    if jsonld.get("valid_context"):
        p2_points += 25
        ledger.append({
            "pillar": "semantic_grounding",
            "status": "PASS",
            "title": "Canonical Schema.org Context Resolved",
            "rfc_ref": "Schema.org Ontology",
            "rfc_url": "https://schema.org/",
            "observation": "@context correctly references https://schema.org ontology.",
            "fix_snippet": "\"@context\": \"https://schema.org\""
        })
    else:
        ledger.append({
            "pillar": "semantic_grounding",
            "status": "FAIL",
            "title": "Unresolved Schema Context",
            "rfc_ref": "Schema.org Ontology",
            "rfc_url": "https://schema.org/",
            "observation": "@context is missing or does not resolve to schema.org.",
            "fix_snippet": "\"@context\": \"https://schema.org\""
        })

    # 2.3 Structural Entity Typing
    if jsonld.get("nodes_typed"):
        p2_points += 25
        ledger.append({
            "pillar": "semantic_grounding",
            "status": "PASS",
            "title": "Entities Explicitly Typed",
            "rfc_ref": "W3C RDF Schema",
            "rfc_url": "https://www.w3.org/TR/rdf-schema/",
            "observation": f"All nodes define explicit @type: {', '.join(jsonld.get('types_found', [])[:4])}",
            "fix_snippet": "\"@type\": [\"Organization\", \"ProfessionalService\"]"
        })
    else:
        ledger.append({
            "pillar": "semantic_grounding",
            "status": "WARN",
            "title": "Untyped Graph Nodes Detected",
            "rfc_ref": "W3C RDF Schema",
            "rfc_url": "https://www.w3.org/TR/rdf-schema/",
            "observation": "One or more nodes in graph lack explicit @type declaration.",
            "fix_snippet": "\"@type\": \"Organization\""
        })

    # 2.4 RFC 3986 sameAs Absolute URI Anchoring
    if jsonld.get("sameas_count", 0) > 0 and jsonld.get("absolute_sameas_uris"):
        p2_points += 25
        ledger.append({
            "pillar": "semantic_grounding",
            "status": "PASS",
            "title": "Knowledge Graph sameAs Anchoring Active",
            "rfc_ref": "RFC 3986",
            "rfc_url": "https://www.rfc-editor.org/rfc/rfc3986",
            "observation": f"Detected {jsonld.get('sameas_count')} valid absolute URI entity bindings.",
            "fix_snippet": "\"sameAs\": [\"https://www.wikidata.org/wiki/Q...\", \"https://linkedin.com/...\"]"
        })
    else:
        ledger.append({
            "pillar": "semantic_grounding",
            "status": "WARN",
            "title": "Missing Canonical sameAs Entity URIs",
            "rfc_ref": "RFC 3986",
            "rfc_url": "https://www.rfc-editor.org/rfc/rfc3986",
            "observation": "Zero external knowledge graph entity anchors (Wikidata, Crunchbase) bound in JSON-LD.",
            "fix_snippet": "\"sameAs\": [\"https://www.wikidata.org/wiki/Q192490\"]"
        })

    # ----------------------------------------------------
    # PILLAR 3: CONTENT EFFICIENCY & INGESTION (Weight: 25%)
    # ----------------------------------------------------
    p3_points = 0
    has_md_link = "alternate" in links and any("markdown" in l.get("params", {}).get("type", "") for l in links["alternate"])
    density = t.get("content_density", {})
    ratio = density.get("density_ratio_pct", 0)

    # 3.1 Markdown Mirror Advertisement (RFC 8288 / RFC 7763)
    if has_md_link:
        p3_points += 50
        ledger.append({
            "pillar": "content_efficiency",
            "status": "PASS",
            "title": "Markdown Alternate Representation Advertised",
            "rfc_ref": "RFC 7763 / RFC 8288",
            "rfc_url": "https://www.rfc-editor.org/rfc/rfc7763",
            "observation": "Link: </md/index.md>; rel=\"alternate\"; type=\"text/markdown\" active.",
            "fix_snippet": "Link: </md/index.md>; rel=\"alternate\"; type=\"text/markdown\""
        })
    else:
        ledger.append({
            "pillar": "content_efficiency",
            "status": "FAIL",
            "title": "No Markdown Alternate Stream Advertised",
            "rfc_ref": "RFC 7763 / RFC 8288",
            "rfc_url": "https://www.rfc-editor.org/rfc/rfc7763",
            "observation": "Autonomous agents must ingest heavy HTML/JS bundles. Token overhead elevated.",
            "fix_snippet": "Link: </index.md>; rel=\"alternate\"; type=\"text/markdown\""
        })

    # 3.2 Content-to-Code Density Ratio
    if ratio >= 15.0:
        p3_points += 30
        ledger.append({
            "pillar": "content_efficiency",
            "status": "PASS",
            "title": "High Text-to-Markup Density Ratio",
            "rfc_ref": "Information Density",
            "rfc_url": "https://www.rfc-editor.org/rfc/rfc9110",
            "observation": f"Measured {ratio}% visible text density. Fast RAG token chunkability.",
            "fix_snippet": "Strip nested boilerplate containers and inline scripts."
        })
    elif ratio >= 7.0:
        p3_points += 15
        ledger.append({
            "pillar": "content_efficiency",
            "status": "WARN",
            "title": "Moderate Markup Bloat Detected",
            "rfc_ref": "Information Density",
            "rfc_url": "https://www.rfc-editor.org/rfc/rfc9110",
            "observation": f"Measured {ratio}% text density. Moderate DOM extraction overhead.",
            "fix_snippet": "Pre-render static semantic HTML and defer non-critical JS."
        })
    else:
        ledger.append({
            "pillar": "content_efficiency",
            "status": "FAIL",
            "title": "Severe Code Bloat (>93% Wasted Tokens)",
            "rfc_ref": "Information Density",
            "rfc_url": "https://www.rfc-editor.org/rfc/rfc9110",
            "observation": f"Measured {ratio}% text density. Over 93% of payload is script and markup noise.",
            "fix_snippet": "Provide clean markdown alternative mirror to bypass DOM parsing."
        })

    # 3.3 Emerging Content-Signal Directive
    headers = t.get("headers", {})
    if "content-signal" in headers:
        p3_points += 20
        ledger.append({
            "pillar": "content_efficiency",
            "status": "PASS",
            "title": "Content-Signal AI Directive Declared",
            "rfc_ref": "Content-Signal Spec",
            "rfc_url": "https://blog.cloudflare.com/content-independence-day-ai-options/",
            "observation": f"Header declared: {headers['content-signal']}",
            "fix_snippet": "Content-Signal: ai-train=no, search=yes, ai-input=yes"
        })
    else:
        ledger.append({
            "pillar": "content_efficiency",
            "status": "WARN",
            "title": "Missing Content-Signal Directive",
            "rfc_ref": "Content-Signal Spec",
            "rfc_url": "https://blog.cloudflare.com/content-independence-day-ai-options/",
            "observation": "No explicit AI crawler permission directives declared.",
            "fix_snippet": "Content-Signal: ai-train=no, search=yes, ai-input=yes"
        })

    # ----------------------------------------------------
    # PILLAR 4: TRANSPORT & EDGE CACHING (Weight: 15%)
    # ----------------------------------------------------
    p4_points = 0
    ssl_info = t.get("ssl_telemetry", {})
    ttfb = t.get("ttfb_ms", 9999)
    cache_status = headers.get("cf-cache-status", headers.get("x-cache", "")).upper()

    # 4.1 RFC 8446 TLS 1.3
    if ssl_info.get("is_tls_13"):
        p4_points += 35
        ledger.append({
            "pillar": "transport",
            "status": "PASS",
            "title": "RFC 8446 TLS 1.3 Negotiated (0-RTT/1-RTT)",
            "rfc_ref": "RFC 8446",
            "rfc_url": "https://www.rfc-editor.org/rfc/rfc8446",
            "observation": f"Negotiated {ssl_info.get('tls_version')} in {ssl_info.get('handshake_ms')}ms.",
            "fix_snippet": "Enable TLS 1.3 on edge CDN / Nginx ssl_protocols TLSv1.3;"
        })
    else:
        ledger.append({
            "pillar": "transport",
            "status": "WARN",
            "title": "Legacy TLS Protocol Detected",
            "rfc_ref": "RFC 8446",
            "rfc_url": "https://www.rfc-editor.org/rfc/rfc8446",
            "observation": f"Negotiated {ssl_info.get('tls_version') or 'Unknown'}. TLS 1.3 recommended.",
            "fix_snippet": "ssl_protocols TLSv1.3 TLSv1.2;"
        })

    # 4.2 RFC 9111 Edge Caching State
    if "HIT" in cache_status:
        p4_points += 35
        ledger.append({
            "pillar": "transport",
            "status": "PASS",
            "title": "Edge Cache HIT Active (RFC 9111)",
            "rfc_ref": "RFC 9111",
            "rfc_url": "https://www.rfc-editor.org/rfc/rfc9111",
            "observation": f"Edge cache returned status: {cache_status}. Origin compute bypassed.",
            "fix_snippet": "Cache-Control: public, max-age=14400, stale-while-revalidate=86400"
        })
    else:
        ledger.append({
            "pillar": "transport",
            "status": "WARN",
            "title": "Edge Cache MISS (Un-cached Origin Latency)",
            "rfc_ref": "RFC 9111",
            "rfc_url": "https://www.rfc-editor.org/rfc/rfc9111",
            "observation": f"Edge status: {cache_status or 'MISS/NONE'}. Request hit un-cached origin.",
            "fix_snippet": "Create Cloudflare Edge Cache Rule to cache HTML at the edge."
        })

    # 4.3 TTFB Latency Benchmark
    if ttfb <= 450:
        p4_points += 30
        ledger.append({
            "pillar": "transport",
            "status": "PASS",
            "title": "Ultra-Low Socket Latency (TTFB < 450ms)",
            "rfc_ref": "RFC 9110 §8.8",
            "rfc_url": "https://www.rfc-editor.org/rfc/rfc9110",
            "observation": f"Measured TTFB of {ttfb}ms.",
            "fix_snippet": "Maintain edge proxy caching and zstd/brotli compression."
        })
    elif ttfb <= 1200:
        p4_points += 15
        ledger.append({
            "pillar": "transport",
            "status": "WARN",
            "title": "Moderate Transport Latency",
            "rfc_ref": "RFC 9110 §8.8",
            "rfc_url": "https://www.rfc-editor.org/rfc/rfc9110",
            "observation": f"Measured TTFB of {ttfb}ms.",
            "fix_snippet": "Configure regional edge caching to drop latency below 450ms."
        })
    else:
        ledger.append({
            "pillar": "transport",
            "status": "FAIL",
            "title": "High Origin Latency Penalty (TTFB > 1.2s)",
            "rfc_ref": "RFC 9110 §8.8",
            "rfc_url": "https://www.rfc-editor.org/rfc/rfc9110",
            "observation": f"Measured TTFB of {ttfb}ms. Crawlers throttle bulk retrieval queues.",
            "fix_snippet": "Enable Edge HTML Caching on Cloudflare to drop TTFB to <100ms."
        })

    # ----------------------------------------------------
    # FINAL WEIGHTED AGGREGATION
    # ----------------------------------------------------
    p1_final = min(100, p1_points)
    p2_final = min(100, p2_points)
    p3_final = min(100, p3_points)
    p4_final = min(100, p4_points)

    overall_score = round(
        (p1_final * WEIGHTS["discoverability"]) +
        (p2_final * WEIGHTS["semantic_grounding"]) +
        (p3_final * WEIGHTS["content_efficiency"]) +
        (p4_final * WEIGHTS["transport"])
    )

    # Determine Grade
    if overall_score >= 80:
        grade = "Agent-Native Authority"
        tier = "OPTIMAL"
    elif overall_score >= 50:
        grade = "Partially Observable"
        tier = "MODERATE"
    else:
        grade = "Agent Blind"
        tier = "CRITICAL"

    return {
        "overall_score": overall_score,
        "grade": grade,
        "tier": tier,
        "pillar_scores": {
            "discoverability": p1_final,
            "semantic_grounding": p2_final,
            "content_efficiency": p3_final,
            "transport": p4_final
        },
        "weights": WEIGHTS,
        "ledger": ledger
    }
