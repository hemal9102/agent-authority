# Agent Authority (AA)

[![IETF Internet-Draft](https://img.shields.io/badge/IETF_I--D-draft--shah--agent--readiness--evaluation--00-blue.svg)](https://datatracker.ietf.org/doc/draft-shah-agent-readiness-evaluation/)
[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Standards](https://img.shields.io/badge/RFC_Grounded-RFC_9309_|_RFC_8288_|_RFC_9727_|_RFC_8446-cyan.svg)](https://www.rfc-editor.org/)

> **A Standards-Grounded Method and Reference Implementation for Evaluating Website Agent-Readiness**  
> Formally specified in IETF Internet-Draft: [`draft-shah-agent-readiness-evaluation-00`](https://datatracker.ietf.org/doc/draft-shah-agent-readiness-evaluation/).

---

## 🎯 What is Agent Authority?

**Agent Authority (AA)** is an open-source, deterministic diagnostic engine that measures how effectively an origin server supports autonomous AI retrieval agents, generative search crawlers, and LLM-driven ingestion pipelines (e.g., ChatGPT Search, Claude, Google AI Overviews, Perplexity).

Unlike subjective SEO scores or heuristic audits, Agent Authority is **grounded strictly in published IETF RFCs and W3C machine specifications**. It computes a deterministic, reproducible score between **0 and 100** by observing real server network behavior across four foundational pillars:

```
+-------------------------------------------------------------------------------+
|                        AGENT AUTHORITY SCORING ENGINE                         |
|             (Deterministic Weighted Score: 0 - 100 RFC Conformance)           |
+-----------------------+-----------------------+---------------+---------------+
|       PILLAR 1        |       PILLAR 2        |   PILLAR 3    |   PILLAR 4    |
| Agent Discoverability |  Semantic Grounding   |  Efficiency   |   Transport   |
|     (Weight: 30%)     |     (Weight: 30%)     | (Weight: 25%) | (Weight: 15%) |
+-----------------------+-----------------------+---------------+---------------+
| * RFC 9309 Robots     | * W3C JSON-LD 1.1 AST | * RFC 7763 MD | * RFC 8446    |
| * RFC 8288 Linking    | * Schema.org Context  | * RFC 8288 Alt|   TLS 1.3     |
| * RFC 9727 API Catalog| * Structural Typing   | * Text-to-code| * RFC 9111    |
| * RFC 8631 Service Doc| * RFC 3986 sameAs     | * Content-    |   Edge Cache  |
|                       |   Wikidata Anchoring  |   Signal      | * TTFB Latency|
+-----------------------+-----------------------+---------------+---------------+
```

---

## 🏛️ The Four Foundational Pillars

### 1. Agent Discoverability (30% Weight)
* **RFC 9309 (Robots Exclusion Protocol):** Validates origin policy and verifies non-blocking ingress rules for autonomous crawlers (`GPTBot`, `ClaudeBot`, `PerplexityBot`).
* **RFC 8288 (Web Linking):** Probes HTTP response headers for machine-readable context manifests (`Link: </llms.txt>; rel="describedby"`).
* **RFC 9727 & RFC 8615 (`api-catalog`):** Detects whether origin advertises machine-callable API catalogs at `/.well-known/api-catalog` or via `rel="api-catalog"`.
* **RFC 8631 (Service Documentation):** Probes machine documentation links via `rel="service-doc"`.

### 2. Semantic Entity Grounding (30% Weight)
* **W3C JSON-LD 1.1 AST Parsing:** Parses the Abstract Syntax Tree of `<script type="application/ld+json">` graphs to eliminate hallucination vectors.
* **Schema.org Ontology:** Enforces canonical URI resolution for `@context`.
* **Structural Typing:** Checks typed entities (`Organization`, `TechArticle`, `Product`, etc.).
* **RFC 3986 Absolute URI Anchoring:** Verifies explicit entity resolution via external knowledge graph bindings (`sameAs` links to Wikidata, Crunchbase, official social registries).

### 3. Content Efficiency & Ingestion (25% Weight)
* **RFC 7763 & RFC 8288 Markdown Mirror:** Probes HTTP `rel="alternate"` link headers advertising direct Markdown streams (`type="text/markdown"`), bypassing DOM and JavaScript execution penalties.
* **Text-to-Markup Density:** Measures the ratio of visible knowledge tokens against boilerplate HTML/CSS/JS payload.
* **Content-Signal Directives:** Inspects emerging permission headers (`Content-Signal: ai-train=..., search=...`).

### 4. Transport & Edge Caching (15% Weight)
* **RFC 8446 (TLS 1.3):** Probes low-level cryptographic handshakes for 0-RTT/1-RTT performance.
* **RFC 9111 (HTTP Caching):** Verifies edge CDN caching states (`HIT`) and cache-control headers to prevent origin rate throttling.
* **Socket Latency (TTFB):** Benchmarks Time-to-First-Byte origin responsiveness.

---

## 🚀 Quickstart & Reference Implementation

### Installation

```bash
git clone https://github.com/hemal9102/agent-authority.git
cd agent-authority
pip install -r requirements.txt
```

### 1. Run via CLI

Audit any domain directly in your terminal:

```bash
python cli.py tensix.in
```

Or output machine-readable JSON:

```bash
python cli.py tensix.in --json
```

### 2. Launch Web Server & Dashboard

Start the high-performance diagnostic web application and API:

```bash
python -m uvicorn server:app --host 127.0.0.1 --port 8000 --reload
```

Open your browser at `http://127.0.0.1:8000`.

---

## 🛡️ Dynamic Shield Badge

Embed a real-time, dynamic SVG badge directly in your GitHub `README.md` or website:

```markdown
[![Agent Authority](http://127.0.0.1:8000/api/badge/tensix.in)](http://127.0.0.1:8000)
```

The badge dynamically recalculates the origin's score and assigns the standard status tier:
* **80–100:** `Agent-Native Authority` (Emerald Green `#10b981`)
* **50–79:** `Partially Observable` (Amber `#f59e0b`)
* **0–49:** `Agent Blind` (Red `#ef4444`)

---

## 📜 Standards Citation

If referencing Agent Authority in research, protocol implementations, or diagnostic tools, cite the official IETF document:

```text
Shah, H. K., "A Standards-Grounded Method for Evaluating Website Agent-Readiness",
draft-shah-agent-readiness-evaluation-00, Internet Engineering Task Force (IETF),
October 2026, <https://datatracker.ietf.org/doc/draft-shah-agent-readiness-evaluation/>.
```

---

## ⚖️ License

MIT License. Copyright (c) 2026 H. K. Shah / TENSIX.
