# Agent Authority (AA)

> **A Standards-Grounded Method and Reference Implementation for Evaluating Website Agent-Readiness**  
> Based on IETF Internet-Draft: `draft-shah-agent-readiness-evaluation-00`

---

## 🎯 Overview

**Agent Authority (AA)** is an open, deterministic diagnostic platform that measures how effectively a website supports autonomous AI agents and generative search engines (ChatGPT Search, Google AI Overviews, Perplexity, Claude).

Unlike subjective SEO metrics, Agent Authority is grounded strictly in published **IETF RFCs and W3C machine specifications**. It derives an objective score between **0 and 100** across four foundational evaluation pillars:

1. **Agent Discoverability (30%):** RFC 9309 (Robots Exclusion Protocol), RFC 8288 (Web Linking), RFC 9727 (`api-catalog`), RFC 8615 (`/.well-known/`).
2. **Semantic Entity Grounding (30%):** W3C JSON-LD 1.1, Schema.org Ontology, RFC 3986 (URI Generic Syntax & Wikidata `sameAs` entity anchoring).
3. **Content Efficiency & Ingestion (25%):** RFC 7763 (Media-Type Registration for Markdown), RFC 8288 (Markdown Mirror advertisement via `rel="alternate"`), text-to-markup density.
4. **Transport & Edge Caching (15%):** RFC 9110 (HTTP Semantics), RFC 9111 (HTTP Caching & normalized `Vary`), RFC 8446 (TLS 1.3 0-RTT/1-RTT handshakes).

---

## 📄 Standards Reference

* **IETF Internet-Draft:** `draft-shah-agent-readiness-evaluation-00`
* **Author:** H. K. Shah (`TENSIX`)
* **Datatracker URL:** [https://datatracker.ietf.org/doc/draft-shah-agent-readiness-evaluation/](https://datatracker.ietf.org/doc/draft-shah-agent-readiness-evaluation/)

---

## 🚀 Quickstart & Reference Implementation

### Running Locally
```bash
git clone https://github.com/hemal9102/agent-authority.git
cd agent-authority
pip install -r requirements.txt
python server.py
```

### CLI Scan
```bash
python cli.py tensix.in
```

---

## ⚖️ License
MIT License. Copyright (c) 2026 H. K. Shah.
