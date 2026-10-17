/**
 * Agent Authority Frontend Controller
 * Interacts with /api/audit to render deterministic scoring & RFC ledger.
 */

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("auditForm");
  const targetInput = document.getElementById("targetInput");
  const submitBtn = document.getElementById("submitBtn");
  const btnSpinner = document.getElementById("btnSpinner");
  const btnText = submitBtn.querySelector(".btn-text");
  
  const errorAlert = document.getElementById("errorAlert");
  const errorMessage = document.getElementById("errorMessage");
  const resultsSection = document.getElementById("resultsSection");

  const samplePills = document.querySelectorAll(".sample-pill");

  // Hero Card Elements
  const heroScoreValue = document.getElementById("heroScoreValue");
  const gaugeProgress = document.getElementById("gaugeProgress");
  const heroTierBadge = document.getElementById("heroTierBadge");
  const resolvedProtocol = document.getElementById("resolvedProtocol");
  const resolvedHostname = document.getElementById("resolvedHostname");
  const targetGradeDesc = document.getElementById("targetGradeDesc");

  const metaTtfb = document.getElementById("metaTtfb");
  const metaTls = document.getElementById("metaTls");
  const metaDensity = document.getElementById("metaDensity");
  const metaEntities = document.getElementById("metaEntities");

  // Pillars
  const p1Score = document.getElementById("p1Score");
  const p1Bar = document.getElementById("p1Bar");
  const p2Score = document.getElementById("p2Score");
  const p2Bar = document.getElementById("p2Bar");
  const p3Score = document.getElementById("p3Score");
  const p3Bar = document.getElementById("p3Bar");
  const p4Score = document.getElementById("p4Score");
  const p4Bar = document.getElementById("p4Bar");

  // Ledger Elements
  const ledgerContainer = document.getElementById("ledgerContainer");
  const filterPills = document.querySelectorAll(".filter-pill");
  const countAll = document.getElementById("countAll");
  const countPass = document.getElementById("countPass");
  const countWarn = document.getElementById("countWarn");
  const countFail = document.getElementById("countFail");

  // Badge Elements
  const badgePreviewImg = document.getElementById("badgePreviewImg");
  const badgeMarkdownCode = document.getElementById("badgeMarkdownCode");
  const copyBadgeBtn = document.getElementById("copyBadgeBtn");

  let currentLedgerData = [];
  let currentActiveFilter = "all";

  // Event: Sample Pills
  samplePills.forEach(pill => {
    pill.addEventListener("click", () => {
      targetInput.value = pill.getAttribute("data-domain");
      runAudit(pill.getAttribute("data-domain"));
    });
  });

  // Event: Form Submit
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const val = targetInput.value.trim();
    if (val) runAudit(val);
  });

  async function runAudit(target) {
    // Show loading
    errorAlert.classList.add("hidden");
    submitBtn.disabled = true;
    btnSpinner.classList.remove("hidden");
    btnText.textContent = "Scanning RFCs...";
    
    try {
      const resp = await fetch("/api/audit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target })
      });

      if (!resp.ok) {
        const errJson = await resp.json().catch(() => ({}));
        throw new Error(errJson.detail || `Scan request failed with HTTP ${resp.status}`);
      }

      const data = await resp.json();
      renderResults(data);
    } catch (err) {
      errorMessage.textContent = err.message || "An unexpected error occurred during RFC audit.";
      errorAlert.classList.remove("hidden");
    } finally {
      submitBtn.disabled = false;
      btnSpinner.classList.add("hidden");
      btnText.textContent = "Audit Agent Authority";
    }
  }

  function renderResults(data) {
    const { telemetry, score } = data;
    currentLedgerData = score.ledger || [];

    // Protocol & Hostname
    const finalUrl = telemetry.final_url || targetInput.value;
    try {
      const u = new URL(finalUrl.startsWith("http") ? finalUrl : "https://" + finalUrl);
      resolvedProtocol.textContent = u.protocol.replace(":", "").toUpperCase();
      resolvedHostname.textContent = u.hostname;
    } catch {
      resolvedProtocol.textContent = "ORIGIN";
      resolvedHostname.textContent = telemetry.hostname || targetInput.value;
    }

    // Overall Score & Gauge Animation
    const finalScore = score.overall_score;
    animateGauge(finalScore);

    // Tier & Grade
    heroTierBadge.textContent = score.grade;
    if (finalScore >= 80) {
      heroTierBadge.style.color = "var(--color-green)";
      heroTierBadge.style.borderColor = "var(--color-green)";
      heroTierBadge.style.background = "var(--color-green-glow)";
      gaugeProgress.style.stroke = "var(--color-green)";
      targetGradeDesc.textContent = "Optimal Agent Authority. Origins with scores >= 80 are natively prioritized and reliably indexed by autonomous LLM agent fleets without hallucinations.";
    } else if (finalScore >= 50) {
      heroTierBadge.style.color = "var(--color-amber)";
      heroTierBadge.style.borderColor = "var(--color-amber)";
      heroTierBadge.style.background = "var(--color-amber-glow)";
      gaugeProgress.style.stroke = "var(--color-amber)";
      targetGradeDesc.textContent = "Partially Observable. Agent crawlers can parse basic entities but encounter high token overhead, missing link manifests, or unoptimized transport pipelines.";
    } else {
      heroTierBadge.style.color = "var(--color-red)";
      heroTierBadge.style.borderColor = "var(--color-red)";
      heroTierBadge.style.background = "var(--color-red-glow)";
      gaugeProgress.style.stroke = "var(--color-red)";
      targetGradeDesc.textContent = "Agent Blind (<50). Autonomous systems cannot reliably ground facts or discover machine endpoints. High token discard and citation hallucination risk.";
    }

    // Metadata Row
    metaTtfb.textContent = telemetry.ttfb_ms ? `${telemetry.ttfb_ms} ms` : "--";
    metaTls.textContent = telemetry.ssl_telemetry?.tls_version || "Unknown";
    metaDensity.textContent = telemetry.content_density?.density_ratio_pct ? `${telemetry.content_density.density_ratio_pct}%` : "0%";
    const entityTypes = telemetry.jsonld_telemetry?.types_found || [];
    metaEntities.textContent = entityTypes.length > 0 ? entityTypes.slice(0, 2).join(", ") : "None Detected";

    // Pillars
    const p = score.pillar_scores;
    setPillar(p1Score, p1Bar, p.discoverability);
    setPillar(p2Score, p2Bar, p.semantic_grounding);
    setPillar(p3Score, p3Bar, p.content_efficiency);
    setPillar(p4Score, p4Bar, p.transport);

    // Update Counts & Ledger
    updateLedgerCounts(currentLedgerData);
    renderLedgerItems(currentLedgerData, currentActiveFilter);

    // Update Badge Section
    const originHost = telemetry.hostname || "domain";
    const badgeUrl = `${window.location.origin}/api/badge/${originHost}`;
    badgePreviewImg.src = badgeUrl;
    badgeMarkdownCode.textContent = `[![Agent Authority](${badgeUrl})](${window.location.origin})`;

    // Reveal container smoothly
    resultsSection.classList.remove("hidden");
    resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function setPillar(scoreElem, barElem, val) {
    scoreElem.textContent = `${val}/100`;
    barElem.style.width = `${val}%`;
    if (val >= 80) {
      barElem.style.background = "var(--color-green)";
    } else if (val >= 50) {
      barElem.style.background = "var(--color-amber)";
    } else {
      barElem.style.background = "var(--color-red)";
    }
  }

  function animateGauge(score) {
    // Circumference = 2 * PI * 70 = ~440
    const circumference = 440;
    const offset = circumference - (circumference * score / 100);
    
    // Counter animation
    let start = 0;
    const duration = 1000;
    const startTime = performance.now();

    function updateCounter(now) {
      const progress = Math.min((now - startTime) / duration, 1);
      const current = Math.floor(progress * score);
      heroScoreValue.textContent = current;
      if (progress < 1) {
        requestAnimationFrame(updateCounter);
      } else {
        heroScoreValue.textContent = score;
      }
    }
    requestAnimationFrame(updateCounter);

    // Animate SVG stroke
    setTimeout(() => {
      gaugeProgress.style.strokeDashoffset = offset;
    }, 50);
  }

  function updateLedgerCounts(items) {
    countAll.textContent = items.length;
    countPass.textContent = items.filter(i => i.status === "PASS").length;
    countWarn.textContent = items.filter(i => i.status === "WARN").length;
    countFail.textContent = items.filter(i => i.status === "FAIL").length;
  }

  function renderLedgerItems(items, filter) {
    ledgerContainer.innerHTML = "";
    const filtered = filter === "all" ? items : items.filter(i => i.status === filter);

    if (filtered.length === 0) {
      ledgerContainer.innerHTML = `<div style="text-align:center; padding: 2rem; color: var(--text-dim);">No checks matching "${filter}".</div>`;
      return;
    }

    filtered.forEach((item, index) => {
      const card = document.createElement("div");
      card.className = "ledger-item";

      const showRemediation = item.status !== "PASS" && item.fix_snippet;

      card.innerHTML = `
        <div class="item-header">
          <div class="item-title-group">
            <span class="status-badge ${item.status}">${item.status}</span>
            <span class="item-title">${item.title}</span>
          </div>
          <a href="${item.rfc_url}" target="_blank" rel="noopener" class="rfc-link-btn" title="View Official RFC Clause">
            ${item.rfc_ref}
            <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
          </a>
        </div>
        <div class="item-observation">${item.observation}</div>
        ${showRemediation ? `
          <div class="item-remediation">
            <div class="remediation-header">
              <span class="remediation-label">Standard Remediation Directive</span>
              <button type="button" class="copy-mini-btn" data-snippet="${encodeURIComponent(item.fix_snippet)}">Copy Fix</button>
            </div>
            <pre><code>${escapeHtml(item.fix_snippet)}</code></pre>
          </div>
        ` : ''}
      `;

      ledgerContainer.appendChild(card);
    });

    // Attach copy listeners
    ledgerContainer.querySelectorAll(".copy-mini-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const text = decodeURIComponent(btn.getAttribute("data-snippet"));
        navigator.clipboard.writeText(text).then(() => {
          const orig = btn.textContent;
          btn.textContent = "Copied!";
          setTimeout(() => { btn.textContent = orig; }, 1500);
        });
      });
    });
  }

  // Filter Pill clicks
  filterPills.forEach(pill => {
    pill.addEventListener("click", () => {
      filterPills.forEach(p => p.classList.remove("active"));
      pill.classList.add("active");
      currentActiveFilter = pill.getAttribute("data-filter");
      renderLedgerItems(currentLedgerData, currentActiveFilter);
    });
  });

  // Copy Badge Markdown
  copyBadgeBtn.addEventListener("click", () => {
    navigator.clipboard.writeText(badgeMarkdownCode.textContent).then(() => {
      copyBadgeBtn.textContent = "Copied!";
      setTimeout(() => { copyBadgeBtn.textContent = "Copy Markdown"; }, 1500);
    });
  });

  function escapeHtml(str) {
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
});
