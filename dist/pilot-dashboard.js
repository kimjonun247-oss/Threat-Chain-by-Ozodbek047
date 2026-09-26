// Generated from web/src/pilot-dashboard.ts by web/build.mjs -- edit the source, not this file.
"use strict";
(() => {
  const e = escapeHTML;
  const labels = { external_or_interrupted: "Boshqa jarayon yoki uzilgan skan", completed: "Tugagan", partial: "Qisman qamrov", failed: "Tugallanmagan", cancelled: "Bekor qilingan", running: "Tekshirilmoqda", queued: "Navbatda" };
  const owaspBadges = (tags) => (tags || []).map((o) => `<span class="badge neutral" title="${e(o.name)}">${e(o.code)}</span>`).join(" ");
  let job = null, report = null, page = 0, filter = "", severity = "all";
  function findings() {
    const rows = (report.findings || []).filter((f) => (severity === "all" || f.severity === severity) && JSON.stringify([f.package, f.version, f.advisory_id, f.title]).toLowerCase().includes(filter));
    page = Math.min(page, Math.max(0, Math.ceil(rows.length / 25) - 1));
    $("image-findings").innerHTML = rows.slice(page * 25, page * 25 + 25).map((f) => `<details class="repo-finding"><summary><span class="badge ${f.severity === "CRITICAL" ? "red" : f.severity === "HIGH" ? "amber" : "neutral"}">${e(f.severity)}</span><strong>${e(f.package)} <small>${e(f.version)}</small></strong><span>${e(f.advisory_id)}</span></summary><div class="finding-body"><p>${e(f.title)}</p><p>${e((f.cwe_ids || []).join(", ") || "CWE aniqlanmagan")} ${owaspBadges(f.owasp_top10_2025)} <span class="badge amber">Qo‘lda tekshirish kerak</span></p><p>Manba: ${e(f.source)} · ${e(f.type)}</p><p>CISA KEV: <strong>${f.known_exploited === true ? "Ha · " + e(f.kev_added_on || "") : f.known_exploited === false ? "Yo‘q" : "Tekshirilmagan"}</strong>${f.epss ? ` · EPSS ${(f.epss.epss * 100).toFixed(1)}% (persentil ${e(f.epss.percentile)})` : ""}</p><p>Tuzatilgan versiya: <strong>${e(f.fixed_version || "Manbada ko‘rsatilmagan")}</strong></p><p>Ta’sir shartlari, platforma va ishlatilayotgan funksiyani tekshiring. Yangi image yig‘ib, funksional sinov va qayta skan bajaring.</p></div></details>`).join("") || '<p class="empty">Tanlangan filtrda moslik yo‘q. Skan holati va qamrovni tekshiring.</p>';
    $("image-page").textContent = `${rows.length} ta moslik · ${page + 1}/${Math.max(1, Math.ceil(rows.length / 25))} sahifa`;
    $("image-prev").disabled = page === 0;
    $("image-next").disabled = (page + 1) * 25 >= rows.length;
  }
  function render(row) {
    syncTarget("image-target", row.target);
    report = row;
    $("image-result").className = "";
    $("image-result").innerHTML = `<div class="scanner-summary"><strong>${e(labels[row.state] || row.state)}</strong><span>${e(time(row.created_at))}</span><a href="/api/images/reports/${encodeURIComponent(row.id)}/download">JSON hisobot ↓</a>${row.packages ? `<a href="/api/images/reports/${encodeURIComponent(row.id)}/sbom">SBOM (CycloneDX) ↓</a>` : ""}</div>${row.packages ? "" : '<p class="muted gap-note">SBOM yo‘q: bu hisobot paket ro‘yxati saqlanishidan oldin olingan. Olish uchun image’ni qayta skanerlang.</p>'}<p class="hash">${e(row.reference)}</p>${row.os?.EOSL ? `<p class="unknown-note">Diqqat: ${e(row.os.Family || "")} ${e(row.os.Name || "")} qo‘llab-quvvatlash muddati tugagan (EOL). Bunday OS uchun yangi zaifliklar bazaga kiritilmaydi va tuzatish chiqmaydi — kam topilma "xavfsiz" degani emas. Asos image’ni qo‘llab-quvvatlanadigan versiyaga yangilang.</p>` : ""}<div class="scanner-cards"><article class="scanner-card"><h3>Paket–zaiflik mosliklari</h3><strong>${e(row.count)}</strong></article><article class="scanner-card"><h3>Kritik / yuqori</h3><strong>${e(row.severity_counts?.CRITICAL || 0)} / ${e(row.severity_counts?.HIGH || 0)}</strong></article><article class="scanner-card"><h3>Trivy</h3><strong>${e(row.tool?.version || "—")}</strong></article><article class="scanner-card"><h3>Tasdiqlash</h3><strong>${row.verification_summary ? e(row.verification_summary.confirmed_by_evidence) + " / " + e(row.verification_summary.total) : e(row.count) + " ta (eski format)"}</strong><p>${row.verification_summary ? "Image ishga tushirilmagan; barchasi qo‘lda tekshiriladi" : "Bu hisobot CWE/OWASP teglaridan oldin olingan. To‘liq tasniflash uchun qayta tekshiring."}</p></article></div><p id="image-baseline" class="muted"></p><details class="pilot-help"><summary>Qamrov va baza yangiligi</summary><p>Baza yangilangan: ${e(row.database?.UpdatedAt ? time(row.database.UpdatedAt) : "Ma’lumot yo‘q")}</p><p>OS: ${e(row.os?.Family || "Noma’lum")} ${e(row.os?.Name || "")} ${row.os?.EOSL ? "· Qo‘llab-quvvatlash muddati tugagan" : ""}</p>${(row.coverage || []).map((s) => `<p>${e(s.Type)} · ${e(s.Class)} · ${e(s.packages)} paket</p>`).join("")}<p class="hash">Image ID: ${e(row.image_id || "—")}</p></details><div class="dep-filters"><label>Qidirish<input id="image-search" type="search" value="${e(filter)}" placeholder="Paket yoki CVE"></label><label>Og‘irlik<select id="image-severity">${["all", "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].map((s) => `<option value="${s}" ${severity === s ? "selected" : ""}>${s === "all" ? "Barchasi" : s}</option>`).join("")}</select></label></div><div id="image-findings"></div><div class="scanner-summary"><button id="image-prev" class="secondary">← Oldingi</button><span id="image-page"></span><button id="image-next" class="secondary">Keyingi →</button></div>`;
    if (!["queued", "running"].includes(row.state)) {
      fillBaseline("images", row.id, "image-baseline");
      showFixPlan(row.fix_plan, "image-baseline");
    }
    $("image-search").addEventListener("input", (ev) => {
      filter = ev.target.value.toLowerCase();
      page = 0;
      findings();
    });
    $("image-severity").addEventListener("change", (ev) => {
      severity = ev.target.value;
      page = 0;
      findings();
    });
    $("image-prev").addEventListener("click", () => {
      page--;
      findings();
    });
    $("image-next").addEventListener("click", () => {
      page++;
      findings();
    });
    findings();
  }
  async function history() {
    const rows = await api("/api/images/reports");
    $("image-history").innerHTML = rows.map((r) => `<button class="secondary scanner-history" data-image-id="${e(r.id)}">${e(r.target)} · ${e(time(r.created_at))} · ${e(labels[r.state] || r.state)} · ${e(r.count)}</button>`).join("");
    $("image-history").querySelectorAll("[data-image-id]").forEach((b) => b.addEventListener("click", async () => {
      if (job) return;
      try {
        render(await api("/api/images/reports/" + b.dataset.imageId));
      } catch (error) {
        showError(error);
      }
    }));
    return rows;
  }
  async function follow(id) {
    job = id;
    $("image-scan").disabled = true;
    $("image-target").disabled = true;
    $("image-cancel").hidden = false;
    try {
      const row = await pollReport("/api/images/reports/" + id, (s) => {
        $("image-progress").textContent = s.progress || labels[s.state];
      });
      if (row.active_here === false) {
        row.state = "external_or_interrupted";
        row.progress = "Bu job boshqa terminalda yoki oldingi serverda boshlangan. O‘sha terminalni tekshiring; tugallanmagan natija.";
      }
      $("image-progress").textContent = row.progress || labels[row.state];
      render(row);
      await history();
    } finally {
      job = null;
      $("image-scan").disabled = false;
      $("image-target").disabled = false;
      $("image-cancel").hidden = true;
    }
  }
  $("image-scan").addEventListener("click", async () => {
    try {
      const row = await api("/api/images/scan", { target: $("image-target").value, online: true });
      await follow(row.id);
    } catch (error) {
      showError(error);
    }
  });
  $("image-cancel").addEventListener("click", async () => {
    try {
      await api("/api/images/cancel", { report_id: job });
    } catch (error) {
      showError(error);
    }
  });
  async function init() {
    try {
      const targets = await api("/api/images/targets");
      $("image-target").innerHTML = targets.map((t) => `<option value="${e(t.id)}" ${t.id === "pilot-crapi-web" ? "selected" : ""}>${e(t.name)}</option>`).join("");
      const rows = await history();
      if (rows.length) {
        if (["queued", "running"].includes(rows[0].state)) follow(rows[0].id).catch(showError);
        else render(await api("/api/images/reports/" + rows[0].id));
      }
    } catch (error) {
      showError(error);
    }
  }
  whenShown(["images"], init);
  view("readiness");
})();
