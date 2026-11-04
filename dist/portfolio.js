// Generated from web/src/portfolio.ts by web/build.mjs -- edit the source, not this file.
"use strict";
(() => {
  const e = escapeHTML;
  const CELL = {
    never_scanned: { cls: "gap", label: "Tekshirilmagan", hint: "Bu bosqich hech qachon ishga tushirilmagan. Bu “toza” degani emas." },
    not_registered: { cls: "unset", label: RUN_STATE.not_registered, hint: "Bu qatlamga nishon ulanmagan." },
    completed: { cls: "done", label: RUN_STATE.completed, hint: "Tekshiruv to‘liq bajarildi." },
    partial: { cls: "part", label: "Qisman", hint: "Qamrov bo‘shlig‘i bor; hisobotni oching." },
    failed: { cls: "part", label: RUN_STATE.failed, hint: "Tekshiruv tugamadi; natija yo‘qligi toza degani emas." },
    cancelled: { cls: "part", label: RUN_STATE.cancelled, hint: "Tekshiruv bekor qilindi." },
    no_supported_packages: { cls: "gap", label: "Paket fayli yo‘q", hint: "Tekshiruv tugadi, lekin o‘qiladigan lock/manifest fayli topilmadi. Bu “zaiflik yo‘q” degani emas." }
  };
  const cell = (s) => {
    const meta = CELL[s.state] || { cls: "part", label: s.state || "—", hint: "" };
    const count = s.count === null || s.count === void 0 ? "" : `<strong>${e(s.count)}</strong> topilma`;
    const many = s.targets.length > 1 ? `<small>${e(s.scanned_targets)}/${e(s.targets.length)} nishon natija berdi</small>` : "";
    const missed = (s.unscanned_targets || []).length ? `<small class="gap-note">Tekshirilmagan: ${e(s.unscanned_targets.join(", "))}</small>` : "";
    const broken = (s.incomplete_targets || []).length ? `<small class="gap-note">Tugamagan: ${e(s.incomplete_targets.join(", "))}</small>` : "";
    const when = s.last_scan ? `<small>${e(time(s.last_scan))}</small>` : "";
    return `<td class="pf-cell ${meta.cls}" title="${e(meta.hint)}"><span class="pf-state">${e(meta.label)}</span>${count ? `<span>${count}</span>` : ""}${many}${when}${broken}${missed}</td>`;
  };
  let stageList = [];
  async function loadOverview() {
    const data = await api("/api/portfolio");
    stageList = data.stages;
    const rows = data.projects;
    $("portfolio-result").className = rows.length ? "" : "empty";
    $("portfolio-result").innerHTML = rows.length ? `<div class="scanner-table"><table class="pf-table"><thead><tr><th>Loyiha</th>${data.stages.map((s) => `<th>${e(s.title)}</th>`).join("")}</tr></thead><tbody>${rows.map((p) => `<tr><th scope="row"><strong>${e(p.name)}</strong><small>${e(p.id)}</small>${p.owner ? `<small>${e(p.owner)}</small>` : ""}${p.bundled ? '<small class="pf-tag">tayyor namuna</small>' : p.single_stage ? '<small class="pf-tag">Bitta nishonli loyiha</small>' : p.derived ? '<small class="pf-tag" title="Nishonlar bir xil ID orqali bitta loyihaga guruhlandi">Avtomatik guruhlangan</small>' : ""}${p.gaps.length ? `<small class="gap-note">${e(p.gaps.length)} ta qatlam tekshirilmagan</small>` : ""}${(p.unknown_targets || []).length ? `<small class="unknown-note">Ro‘yxatda yo‘q nishon: ${e(p.unknown_targets.join(", "))}</small>` : ""}</th>${data.stages.map((s) => cell(p.stages[s.key])).join("")}</tr>`).join("")}</tbody></table></div><p class="muted">${e(data.note)}</p>` : "Hali guruhlangan loyiha yo‘q.";
    const project = $("trend-project");
    const keep = project.value;
    project.innerHTML = rows.map((p) => `<option value="${e(p.id)}">${e(p.name)}</option>`).join("");
    if (rows.some((p) => p.id === keep)) project.value = keep;
    syncStages(rows);
  }
  function syncStages(rows) {
    const project = rows.find((p) => p.id === $("trend-project").value);
    const usable = project ? stageList.filter((s) => (project.stages[s.key].targets || []).length) : [];
    const keep = $("trend-stage").value;
    $("trend-stage").innerHTML = usable.map((s) => `<option value="${e(s.key)}">${e(s.title)}</option>`).join("") || '<option value="">Bog‘langan bosqich yo‘q</option>';
    if (usable.some((s) => s.key === keep)) $("trend-stage").value = keep;
  }
  async function loadTrend() {
    const project = $("trend-project").value, stage = $("trend-stage").value;
    if (!project || !stage) {
      $("trend-result").className = "empty";
      $("trend-result").textContent = "Loyiha va bosqichni tanlang.";
      return;
    }
    try {
      const t = await api(`/api/portfolio/trend?project=${encodeURIComponent(project)}&stage=${encodeURIComponent(stage)}`);
      const counts = t.points.map((p) => p.count).filter((c) => typeof c === "number");
      const top = Math.max(1, ...counts);
      $("trend-result").className = "";
      $("trend-result").innerHTML = t.points.length ? `<p class="muted">${e(t.title)} · ${e(t.targets.join(", "))}</p><div class="trend-rows">${t.points.map((p) => {
        const c = typeof p.count === "number" ? p.count : null;
        const meta = CELL[p.state] || { cls: "part", label: p.state };
        const w = c === null ? 0 : Math.round(c / top * 20) * 5;
        return `<div class="trend-row"><span class="trend-when">${e(time(p.created_at))}</span><span class="trend-bar"><i class="${meta.cls} w${w}"></i></span><span class="trend-count">${c === null ? "—" : e(c)}</span><span class="badge ${meta.cls === "done" ? "green" : meta.cls === "part" ? "amber" : "neutral"}">${e(meta.label)}</span></div>`;
      }).join("")}</div><p class="baseline-note">${e(t.note)}</p>` : "Bu bosqich uchun hali hisobot yo‘q.";
    } catch (error) {
      showError(error);
    }
  }
  $("portfolio-refresh").addEventListener("click", (event) => {
    const btn = event.currentTarget;
    btn.classList.add("spinning");
    btn.disabled = true;
    loadOverview().then(loadTrend).catch(showError).finally(() => {
      btn.classList.remove("spinning");
      btn.disabled = false;
    });
  });
  $("trend-project").addEventListener("change", async () => {
    await loadOverview();
    loadTrend();
  });
  $("trend-stage").addEventListener("change", loadTrend);
  document.addEventListener("view-shown", (event) => {
    if (event.detail !== "portfolio") return;
    loadOverview().then(loadTrend).catch(showError);
  });
  onRegistryChange(async () => {
    if (!$("portfolio-view").hidden) {
      await loadOverview();
      loadTrend();
    }
  });
})();
