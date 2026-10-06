// Generated from web/src/portfolio.ts by web/build.mjs -- edit the source, not this file.
"use strict";
(() => {
  const e = escapeHTML;
  const CELL = {
    never_scanned: { cls: "gap", label: "Tekshirilmagan", hint: "Bu bosqich hech qachon ishga tushirilmagan. Bu “toza” degani emas." },
    not_registered: { cls: "unset", label: "Bog‘lanmagan", hint: "Bu bosqichga nishon bog‘lanmagan." },
    completed: { cls: "done", label: "Tugagan", hint: "Tekshiruv to‘liq bajarildi." },
    partial: { cls: "part", label: "Qisman", hint: "Qamrov bo‘shlig‘i bor; hisobotni oching." },
    failed: { cls: "part", label: "Tugallanmagan", hint: "Tekshiruv tugamadi; natija yo‘qligi toza degani emas." },
    cancelled: { cls: "part", label: "Bekor qilingan", hint: "Tekshiruv bekor qilindi." },
    no_supported_packages: { cls: "gap", label: "Manifest yo‘q", hint: "Tekshiruv tugadi, lekin o‘qiladigan lock/manifest fayli topilmadi. Bu “zaiflik yo‘q” degani emas." }
  };
  const cell = (s) => {
    const meta = CELL[s.state] || { cls: "part", label: s.state || "—", hint: "" };
    const count = s.count === null || s.count === void 0 ? "" : `<strong>${e(s.count)}</strong> kuzatuv`;
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
    $("portfolio-result").innerHTML = rows.length ? `<div class="scanner-table"><table class="pf-table"><thead><tr><th>Loyiha</th>${data.stages.map((s) => `<th>${e(s.title)}</th>`).join("")}</tr></thead><tbody>${rows.map((p) => `<tr><th scope="row"><strong>${e(p.name)}</strong><small>${e(p.id)}</small>${p.owner ? `<small>${e(p.owner)}</small>` : ""}${p.bundled ? '<small class="pf-tag">bundled namuna</small>' : p.single_stage ? '<small class="pf-tag">Yakka nishon</small>' : p.derived ? '<small class="pf-tag">ID mosligidan avtomatik</small>' : ""}${p.gaps.length ? `<small class="gap-note">${e(p.gaps.length)} ta qatlam ochiq</small>` : ""}${(p.unknown_targets || []).length ? `<small class="unknown-note">Ro‘yxatda yo‘q nishon: ${e(p.unknown_targets.join(", "))}</small>` : ""}</th>${data.stages.map((s) => cell(p.stages[s.key])).join("")}</tr>`).join("")}</tbody></table></div><p class="muted">${e(data.note)}</p>` : "Hali guruhlangan loyiha yo‘q.";
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
  async function buildStagePicker() {
    try {
      const data = await api("/api/portfolio/targets");
      $("pf-stages").innerHTML = data.stages.map((s) => `<label>${e(s.title)}${s.multi ? " (bir nechtasini tanlash mumkin)" : ""}<select id="pf-stage-${e(s.key)}" ${s.multi ? 'multiple size="4"' : ""}>${s.multi ? "" : '<option value="">Bog‘lanmagan</option>'}${s.targets.map((t) => `<option value="${e(t)}">${e(t)}</option>`).join("")}</select></label>`).join("");
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
  $("pf-save").addEventListener("click", async () => {
    const status = $("pf-status");
    status.className = "rule-status";
    status.textContent = "Saqlanmoqda…";
    const stages = {};
    for (const s of stageList) {
      const el = $("pf-stage-" + s.key);
      if (!el) continue;
      const value = el.multiple ? [...el.selectedOptions].map((o) => o.value) : el.value;
      if (el.multiple ? value.length : value) stages[s.key] = value;
    }
    try {
      const r = await api("/api/portfolio/register", { id: $("pf-id").value.trim(), name: $("pf-name").value.trim(), owner: $("pf-owner").value.trim(), stages });
      status.className = "rule-status ok";
      status.textContent = `Saqlandi: ${r.name}`;
      await loadOverview();
      loadTrend();
    } catch (error) {
      status.className = "rule-status bad";
      status.textContent = messageOf(error);
    }
  });
  let built = false;
  document.addEventListener("view-shown", (event) => {
    if (event.detail !== "portfolio") return;
    const first = !built;
    built = true;
    loadOverview().then(loadTrend).then(() => {
      if (first) return buildStagePicker();
    }).catch(showError);
  });
})();
