// Generated from web/src/findings.ts by web/build.mjs -- edit the source, not this file.
"use strict";
(() => {
  const e = escapeHTML;
  const KEYS = ["q", "stage", "project", "severity", "owasp", "status", "state", "target"];
  const FACET_TITLES = { severity: "Og‘irlik", stage: "Skaner", project: "Loyiha", owasp: "OWASP", status: "Holat" };
  const STAGE_NAMES = {
    code: "Kod",
    dependencies: "CVE",
    images: "Image",
    web: "Sayt",
    iac: "IaC",
    repository: "Repository",
    chain: "Zanjir"
  };
  const STATUS_NAMES = {
    untriaged: "Ko‘rilmagan",
    investigating: "Tekshirilmoqda",
    confirmed: "Tasdiqlangan",
    fix_planned: "Tuzatish rejalashtirilgan",
    false_positive: "Noto‘g‘ri signal",
    accepted_risk: "Xavf qabul qilingan",
    fixed: "Tuzatilgan"
  };
  const icon = (name) => `<svg class="ic"><use href="#${name}"/></svg>`;
  const state = { filters: {}, offset: 0, limit: 50, data: null, selected: /* @__PURE__ */ new Set() };
  function readUrl() {
    const params = new URLSearchParams(location.hash.replace(/^#\/?findings\??/, ""));
    state.filters = {};
    KEYS.forEach((key) => {
      const value = params.get(key);
      if (value) state.filters[key] = value;
    });
    state.offset = Number(params.get("offset") || 0) || 0;
  }
  function writeUrl() {
    const params = new URLSearchParams();
    KEYS.forEach((key) => {
      if (state.filters[key]) params.set(key, state.filters[key]);
    });
    if (state.offset) params.set("offset", String(state.offset));
    const query = params.toString();
    history.replaceState(null, "", "#/findings" + (query ? "?" + query : ""));
  }
  function toggle(key, value) {
    if (state.filters[key] === value) delete state.filters[key];
    else state.filters[key] = value;
    state.offset = 0;
    load();
  }
  function facets(data) {
    const blocks = Object.entries(FACET_TITLES).map(([key, title]) => {
      const counts = data.facets[key] || {};
      const chips = Object.entries(counts).slice(0, 8).map(([value, count]) => {
        const label = key === "stage" ? STAGE_NAMES[value] || value : key === "status" ? STATUS_NAMES[value] || value : key === "severity" && value === "UNRATED" ? "INFO" : value;
        return `<button class="chip" data-facet="${e(key)}" data-value="${e(value)}" aria-pressed="${state.filters[key] === value}">${e(label)}<small>${e(count)}</small></button>`;
      }).join("");
      return chips ? `<div class="facet-group"><b>${e(title)}</b>${chips}</div>` : "";
    }).join("");
    const quick = [
      ["open", "Ochiq"],
      ["overdue", "Muddati o‘tgan"],
      ["kev", "CISA KEV"],
      ["verified", "Tasdiqlangan dalil"],
      ["duplicate", "Takroriy"],
      ["closed", "Yopilgan"]
    ].map(([value, label]) => `<button class="chip" data-facet="state" data-value="${value}" aria-pressed="${state.filters.state === value}">${e(label)}</button>`).join("");
    return blocks + `<div class="facet-group"><b>Tez filtr</b>${quick}</div>`;
  }
  function coverage(data) {
    const unscanned = data.coverage.unscanned || [];
    const incomplete = data.coverage.incomplete || [];
    const truncated = data.coverage.truncated || [];
    if (!unscanned.length && !incomplete.length && !truncated.length) return "";
    const parts = [];
    if (unscanned.length) parts.push(`<strong>${unscanned.length} ta nishon tekshirilmagan</strong> — ${e(unscanned.map((c) => `${STAGE_NAMES[c.stage] || c.stage}/${c.target}`).join(", "))}`);
    if (incomplete.length) parts.push(`<strong>${incomplete.length} ta skan natija bermadi</strong> — ${e(incomplete.map((c) => `${STAGE_NAMES[c.stage] || c.stage}/${c.target}`).join(", "))}`);
    if (truncated.length) parts.push(`Qisqartirildi: ${e(truncated.map((t) => `${t.target} ${t.shown}/${t.total}`).join(", "))}`);
    return parts.map((p) => `<p>${p}</p>`).join("");
  }
  function tags(row) {
    const out = [];
    if (row.known_exploited === true) out.push('<span class="tag tag-kev">CISA KEV</span>');
    if (row.overdue) out.push(`<span class="tag tag-overdue">SLA ${e(row.sla?.days_remaining)} kun</span>`);
    if (row.epss != null) out.push(`<span class="tag">EPSS ${(row.epss * 100).toFixed(1)}%</span>`);
    if (row.verified) out.push('<span class="tag tag-open">Dalil bilan</span>');
    if (row.duplicate_of) out.push('<span class="tag">Takroriy</span>');
    if (row.escalates) out.push('<span class="tag">Kuchaytirilgan</span>');
    if (row.report_state === "partial") out.push('<span class="tag tag-overdue">Qisman qamrov</span>');
    if (row.stale) out.push('<span class="tag tag-overdue">Qaror eskirgan</span>');
    return out.join("");
  }
  function table(data) {
    if (!data.rows.length) {
      return `<p class="empty">${icon("i-search")} Bu filtrda topilma yo‘q — <strong>xavfsizlik xulosasi emas</strong>.</p>`;
    }
    const body = data.rows.map((row) => {
      const severity = row.severity_scale || "UNRATED";
      return `<tr data-fp="${e(row.fingerprint)}" class="${state.selected.has(row.fingerprint) ? "selected" : ""}">
        <td><input type="checkbox" data-select="${e(row.fingerprint)}" ${state.selected.has(row.fingerprint) ? "checked" : ""} aria-label="Tanlash"></td>
        <td><span class="sev sev-${e(severity)}">${e(severity === "UNRATED" ? "INFO" : severity)}</span></td>
        <td><button class="cell-title" data-open="${e(row.fingerprint)}">${e(row.title || row.rule_id)}</button>
            <span class="cell-sub">${e(row.rule_id)} · ${e(row.subject)}</span>
            <span class="cell-sub">${tags(row)}</span></td>
        <td>${e(STAGE_NAMES[row.stage] || row.stage)}<span class="cell-sub">${e(row.target)}</span></td>
        <td>${(row.owasp || []).map((o) => `<span class="tag">${e(o)}</span>`).join("") || '<span class="cell-sub">—</span>'}
            <span class="cell-sub">${e((row.cwe_ids || []).join(", ") || "CWE yo‘q")}</span></td>
        <td>${e(STATUS_NAMES[row.status || "untriaged"])}<span class="cell-sub">${row.owner ? e(row.owner) : ""}</span></td>
        <td><span class="cell-sub">${row.first_seen ? e(time(row.first_seen)) : "noma’lum"}</span></td>
      </tr>`;
    }).join("");
    return `<table class="findings-table"><thead><tr>
      <th><input type="checkbox" id="findings-all" aria-label="Sahifadagi hammasini tanlash"></th>
      <th>Og‘irlik</th><th>Topilma</th><th>Skaner / nishon</th><th>OWASP / CWE</th><th>Holat</th><th>Birinchi ko‘rilgan</th>
    </tr></thead><tbody>${body}</tbody></table>`;
  }
  function paint() {
    const data = state.data;
    $("findings-coverage").innerHTML = coverage(data);
    $("findings-facets").innerHTML = facets(data);
    $("findings-table").innerHTML = table(data);
    const from = data.total ? data.offset + 1 : 0;
    $("findings-page").textContent = `${from}–${Math.min(data.offset + data.limit, data.total)} / ${data.total} ta topilma`;
    $("findings-prev").disabled = data.offset === 0;
    $("findings-next").disabled = data.offset + data.limit >= data.total;
    const count = $("nav-findings-count");
    if (count) {
      count.textContent = String(data.total);
      count.hidden = false;
    }
    $("findings-facets").querySelectorAll("[data-facet]").forEach((chip) => chip.addEventListener("click", () => toggle(chip.dataset.facet ?? "", chip.dataset.value ?? "")));
    $("findings-table").querySelectorAll("[data-open]").forEach((button) => button.addEventListener("click", () => drawer(button.dataset.open ?? "")));
    $("findings-table").querySelectorAll("[data-select]").forEach((box) => box.addEventListener("change", () => {
      if (box.checked) state.selected.add(box.dataset.select ?? "");
      else state.selected.delete(box.dataset.select ?? "");
      box.closest("tr")?.classList.toggle("selected", box.checked);
      bulk();
    }));
    $("findings-all")?.addEventListener("change", (event) => {
      data.rows.forEach((row) => event.target.checked ? state.selected.add(row.fingerprint) : state.selected.delete(row.fingerprint));
      paint();
    });
    bulk();
  }
  function bulk() {
    $("findings-bulk").hidden = state.selected.size === 0;
    $("findings-selected").textContent = `${state.selected.size} ta tanlandi`;
  }
  async function load() {
    writeUrl();
    $("findings-table").innerHTML = '<p class="empty">Yuklanmoqda…</p>';
    const params = new URLSearchParams(state.filters);
    params.set("offset", String(state.offset));
    params.set("limit", String(state.limit));
    try {
      state.data = await api("/api/findings?" + params.toString());
      paint();
    } catch (error) {
      showError(error);
    }
  }
  function evidence(finding) {
    if (!finding) return '<p class="cell-sub">Asl yozuv topilmadi (hisobot o‘chirilgan bo‘lishi mumkin).</p>';
    const skip = /* @__PURE__ */ new Set(["triage", "owasp_top10_2025", "cwe_ids", "verification_note"]);
    const rows = Object.entries(finding).filter(([key, value]) => !skip.has(key) && value !== null && value !== "" && !(Array.isArray(value) && !value.length) && typeof value !== "object").map(([key, value]) => `<tr><td>${e(key)}</td><td>${e(value)}</td></tr>`).join("");
    const nested = Object.entries(finding).filter(([key, value]) => !skip.has(key) && value && typeof value === "object").map(([key, value]) => `<h3>${e(key)}</h3><pre>${e(JSON.stringify(value, null, 1))}</pre>`).join("");
    return `<table class="kv"><tbody>${rows}</tbody></table>${nested}`;
  }
  async function drawer(fingerprint) {
    $("drawer").hidden = false;
    $("drawer-body").innerHTML = "<p>Yuklanmoqda…</p>";
    try {
      const detail = await api("/api/findings/" + encodeURIComponent(fingerprint));
      const row = detail.row;
      $("drawer-title").textContent = row.title || row.rule_id;
      const sla = row.sla ? `${row.sla.days} kunlik muddat · ${row.sla.overdue ? "muddati o‘tgan" : row.sla.days_remaining + " kun qoldi"}` : "Muddat berilmagan (og‘irlik baholanmagan yoki topilma yopilgan)";
      $("drawer-body").innerHTML = `
        <p><span class="sev sev-${e(row.severity_scale || "UNRATED")}">${e(row.severity_scale || "INFO")}</span> ${tags(row)}</p>
        <table class="kv"><tbody>
          <tr><td>Skaner</td><td>${e(STAGE_NAMES[row.stage] || row.stage)} · ${e(row.tool || "—")}</td></tr>
          <tr><td>Nishon</td><td>${e(row.target)}</td></tr>
          <tr><td>Loyiha</td><td>${e(row.project || "—")}</td></tr>
          <tr><td>Joy</td><td>${e(row.subject || "—")}</td></tr>
          <tr><td>CWE / OWASP</td><td>${e((row.cwe_ids || []).join(", ") || "—")} ${(row.owasp || []).map((o) => `<span class="tag">${e(o)}</span>`).join("")}</td></tr>
          <tr><td>SLA</td><td>${e(sla)}</td></tr>
          <tr><td>Birinchi / oxirgi ko‘rilgan</td><td>${row.first_seen ? e(time(row.first_seen)) : "—"} / ${row.last_seen ? e(time(row.last_seen)) : "—"}</td></tr>
          <tr><td>Hisobot</td><td>${e(row.report_id)} · ${e(row.report_state)}</td></tr>
          <tr><td>Identifikator</td><td class="hash">${e(row.fingerprint)}</td></tr>
        </tbody></table>
        ${detail.related.length ? `<h3>Bog‘liq topilmalar</h3>${detail.related.map((r) => `<p><button class="cell-title" data-open="${e(r.fingerprint)}">${e(r.rule_id)} — ${e(r.title)}</button><span class="cell-sub">${r.escalates === row.fingerprint ? "Bu topilmani kuchaytiradi" : r.duplicate_of === row.fingerprint ? "Shu topilmaning takrori" : "Bog‘liq"}</span></p>`).join("")}` : ""}
        <h3>Qaror</h3>
        <form id="drawer-triage">
          <label>Holat<select name="status">${Object.entries(STATUS_NAMES).filter(([v]) => v !== "untriaged").map(([value, label]) => `<option value="${value}" ${row.status === value ? "selected" : ""}>${e(label)}</option>`).join("")}</select></label>
          <label>Mas’ul<input name="owner" maxlength="120" value="${e(row.owner || "")}" required></label>
          <label>Asos<textarea name="note" maxlength="1000" required>${e(detail.events.length ? detail.events[detail.events.length - 1].note : "")}</textarea></label>
          <div class="modal-actions"><button class="primary" data-submit>Qarorni saqlash</button></div>
          <p class="modal-feedback"></p>
        </form>
        ${detail.events.length ? `<h3>Qaror tarixi</h3>${detail.events.slice().reverse().map((ev) => `<p><strong>${e(STATUS_NAMES[ev.status] || ev.status)}</strong> · ${e(ev.owner)} · ${e(time(ev.updated_at))}<span class="cell-sub">${e(ev.note)}</span></p>`).join("")}` : ""}
        <h3>Asl dalil</h3>${evidence(detail.finding)}`;
      $("drawer-body").querySelectorAll("[data-open]").forEach((b) => b.addEventListener("click", () => drawer(b.dataset.open ?? "")));
      $("drawer-body").querySelector("#drawer-triage").addEventListener("submit", async (event) => {
        event.preventDefault();
        const form = formData(event.target);
        const line = event.target.querySelector(".modal-feedback");
        try {
          await api("/api/triage", {
            stage: row.stage === "chain" ? "repository" : row.stage,
            report_id: row.report_id,
            fingerprint: row.fingerprint,
            status: form.get("status"),
            owner: form.get("owner").trim(),
            note: form.get("note").trim()
          });
          line.textContent = "Saqlandi.";
          line.className = "modal-feedback ok";
          await load();
        } catch (error) {
          line.textContent = messageOf(error);
          line.className = "modal-feedback bad";
        }
      });
    } catch (error) {
      $("drawer-body").innerHTML = `<p class="error">${e(messageOf(error))}</p>`;
    }
  }
  $("drawer-close").addEventListener("click", () => {
    $("drawer").hidden = true;
  });
  async function bulkDecide(status) {
    const chosen = [...state.selected];
    const byReport = {};
    chosen.forEach((fp) => {
      const row = state.data.rows.find((r) => r.fingerprint === fp);
      if (!row) return;
      const key = (row.stage === "chain" ? "repository" : row.stage) + "|" + row.report_id;
      (byReport[key] = byReport[key] || []).push(fp);
    });
    const owner = prompt("Qaror uchun mas’ul:");
    if (!owner) return;
    const note = prompt("Qaror asosi:");
    if (!note) return;
    try {
      for (const [key, fingerprints] of Object.entries(byReport)) {
        const [stage, reportId] = key.split("|");
        await api("/api/triage/bulk", { stage, report_id: reportId, fingerprints, status, owner, note });
      }
      state.selected.clear();
      await load();
    } catch (error) {
      showError(error);
    }
  }
  $("findings-bulk").querySelectorAll("[data-bulk]").forEach((button) => button.addEventListener("click", () => bulkDecide(button.dataset.bulk ?? "")));
  $("findings-clear-selection").addEventListener("click", () => {
    state.selected.clear();
    paint();
  });
  $("findings-refresh").addEventListener("click", load);
  $("findings-reset").addEventListener("click", () => {
    state.filters = {};
    state.offset = 0;
    load();
  });
  $("findings-prev").addEventListener("click", () => {
    state.offset = Math.max(0, state.offset - state.limit);
    load();
  });
  $("findings-next").addEventListener("click", () => {
    state.offset += state.limit;
    load();
  });
  document.addEventListener("search-requested", (event) => {
    state.filters.q = event.detail;
    state.offset = 0;
    if (!$("findings-view").hidden) load();
  });
  document.addEventListener("view-shown", (event) => {
    if (event.detail !== "findings") return;
    if (!state.data) readUrl();
    load();
  });
})();
