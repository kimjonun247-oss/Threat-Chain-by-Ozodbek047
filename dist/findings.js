// Generated from web/src/findings.ts by web/build.mjs -- edit the source, not this file.
"use strict";
(() => {
  const e = escapeHTML;
  const KEYS = ["q", "stage", "project", "severity", "status", "state", "target"];
  const FACET_TITLES = { severity: "Og‘irlik", stage: "Skaner", project: "Loyiha", status: "Holat" };
  const STAGE_NAMES = STAGE_SHORT;
  const ROLE_BY_STAGE = {
    code: "Dasturchi",
    dependencies: "Dasturchi",
    repository: "DevOps",
    iac: "DevOps",
    images: "DevOps",
    web: "Tarmoq"
  };
  const ROLE_BY_CHAIN = {
    "SX-001": "Dasturchi + DevOps",
    "SX-002": "DevOps",
    "SX-003": "DevOps",
    "SX-004": "Dasturchi",
    "SX-005": "DevOps",
    "SX-006": "Dasturchi",
    "SX-007": "DevOps + Dasturchi"
  };
  const responsibleOf = (row) => row.stage === "chain" ? ROLE_BY_CHAIN[row.rule_id] || "Dasturchi + DevOps" : ROLE_BY_STAGE[row.stage] || "—";
  const STATUS_NAMES = TRIAGE_STATUS;
  const icon = (name) => `<svg class="ic"><use href="#${name}"/></svg>`;
  const state = { filters: {}, offset: 0, limit: 50, data: null, selected: /* @__PURE__ */ new Set() };
  const origin = /* @__PURE__ */ new Map();
  function pick(row) {
    if (!row) return;
    state.selected.add(row.fingerprint);
    origin.set(row.fingerprint, row.stage + "|" + row.report_id);
  }
  function unpick(fingerprint) {
    state.selected.delete(fingerprint);
    origin.delete(fingerprint);
  }
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
    LAST_ADDRESS.findings = "#/findings" + (query ? "?" + query : "");
    const csv = new URLSearchParams(params);
    csv.delete("offset");
    $("findings-csv").href = "/api/findings/export.csv" + (csv.toString() ? "?" + csv : "");
    history.replaceState(null, "", LAST_ADDRESS.findings);
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
        const label = key === "stage" ? STAGE_NAMES[value] || value : key === "status" ? STATUS_NAMES[value] || value : key === "severity" ? SEVERITY_LABEL[value] || value : value;
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
    const out = [`<span class="tag tag-role" title="Kim tuzatadi">${e(responsibleOf(row))}</span>`];
    if (row.known_exploited === true) out.push('<span class="tag tag-kev">CISA KEV</span>');
    if (row.overdue) out.push(`<span class="tag tag-overdue">SLA ${e(row.sla?.days_remaining)} kun</span>`);
    if (row.epss != null) out.push(`<span class="tag">EPSS ${(row.epss * 100).toFixed(1)}%</span>`);
    if (row.verified) out.push('<span class="tag tag-open">Dalil bilan</span>');
    if (row.duplicate_of) out.push('<span class="tag">Takroriy</span>');
    if (row.escalates) out.push('<span class="tag" title="Bu topilma zanjir xavfini oshiradi">Zanjirni kuchaytiradi</span>');
    if (row.report_state === "partial") out.push('<span class="tag tag-overdue">Qisman qamrov</span>');
    if (row.stale) out.push('<span class="tag tag-overdue" title="Qaror manbaning oldingi holatiga berilgan; qayta ko‘rib chiqing">Qarorni yangilang</span>');
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
        <td><span class="sev sev-${e(severity)}">${e(SEVERITY_LABEL[severity] || severity)}</span></td>
        <td><button class="cell-title" data-open="${e(row.fingerprint)}" data-project="${e(row.project || "")}">${e(row.title || row.rule_id)}</button>
            <span class="cell-sub">${e(row.rule_id)} · ${e(row.subject)}</span>
            <span class="cell-sub">${tags(row)}</span></td>
        <td>${e(STAGE_NAMES[row.stage] || row.stage)}<span class="cell-sub">${e(row.target)}</span></td>
        <td>${e((row.cwe_ids || []).join(", ") || "CWE yo‘q")}</td>
        <td>${e(STATUS_NAMES[row.status || "untriaged"])}<span class="cell-sub">${row.owner ? e(row.owner) : ""}</span></td>
        <td><span class="cell-sub">${row.first_seen ? e(time(row.first_seen)) : row.stage === "chain" ? "har tekshiruvda hisoblanadi" : "—"}</span></td>
      </tr>`;
    }).join("");
    return `<table class="findings-table"><thead><tr>
      <th><input type="checkbox" id="findings-all" aria-label="Sahifadagi hammasini tanlash"></th>
      <th>Og‘irlik</th><th>Topilma</th><th>Skaner / nishon</th><th>CWE</th><th>Holat</th><th>Birinchi ko‘rilgan</th>
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
    $("findings-table").querySelectorAll("[data-open]").forEach((button) => button.addEventListener("click", () => drawer(button.dataset.open ?? "", button.dataset.project ?? "")));
    $("findings-table").querySelectorAll("[data-select]").forEach((box) => box.addEventListener("change", () => {
      const fp = box.dataset.select ?? "";
      if (box.checked) pick(data.rows.find((r) => r.fingerprint === fp));
      else unpick(fp);
      box.closest("tr")?.classList.toggle("selected", box.checked);
      bulk();
    }));
    $("findings-all")?.addEventListener("change", (event) => {
      data.rows.forEach((row) => event.target.checked ? pick(row) : unpick(row.fingerprint));
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
  function fixOf(finding) {
    if (!finding) return "";
    const what = finding.detail || finding.summary || finding.message || finding.description || "";
    const fix = finding.remediation || finding.recommendation || finding.resolution || (finding.fixed_versions?.length ? "Tuzatilgan versiyaga yangilang: " + finding.fixed_versions.join(", ") : "") || (finding.fixed_version ? "Tuzatilgan versiyaga yangilang: " + finding.fixed_version : "");
    if (!what && !fix) return "";
    return `${what ? `<h3>Bu nima?</h3><p>${e(what)}</p>` : ""}${fix ? `<h3>Qanday tuzatiladi</h3><p class="remediation">${e(fix)}</p>` : ""}`;
  }
  function evidence(finding) {
    if (!finding) return '<p class="cell-sub">Asl yozuv topilmadi (hisobot o‘chirilgan bo‘lishi mumkin).</p>';
    const skip = /* @__PURE__ */ new Set(["triage", "owasp_top10_2025", "cwe_ids", "verification_note"]);
    const NAMES = {
      tool: "Vosita",
      rule_id: "Qoida",
      path: "Fayl",
      line: "Qator",
      path_class: "Fayl turi",
      message: "Skaner xabari",
      severity: "Skaner bahosi",
      state: "Dalil holati",
      title: "Sarlavha",
      service_id: "Xizmat",
      level: "Skaner darajasi",
      fingerprint: "Identifikator",
      verified: "Dalil bilan tasdiqlangan",
      advisory_id: "Zaiflik",
      priority: "Ustuvorlik",
      remediation: "Tavsiya",
      detail: "Tafsilot",
      secret_value: "Sir qiymati",
      evidence: "Dalil tafsiloti",
      runtime_verified: "Ish vaqtida tasdiqlangan",
      rule_meta: "Qoida ma’lumoti",
      package: "Paket"
    };
    const VALUES = {
      unverified_static: "Statik — tasdiqlanmagan",
      prod: "Ishchi kod",
      test: "Test kodi",
      hidden: "Yashirilgan",
      true: "Ha",
      false: "Yo‘q"
    };
    const rows = Object.entries(finding).filter(([key, value]) => !skip.has(key) && value !== null && value !== "" && !(Array.isArray(value) && !value.length) && typeof value !== "object").map(([key, value]) => `<tr><td>${e(NAMES[key] || key)}</td><td>${e(VALUES[String(value)] || value)}</td></tr>`).join("");
    const nested = Object.entries(finding).filter(([key, value]) => !skip.has(key) && value && typeof value === "object").map(([key, value]) => `<h3>${e(NAMES[key] || key)}</h3><pre>${e(JSON.stringify(value, null, 1))}</pre>`).join("");
    return `<details class="raw-evidence"><summary>Skanerning asl yozuvi (texnik)</summary><table class="kv"><tbody>${rows}</tbody></table>${nested}</details>`;
  }
  async function drawer(fingerprint, project = "") {
    if ($("drawer").hidden) drawerReturn = document.activeElement;
    $("drawer").hidden = false;
    $("drawer").focus();
    $("drawer-body").innerHTML = "<p>Yuklanmoqda…</p>";
    try {
      const detail = await api("/api/findings/" + encodeURIComponent(fingerprint) + (project ? "?project=" + encodeURIComponent(project) : ""));
      const row = detail.row;
      $("drawer-title").textContent = row.title || row.rule_id;
      const sla = row.sla ? `${row.sla.days} kunlik muddat · ${row.sla.overdue ? "muddati o‘tgan" : row.sla.days_remaining + " kun qoldi"}` : "Muddat berilmagan (og‘irlik baholanmagan yoki topilma yopilgan)";
      $("drawer-body").innerHTML = `
        ${fixOf(detail.finding)}
        <p><span class="sev sev-${e(row.severity_scale || "UNRATED")}">${e(SEVERITY_LABEL[row.severity_scale || "UNRATED"])}</span> ${tags(row)}</p>
        <table class="kv"><tbody>
          <tr><td>Skaner</td><td>${e(STAGE_NAMES[row.stage] || row.stage)} · ${e(row.tool || "—")}</td></tr>
          <tr><td>Nishon</td><td>${e(row.target)}</td></tr>
          <tr><td>Loyiha</td><td>${e(row.project || "—")}</td></tr>
          <tr><td>Joy</td><td>${e(row.subject || "—")}</td></tr>
          <tr><td>CWE</td><td>${e((row.cwe_ids || []).join(", ") || "—")}</td></tr>
          <tr><td>SLA</td><td>${e(sla)}</td></tr>
          <tr><td>Birinchi / oxirgi ko‘rilgan</td><td>${row.first_seen ? e(time(row.first_seen)) : "—"} / ${row.last_seen ? e(time(row.last_seen)) : "—"}</td></tr>
          <tr><td>Hisobot</td><td>${e(row.report_id)} · ${e(RUN_STATE[row.report_state] || row.report_state)}</td></tr>
          <tr><td>Identifikator</td><td class="hash">${e(row.fingerprint)}</td></tr>
        </tbody></table>
        ${detail.snippet ? `<h3>Kod — aynan shu yerda</h3><pre class="snippet">${detail.snippet.map((l) => `<span class="snippet-line ${l.hit ? "snippet-hit" : ""}"><span class="snippet-n">${e(l.n)}</span><span class="snippet-code">${e(l.text) || " "}</span></span>`).join("")}</pre>` : detail.snippet_state === "secret" ? '<p class="cell-sub">Kod satri ataylab ko‘rsatilmaydi: bu qatorda sir qiymat bor va u himoyalanadi.</p>' : detail.snippet_state === "unavailable" ? '<p class="cell-sub">Kod satri ko‘rsatilmadi: manba papka o‘zgargan yoki o‘qib bo‘lmadi.</p>' : ""}
        ${detail.related.length ? `<h3>Bog‘liq topilmalar</h3>${detail.related.map((r) => `<p><button class="cell-title" data-open="${e(r.fingerprint)}" data-project="${e(r.project || row.project || "")}">${e(r.rule_id)} — ${e(r.title)}</button><span class="cell-sub">${r.escalates === row.fingerprint ? "Bu topilmani kuchaytiradi" : r.duplicate_of === row.fingerprint ? "Shu topilmaning takrori" : row.duplicate_of === r.fingerprint ? "Asl topilma (bu uning takrori)" : "Bog‘liq"}</span></p>`).join("")}` : ""}
        <h3>Qaror</h3>
        <form id="drawer-triage">
          <label>Holat<select name="status" required><option value="" ${row.status ? "" : "selected"} disabled>— tanlang —</option>${Object.entries(STATUS_NAMES).filter(([v]) => v !== "untriaged").map(([value, label]) => `<option value="${value}" ${row.status === value ? "selected" : ""}>${e(label)}</option>`).join("")}</select></label>
          <label>Mas’ul<input name="owner" maxlength="120" value="${e(row.owner || "")}" required></label>
          <label>Asos<textarea name="note" maxlength="1000" required>${e(detail.events.length ? detail.events[detail.events.length - 1].note : "")}</textarea></label>
          <div class="modal-actions"><button class="primary" data-submit>Qarorni saqlash</button></div>
          <p class="modal-feedback"></p>
        </form>
        ${detail.events.length ? `<h3>Qaror tarixi</h3>${detail.events.slice().reverse().map((ev) => `<p><strong>${e(STATUS_NAMES[ev.status] || ev.status)}</strong> · ${e(ev.owner)} · ${e(time(ev.updated_at))}<span class="cell-sub">${e(ev.note)}</span></p>`).join("")}` : ""}
        <h3>Asl dalil</h3>${evidence(detail.finding)}`;
      $("drawer-body").querySelectorAll("[data-open]").forEach((b) => b.addEventListener("click", () => drawer(b.dataset.open ?? "", b.dataset.project ?? "")));
      $("drawer-body").querySelector("#drawer-triage").addEventListener("submit", async (event) => {
        event.preventDefault();
        const form = formData(event.target);
        const line = event.target.querySelector(".modal-feedback");
        try {
          await api("/api/triage", {
            stage: row.stage,
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
  let drawerReturn = null;
  $("drawer-close").addEventListener("click", () => {
    $("drawer").hidden = true;
    if (drawerReturn && document.contains(drawerReturn)) drawerReturn.focus();
  });
  async function bulkDecide(status) {
    const chosen = [...state.selected];
    const byReport = {};
    chosen.forEach((fp) => {
      const key = origin.get(fp);
      if (key) (byReport[key] = byReport[key] || []).push(fp);
    });
    window.openModal("Ommaviy qaror", `
      <form id="bulk-decision">
        <p><strong>${e(chosen.length)} ta topilma</strong> uchun holat: <strong>${e(STATUS_NAMES[status] || status)}</strong></p>
        <label>Mas’ul<input name="owner" required maxlength="120" placeholder="Jamoa yoki mas’ul"></label>
        <label>Qaror asosi<textarea name="note" required maxlength="1000" rows="3" placeholder="Nega bu qaror qabul qilindi"></textarea></label>
        <div class="modal-actions"><button type="button" class="secondary" data-close>Bekor qilish</button><button class="primary" data-submit>Qarorni saqlash</button></div>
        <p class="modal-feedback"></p>
      </form>`, (box) => {
      box.querySelector("[data-close]").addEventListener("click", () => window.closeModal());
      box.querySelector("#bulk-decision").addEventListener("submit", async (event) => {
        event.preventDefault();
        const form = formData(event.target);
        const button = box.querySelector("[data-submit]");
        const line = box.querySelector(".modal-feedback");
        button.disabled = true;
        try {
          for (const [key, fingerprints] of Object.entries(byReport)) {
            const [stage, reportId] = key.split("|");
            await api("/api/triage/bulk", {
              stage,
              report_id: reportId,
              fingerprints,
              status,
              owner: form.get("owner").trim(),
              note: form.get("note").trim()
            });
          }
          state.selected.clear();
          origin.clear();
          window.closeModal();
          await load();
        } catch (error) {
          line.textContent = messageOf(error);
          line.className = "modal-feedback bad";
        } finally {
          button.disabled = false;
        }
      });
    });
  }
  $("findings-bulk").querySelectorAll("[data-bulk]").forEach((button) => button.addEventListener("click", () => bulkDecide(button.dataset.bulk ?? "")));
  $("findings-clear-selection").addEventListener("click", () => {
    state.selected.clear();
    origin.clear();
    paint();
  });
  $("findings-refresh").addEventListener("click", (event) => {
    const btn = event.currentTarget;
    btn.classList.add("spinning");
    btn.disabled = true;
    Promise.resolve(load()).finally(() => {
      btn.classList.remove("spinning");
      btn.disabled = false;
    });
  });
  $("findings-reset").addEventListener("click", () => {
    state.filters = {};
    state.offset = 0;
    $("global-search").value = "";
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
    if (location.hash.startsWith("#/findings")) readUrl();
    load();
  });
})();
