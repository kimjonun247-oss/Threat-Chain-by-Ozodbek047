// Generated from web/src/app.ts by web/build.mjs -- edit the source, not this file.
"use strict";
const $ = (id) => document.getElementById(id);
const state = { busy: false, repository: null, reviews: {}, projects: [], project: "crapi" };
const HTML_ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const formData = (form) => new FormData(form);
const messageOf = (error) => error instanceof Error ? error.message : String(error);
const escapeHTML = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
const time = (value) => new Date(value).toLocaleString("uz-UZ", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
const inflight = /* @__PURE__ */ new Map();
function api(path, body) {
  if (body !== void 0) return request(path, body);
  if (!inflight.has(path)) inflight.set(path, request(path).finally(() => inflight.delete(path)));
  return inflight.get(path);
}
function whenShown(names, start) {
  let started = false;
  const run = () => {
    if (!started) {
      started = true;
      start();
    }
  };
  document.addEventListener("view-shown", (event) => {
    if (names.includes(event.detail)) run();
  });
  if (names.some((name) => $(name + "-view") && !$(name + "-view").hidden)) run();
}
async function pollReport(url, onStatus) {
  let wait = 1e3;
  for (; ; ) {
    while (document.hidden) await new Promise((resolve) => document.addEventListener("visibilitychange", resolve, { once: true }));
    const status = await api(url + "?status=1");
    if (onStatus) onStatus(status);
    if (!["queued", "running"].includes(status.state) || status.active_here === false) return api(url);
    await new Promise((resolve) => setTimeout(resolve, wait));
    wait = Math.min(5e3, Math.round(wait * 1.5));
  }
}
async function request(path, body) {
  const response = await fetch(path, body === void 0 ? {} : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error("Server javobini o‘qib bo‘lmadi. Serverni tekshiring.");
  }
  if (response.status === 401 && data.login_required) {
    await login();
    return request(path, body);
  }
  if (!response.ok) throw new Error(data.error || "So‘rov bajarilmadi.");
  return data;
}
const ROLE_NAMES = { viewer: "kuzatuvchi", operator: "operator", admin: "admin" };
let loginPromise = null;
function login() {
  if (loginPromise) return loginPromise;
  loginPromise = new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.className = "login-overlay";
    overlay.innerHTML = `<form class="login-box" autocomplete="on">
      <h2>ThreatChain</h2><p class="muted">Davom etish uchun tizimga kiring.</p>
      <label>Foydalanuvchi<input name="username" autocomplete="username" required maxlength="40"></label>
      <label>Parol<input name="password" type="password" autocomplete="current-password" required maxlength="200"></label>
      <button class="primary">Kirish</button><p class="login-error" role="alert"></p></form>`;
    document.body.appendChild(overlay);
    const form = overlay.querySelector("form");
    form.elements.username.focus();
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: form.elements.username.value.trim(), password: form.elements.password.value })
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        form.querySelector(".login-error").textContent = data.error || "Kirib bo‘lmadi.";
        form.elements.password.value = "";
        return;
      }
      overlay.remove();
      loginPromise = null;
      showUser(data.user);
      resolve(data.user);
    });
  });
  return loginPromise;
}
function showUser(user) {
  const box = $("user-box");
  if (!box) return;
  box.hidden = !user;
  if (!user) return;
  box.querySelector(".user-name").textContent = `${user.name} · ${ROLE_NAMES[user.role] || user.role}`;
  document.body.dataset.role = user.role;
}
document.addEventListener("DOMContentLoaded", async () => {
  const logout = $("logout");
  if (logout) logout.addEventListener("click", async () => {
    await fetch("/api/auth/logout", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    location.reload();
  });
  try {
    const me = await (await fetch("/api/auth/me")).json();
    if (me.auth_enabled) {
      if (me.user) showUser(me.user);
      else await login();
    }
  } catch {
  }
});
function syncTarget(selectId, value) {
  const select = $(selectId);
  if (select && typeof value === "string" && [...select.options].some((option) => option.value === value)) select.value = value;
}
function showError(error) {
  $("error").textContent = messageOf(error);
  $("error").hidden = false;
}
function busy(value, message = "") {
  state.busy = value;
  for (const id of ["repo-scan", "project"]) {
    const el = $(id);
    if (el) el.disabled = value;
  }
  $("progress").textContent = message;
}
function view(name) {
  for (const item of ["repository", "code", "dependencies", "iac", "readiness", "images", "web", "assessments", "portfolio", "findings", "project", "jobs"]) $(item + "-view").hidden = item !== name;
  $("environment-label").textContent = name === "assessments" ? "UMUMIY TEKSHIRUV · AI ISHLATILMAYDI" : name === "web" ? "RUXSATLI SAYT · NUCLEI · GET" : name === "readiness" ? "PILOT · BOSHLASH" : name === "images" ? "IMAGE · TRIVY" : name === "dependencies" ? "CVE · OSV · KEV · NVD · EPSS" : name === "code" ? "KOD · SIRLAR · CWE/OWASP" : name === "findings" ? "TOPILMALAR · BARCHA SKANERLAR" : name === "project" ? "LOYIHA · BARCHA QATLAMLAR" : name === "iac" ? "IAC · TRIVY CONFIG · FAQAT O‘QISH" : name === "portfolio" ? "PORTFEL · UMUMIY BALL YO‘Q" : name === "jobs" ? "NAVBAT · JADVAL · XABARNOMA" : "REPOSITORY · FAQAT O‘QISH";
  document.querySelectorAll("[data-view]").forEach((button) => {
    const active = button.dataset.view === name;
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
    if (active) {
      const section = button.closest("details");
      if (section) section.open = true;
    }
  });
  document.dispatchEvent(new CustomEvent("view-shown", { detail: name }));
}
function showFixPlan(plan, anchorId) {
  const anchor = $(anchorId);
  if (!anchor || !plan) return;
  const old = anchor.parentElement?.querySelector(":scope > .fix-plan");
  if (old) old.remove();
  const e = escapeHTML;
  const colour = (text) => String(text).split("\n").map((line) => {
    const cls = line.startsWith("+++") || line.startsWith("---") ? "meta" : line.startsWith("+") ? "add" : line.startsWith("-") ? "del" : line.startsWith("@@") || line.startsWith("#") ? "meta" : "";
    return cls ? `<span class="${cls}">${e(line)}</span>` : e(line);
  }).join("\n");
  const diff = (item) => `<details class="fix-diff"><summary><code>${e(item.path)}</code>${item.rules ? " · " + item.rules.map((r) => e(r.rule_id)).join(", ") : ""}</summary>
    ${item.rules ? `<ul class="muted">${item.rules.map((r) => `<li>${e(r.rule_id)}${r.service_id ? " (" + e(r.service_id) + ")" : ""}: ${e(r.why)}</li>`).join("")}</ul>` : ""}
    <div class="fix-actions"><button class="ghost small" data-copy>Nusxa olish</button></div><pre class="diff">${colour(item.diff)}</pre></details>`;
  let body;
  if (plan.packages) {
    const rows = plan.packages.filter((p) => p.upgrade_to || p.without_fix.length);
    body = rows.length ? `<div class="table-wrap"><table><thead><tr><th>Paket</th><th>Hozir</th><th>Yangilash</th><th>OSV qayta tekshiruvi</th><th>Buyruq</th></tr></thead><tbody>${rows.map((p) => `<tr>
      <td>${e(p.ecosystem)} · <strong>${e(p.name)}</strong><br><small>${e(p.advisories.join(", "))}</small></td><td>${e(p.current)}</td>
      <td>${p.upgrade_to ? `<strong>${e(p.upgrade_to)}</strong>${p.major_upgrade ? ' <span class="badge amber">major</span>' : ""}` : '<span class="badge">tuzatish yo‘q</span>'}${p.without_fix.length ? `<br><small>Tuzatishsiz: ${e(p.without_fix.join(", "))}</small>` : ""}</td>
      <td>${{ clean: '<span class="badge green">toza</span>', still_affected: '<span class="badge red">hali zaif</span>', unavailable: "tekshirib bo‘lmadi", not_checked: "—" }[p.target_check] || e(p.target_check)}</td>
      <td>${p.command ? `<code>${e(p.command)}</code>` : "—"}${p.transitive_note ? `<br><small class="muted">${e(p.transitive_note)}</small>` : ""}</td></tr>`).join("")}</tbody></table></div>
      ${rows.flatMap((p) => p.diffs).map(diff).join("")}` : '<p class="muted">Tuzatish versiyasi ma’lum paket yo‘q.</p>';
  } else if ("dockerfile_snippet" in plan) {
    body = (plan.base_image_note ? `<p class="unknown-note">${e(plan.base_image_note)}</p>` : "") + (plan.dockerfile_snippet ? `<p>${e(plan.note)}</p><div class="fix-actions"><button class="ghost small" data-copy>Nusxa olish</button></div><pre class="diff">${e(plan.dockerfile_snippet)}</pre>` : "") + (plan.language_packages.length ? `<ul>${plan.language_packages.map((r) => `<li><code>${e(r.command || r.package + " → " + r.to)}</code>${r.major_upgrade ? ' <span class="badge amber">major</span>' : ""}</li>`).join("")}</ul>` : "") || '<p class="muted">Tuzatilgan versiyasi ma’lum paket yo‘q.</p>';
  } else {
    body = (plan.files || []).map(diff).join("") + ((plan.advice || []).length ? `<ul>${plan.advice.map((a) => `<li><strong>${e(a.rule_id)}</strong>${a.service_id ? " (" + e(a.service_id) + ")" : ""}${a.path ? " · " + e(a.path) : ""}: ${e(a.advice)}</li>`).join("")}</ul>` : "") || '<p class="muted">Avtomatik diff tuzib bo‘ladigan topilma yo‘q.</p>';
  }
  const box = document.createElement("details");
  box.className = "fix-plan pilot-help";
  const LABELS = {
    files_with_diff: "diffli fayl",
    rules_fixed: "diff bilan tuzatiladi",
    advice_only: "faqat tavsiya",
    packages: "paket",
    with_target: "yangilash versiyasi bor",
    target_clean: "OSV bo‘yicha toza",
    with_diff: "manifest diff",
    major_upgrades: "major yangilash",
    os_packages: "OS paketi",
    language_packages: "til paketi",
    eosl: "EOSL"
  };
  const summary = Object.entries(plan.summary || {}).filter(([, v]) => v).map(([k, v]) => v === true ? LABELS[k] || k : `${LABELS[k] || k}: ${v}`);
  box.innerHTML = `<summary>Tuzatish taklifi${summary.length ? " · " + e(summary.join(", ")) : ""}</summary>${body}<p class="hint-text">${e(plan.note || "")}</p>`;
  box.addEventListener("click", (event) => {
    const button = event.target.closest("[data-copy]");
    if (!button) return;
    const text = button.parentElement?.nextElementSibling?.textContent ?? "";
    navigator.clipboard?.writeText(text).then(() => {
      button.textContent = "Nusxalandi";
    }, () => {
    });
  });
  anchor.after(box);
}
async function fillBaseline(stage, reportId, elementId) {
  const box = $(elementId);
  if (!box) return;
  box.textContent = "";
  try {
    const diff = await api(`/api/baseline/${encodeURIComponent(stage)}/${encodeURIComponent(reportId)}`);
    if (diff.available === false) {
      box.innerHTML = `<span class="muted">${escapeHTML(diff.reason)}</span>`;
      return;
    }
    const counts = diff.counts;
    const parts = [
      `<strong>+${counts.new}</strong> yangi`,
      `<strong>−${counts.gone}</strong> yo‘qolgan`,
      `${counts.unchanged} o‘zgarmagan`
    ];
    const warn = (diff.warnings || []).map((w) => `<span class="gap-note">${escapeHTML(w)}</span>`).join(" ");
    box.innerHTML = `<span title="${escapeHTML(diff.note)}">${parts.join(" · ")}</span> ${warn}`;
  } catch (error) {
    box.innerHTML = `<span class="muted">${escapeHTML(messageOf(error))}</span>`;
  }
}
const reviewNames = { new: "Yangi", investigating: "Tekshirilmoqda", accepted_risk: "Xavf qabul qilingan", false_positive: "Noto‘g‘ri signal deb baholangan" };
function owaspBadges(tags) {
  return (tags || []).map((o) => `<span class="badge neutral" title="${escapeHTML(o.name)}">${escapeHTML(o.code)}</span>`).join(" ");
}
function verifiedBadge(finding) {
  const verified = "verified" in finding ? finding.verified : finding.runtime_verified;
  return verified ? '<span class="badge green">Dalil bilan tasdiqlangan</span>' : '<span class="badge amber">Qo‘lda tekshirish kerak</span>';
}
function sourceLink(report, evidence) {
  const base = report.repository.repository, commit = report.repository.commit;
  const label = escapeHTML(evidence.path + ":" + evidence.line);
  if (/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+$/.test(base || "") && /^[a-f0-9]{40}$/.test(commit || "") && evidence.path !== "profile.json") {
    return `<a href="${base}/blob/${commit}/${evidence.path.split("/").map(encodeURIComponent).join("/")}#L${evidence.line}" target="_blank" rel="noreferrer">${label} ↗</a>`;
  }
  return label;
}
function renderRepository(report) {
  state.repository = report;
  const s = report.summary;
  const verification = report.verification_summary || { confirmed_by_evidence: 0, manual_review_required: s.findings, total: s.findings };
  const facts = Object.fromEntries(report.evidence.map((e) => [e.id, e]));
  $("repository-result").className = "";
  $("repository-result").innerHTML = `<div class="repo-provenance"><span class="badge">SOURCE SNAPSHOT</span><strong>${escapeHTML(report.repository.commit?.slice(0, 12) || "Local snapshot")}</strong><span>${time(report.created_at)} · ${(report.duration_ms / 1e3).toFixed(2)} s</span><span class="badge amber">Amalda tasdiqlangan: ${s.runtime_confirmed}</span></div>
    <div class="metrics"><div class="metric"><span>Compose xizmatlari</span><strong>${s.services}</strong><small>${report.files.length} ta fayldan dalil olindi</small></div><div class="metric"><span>Host portlari</span><strong>${s.published_ports}</strong><small>Shundan ${s.loopback_ports} tasi loopback</small></div><div class="metric"><span>Ko‘rib chiqish kerak</span><strong>${s.findings}</strong><small>${verification.confirmed_by_evidence} tasdiqlangan / ${verification.manual_review_required} qo‘lda tekshirish</small></div></div>
    <div class="baseline-note">${s.loopback_ports === s.published_ports && s.published_ports ? "Berilgan konfiguratsiyadagi barcha host portlari localhost’ga bog‘langan. Ular internetga ochiq deb belgilanmadi." : "Host interfeyslarini alohida tekshiring; real firewall va daemon sozlamasi o‘qilmagan."}</div>
    <div class="export-row"><p>Manba nusxasi: <strong>${escapeHTML(report.repository.repository)}</strong></p><a href="/api/repository/reports/${report.id}/download" download>JSON hisobot ↓</a><a href="/api/repository/reports/${report.id}/sarif" download>SARIF eksport ↓</a></div>
    <div class="section-heading"><h2>Dalil bilan bog‘langan kuzatuvlar</h2><button id="compare-repository" class="link-button">Oldingi tahlil bilan solishtirish →</button></div><div id="repository-comparison"></div>
    ${report.findings.length ? report.findings.map((f, index) => {
    const review = state.reviews[report.input_sha256 + ":" + f.fingerprint] || {};
    return `<details class="repo-finding" ${index === 0 ? "open" : ""}><summary><span class="badge ${f.level === "error" ? "red" : f.level === "warning" ? "amber" : ""}">${escapeHTML(f.rule_id)}</span><span><strong>${escapeHTML(f.title)}</strong><small>${escapeHTML(f.service_id)} · ${escapeHTML(reviewNames[review.status || "new"])}</small></span><span class="finding-chevron">⌄</span></summary><div class="finding-body"><p>${escapeHTML(f.detail)}</p><p>${(f.cwe_ids || []).map(escapeHTML).join(", ") || "CWE aniqlanmagan"} ${owaspBadges(f.owasp_top10_2025)} ${verifiedBadge(f)}</p><p class="evidence-label">Manba dalili — fayl, qator va konfiguratsiya tuzilishi. Parol, token yoki boshqa maxfiy qiymat emas, faqat xatoning aniq joyini ko‘rsatadi.</p><div class="repo-evidence">${f.evidence_ids.map((id) => {
      const e = facts[id];
      return `<div><span>${escapeHTML(id)}</span><div><strong>${escapeHTML(e.label)}</strong><p>${escapeHTML(typeof e.value === "object" ? JSON.stringify(e.value) : e.value)}</p><small>${sourceLink(report, e)}</small></div></div>`;
    }).join("")}</div><p class="remediation"><strong>Tavsiya:</strong> ${escapeHTML(f.remediation)}</p><form class="review-form" data-fingerprint="${f.fingerprint}"><label>Holat<select name="status">${Object.entries(reviewNames).map(([v, label]) => `<option value="${v}" ${review.status === v ? "selected" : ""}>${label}</option>`).join("")}</select></label><label>Mas’ul<input name="owner" maxlength="120" placeholder="Jamoa yoki mas’ul" value="${escapeHTML(review.owner || "")}"></label><label class="review-note">Qaror asosi<textarea name="note" maxlength="1000" rows="2" placeholder="Tekshiruv yoki qarorning sababini yozing">${escapeHTML(review.note || "")}</textarea></label><button class="secondary" type="submit">Qarorni saqlash</button><p class="review-feedback" role="status">${review.updated_at ? "Saqlangan: " + time(review.updated_at) : "Qo‘lda baholash statik dalilni o‘zgartirmaydi."}</p></form></div></details>`;
  }).join("") : '<div class="empty">Joriy qoidalar bo‘yicha kuzatuv topilmadi. Bu umumiy xavfsizlik xulosasi emas.</div>'}
    <details class="source-details"><summary>Xizmatlar va host portlari (${s.services})</summary><div class="table-wrap"><table><thead><tr><th>Xizmat</th><th>Host → konteyner</th><th>Compose tarmog‘i</th></tr></thead><tbody>${report.services.map((service) => `<tr><td>${escapeHTML(service.id)}</td><td>${service.ports.map((p) => escapeHTML((p.host_ip || "default") + ":" + p.published + " → " + p.target + "/" + p.protocol)).join("<br>") || "Host porti berilmagan"}</td><td>${escapeHTML(service.networks.join(", ") || "Noma’lum / maxsus rejim")}</td></tr>`).join("")}</tbody></table></div></details>
    <details class="source-details"><summary>Proxy bog‘lanishlari (${s.proxy_routes})</summary><p class="muted">Bu konfiguratsiyada e’lon qilingan yo‘llar; runtime reachability yoki autentifikatsiya isbotlanmagan. depends_on aloqa yo‘li sifatida ishlatilmaydi.</p><div class="table-wrap"><table><thead><tr><th>Proxy : port</th><th>Yo‘l</th><th>Target</th><th>Protokol</th></tr></thead><tbody>${report.edges.map((e) => `<tr><td>${escapeHTML(e.from)} : ${escapeHTML(e.listen)}</td><td>${escapeHTML(e.location)}</td><td>${escapeHTML(e.to)} : ${e.target_port}</td><td>${escapeHTML(e.scheme)}</td></tr>`).join("")}</tbody></table></div></details>
    <details class="source-details"><summary>Qamrov, cheklovlar va fayl xeshlari</summary><ul class="muted">${[...report.unknowns, ...report.limits].map((u) => `<li>${escapeHTML(u)}</li>`).join("")}</ul><p class="hash">Input SHA-256: ${escapeHTML(report.input_sha256)}</p>${report.files.map((f) => `<p class="hash">${escapeHTML(f.path)}<br>${f.sha256}</p>`).join("")}</details>`;
  showFixPlan(report.fix_plan, "repository-comparison");
  $("repository-result").querySelectorAll(".review-form").forEach((form) => form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = form.querySelector("button");
    button.disabled = true;
    try {
      const saved = await api("/api/repository/review", { report_id: report.id, fingerprint: form.dataset.fingerprint, status: form.elements.status.value, owner: form.elements.owner.value, note: form.elements.note.value });
      state.reviews[report.input_sha256 + ":" + form.dataset.fingerprint] = saved;
      form.querySelector(".review-feedback").textContent = "Qaror saqlandi · " + time(saved.updated_at);
      form.closest("details").querySelector("summary small").textContent = report.findings.find((f) => f.fingerprint === form.dataset.fingerprint).service_id + " · " + reviewNames[saved.status];
    } catch (error) {
      form.querySelector(".review-feedback").textContent = messageOf(error);
    } finally {
      button.disabled = false;
    }
  }));
  $("compare-repository").addEventListener("click", async () => {
    try {
      const reports = await api("/api/repository/reports?profile_id=" + encodeURIComponent(report.profile_id));
      const index = reports.findIndex((r) => r.id === report.id);
      const previous = reports[index + 1];
      if (!previous) {
        $("repository-comparison").textContent = "Shu loyihaning oldingi hisoboti hali yo‘q. Qayta tahlildan keyin solishtirish mumkin.";
        return;
      }
      const result = await api("/api/repository/compare", { before: previous.id, after: report.id });
      $("repository-comparison").innerHTML = `<p class="baseline-note">Yangi: ${result.added.length} · Joriy tahlilda yo‘q: ${result.absent.length} · Saqlangan: ${result.unchanged.length}<br>${escapeHTML(result.caution)}${result.coverage_changed ? " Qamrov ham o‘zgargan — alohida tekshiring." : ""}</p>`;
    } catch (error) {
      showError(error);
    }
  });
}
async function loadRepository() {
  busy(true);
  state.repository = null;
  $("repository-result").textContent = "Tanlangan loyiha natijasi yuklanmoqda…";
  const project = state.projects.find((p) => p.id === state.project);
  $("project-scope").textContent = project ? `${project.mode === "bundled_sample" ? "Tayyor o‘quv namunasi" : "Ro‘yxatdan o‘tgan lokal loyiha"} · ${project.compose} · ${project.proxy_bindings} ta proxy mapping${project.owner ? " · Mas’ul: " + project.owner : ""}` : "";
  try {
    const [reports, reviews] = await Promise.all([api("/api/repository/reports?profile_id=" + encodeURIComponent(state.project)), api("/api/repository/reviews")]);
    state.reviews = reviews;
    if (reports.length) renderRepository(await api("/api/repository/reports/" + reports[0].id));
    else {
      $("repository-result").className = "empty";
      $("repository-result").textContent = "Bu loyiha uchun hali hisobot yo‘q. Birinchi tahlilni boshlang.";
    }
  } finally {
    busy(false);
  }
}
async function scanRepository(profileId = state.project) {
  if (state.busy) throw new Error("Tekshiruv davom etmoqda.");
  if (!state.projects.some((p) => p.id === profileId)) throw new Error("Loyiha ro‘yxatdan o‘tmagan.");
  state.project = profileId;
  $("project").value = profileId;
  state.repository = null;
  $("repository-result").textContent = "Tanlangan loyiha tahlil qilinmoqda…";
  $("error").hidden = true;
  view("repository");
  busy(true, "Tanlangan loyihaning lokal manba fayllari o‘qilmoqda…");
  const project = state.projects.find((p) => p.id === profileId);
  $("project-scope").textContent = `${project.name} · ${project.compose} · ${project.proxy_bindings} ta proxy mapping`;
  try {
    const report = await api("/api/repository/scan", { profile_id: profileId });
    renderRepository(report);
    return { id: report.id, profile_id: profileId, summary: report.summary };
  } catch (error) {
    showError(error);
    throw error;
  } finally {
    busy(false);
  }
}
async function init() {
  document.querySelectorAll("[data-view]").forEach((b) => b.addEventListener("click", () => view(b.dataset.view ?? "")));
  $("repo-scan").addEventListener("click", () => scanRepository().catch(() => {
  }));
  $("project").addEventListener("change", () => {
    state.project = $("project").value;
    loadRepository().catch(showError);
  });
  whenShown(["repository"], loadProjects);
}
async function loadProjects() {
  try {
    state.projects = await api("/api/repository/profiles");
    $("project").innerHTML = state.projects.map((p) => `<option value="${escapeHTML(p.id)}">${escapeHTML(p.name)}</option>`).join("");
    state.project = state.projects.some((p) => p.id === "crapi") ? "crapi" : state.projects[0]?.id;
    $("project").value = state.project;
    await loadRepository();
    registerTools();
  } catch (error) {
    showError(error);
  }
}
function registerTools() {
  const context = document.modelContext;
  if (!context?.registerTool) return;
  const lifecycle = new AbortController();
  window.addEventListener("pagehide", () => lifecycle.abort(), { once: true });
  const tools = [
    { name: "read_repository_result", title: "Read repository source analysis", description: "Read the selected source-only repository report. Findings are tagged verified/manual-review; unverified findings are not confirmed attacks.", inputSchema: { type: "object", properties: {}, additionalProperties: false }, annotations: { readOnlyHint: true, untrustedContentHint: false }, execute(input) {
      if (!input || typeof input !== "object" || Array.isArray(input) || Object.keys(input).length) throw new Error("No parameters accepted.");
      return state.repository ? { id: state.repository.id, profile_id: state.repository.profile_id, summary: state.repository.summary, verification: state.repository.verification_summary, commit: state.repository.repository.commit } : { state: "no_result" };
    } },
    { name: "scan_repository_source", title: "Analyze a registered local project", description: "Read the selected or specified registered project source, save a report locally, and update the interface. No repository code or target requests are executed. Arbitrary disk paths are not accepted.", inputSchema: { type: "object", properties: { profile_id: { type: "string", enum: state.projects.map((p) => p.id) } }, additionalProperties: false }, annotations: { readOnlyHint: false, untrustedContentHint: false }, execute(input) {
      if (!input || typeof input !== "object" || Array.isArray(input) || Object.keys(input).some((k) => k !== "profile_id") || "profile_id" in input && !state.projects.some((p) => p.id === input.profile_id)) throw new Error("Invalid registered project.");
      return scanRepository(input.profile_id || state.project);
    } }
  ];
  for (const tool of tools) {
    try {
      Promise.resolve(context.registerTool(tool, { signal: lifecycle.signal })).catch(() => {
      });
    } catch {
    }
  }
}
init();
