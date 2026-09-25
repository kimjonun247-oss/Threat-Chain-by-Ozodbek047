'use strict';
/* The workbench shell: command bar, modal windows, keyboard navigation and the
   theme switch. Everything the old build could only do through a .cmd script
   lives here as a window, so an operator never has to leave the browser to
   register a target or set a key.

   Three constraints shaped it:
     - No build step and no framework. Plain modules, same as the rest of dist/.
     - CSP: script-src 'self'; style-src 'self'. Nothing is written inline --
       state that used to need an inline style becomes a class, and a test
       asserts the files stay free of both.
     - Nothing here decides anything. Every window posts to an endpoint that
       already validates; the UI never invents a value the server did not. */
(() => {
  const e = escapeHTML;
  const THEME_KEY = 'threatchain.theme';

  /* ---- theme ---------------------------------------------------------- */
  function applyTheme(mode) {
    document.documentElement.setAttribute('data-theme', mode);
    const button = $('theme-toggle');
    if (button) { button.setAttribute('aria-pressed', String(mode === 'dark')); button.title = mode === 'dark' ? 'Yorug‘ rejimga o‘tish' : 'Qorong‘u rejimga o‘tish'; }
    try { localStorage.setItem(THEME_KEY, mode); } catch (error) { /* private mode: the choice simply is not remembered */ }
  }
  let stored = null;
  try { stored = localStorage.getItem(THEME_KEY); } catch (error) { stored = null; }
  applyTheme(stored || (window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
  $('theme-toggle')?.addEventListener('click', () =>
    applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark'));

  /* ---- modal windows --------------------------------------------------- */
  let lastFocus = null;
  function closeModal() {
    $('modal').hidden = true;
    $('modal-body').innerHTML = '';
    if (lastFocus && document.contains(lastFocus)) lastFocus.focus();
  }
  function openModal(title, html, onReady) {
    lastFocus = document.activeElement;
    $('modal-title').textContent = title;
    $('modal-body').innerHTML = html;
    $('modal').hidden = false;
    if (onReady) onReady($('modal-body'));
    const first = $('modal-body').querySelector('input,select,textarea,button');
    (first || $('modal-close')).focus();
  }
  window.openModal = openModal;
  window.closeModal = closeModal;
  $('modal-close').addEventListener('click', closeModal);
  $('modal').addEventListener('mousedown', event => { if (event.target === $('modal')) closeModal(); });

  function feedback(box, message, ok) {
    const line = box.querySelector('.modal-feedback');
    if (!line) return;
    line.textContent = message;
    line.className = 'modal-feedback ' + (ok ? 'ok' : 'bad');
  }

  async function submit(box, path, payload, done) {
    const button = box.querySelector('[data-submit]');
    if (button) button.disabled = true;
    try {
      const result = await api(path, payload);
      feedback(box, done(result), true);
      document.dispatchEvent(new CustomEvent('registry-changed'));
    } catch (error) {
      feedback(box, error.message, false);
    } finally {
      if (button) button.disabled = false;
    }
  }

  /* ---- the windows ------------------------------------------------------ */
  const WINDOWS = {
    register: () => openModal('Nishon qo‘shish', `
      <div class="facets" role="tablist">
        <button class="chip" data-tab="project" aria-pressed="true">Manba loyihasi</button>
        <button class="chip" data-tab="remote" aria-pressed="false">Masofaviy repozitoriy</button>
        <button class="chip" data-tab="image" aria-pressed="false">Docker image</button>
        <button class="chip" data-tab="web" aria-pressed="false">Sayt / API</button>
      </div>
      <form id="reg-project" data-panel="project">
        <label>Loyiha ID<input name="id" required maxlength="40" placeholder="masalan: ichki-api"></label>
        <label>Manba papkasi<span class="path-field"><input name="root" id="reg-root" required placeholder="/Users/.../loyiha"><button type="button" class="secondary" id="reg-pick">Papka tanlash</button></span></label>
        <div id="reg-browser" class="folder-browser" hidden></div>
        <label>Compose fayli (ixtiyoriy)<input name="compose" placeholder="docker-compose.yml"></label>
        <label>Nomi<input name="name" maxlength="120" placeholder="Ko‘rinadigan nom"></label>
        <div class="modal-actions"><button type="button" class="secondary" data-close>Yopish</button><button class="primary" data-submit>Ro‘yxatga olish</button></div>
        <p class="modal-feedback"></p>
      </form>
      <form id="reg-remote" data-panel="remote" hidden>
        <label>Loyiha ID<input name="id" required maxlength="40" placeholder="masalan: ichki-api-git"></label>
        <label>Repozitoriy manzili<input name="url" required placeholder="https://github.com/egasi/repo.git"></label>
        <label>Branch yoki tag (ixtiyoriy)<input name="ref" maxlength="200" placeholder="main"></label>
        <label>Nomi<input name="name" maxlength="120"></label>
        <p class="hint-text">Manzil ichida foydalanuvchi/parol bo‘lmasin.</p>
        <div class="modal-actions"><button type="button" class="secondary" data-close>Yopish</button><button class="primary" data-submit>Ro‘yxatga olish</button></div>
        <p class="modal-feedback"></p>
      </form>
      <form id="reg-image" data-panel="image" hidden>
        <label>Image ID<input name="id" required maxlength="40" placeholder="masalan: ichki-api-image"></label>
        <label>Image manzili<input name="reference" required placeholder="registry.example.com/jamoa/app:1.0 yoki nom@sha256:…"></label>
        <label>Registry autentifikatsiyasi<select name="auth"><option value="none">Kerak emas (ochiq registry)</option><option value="environment">Muhit o‘zgaruvchisidan</option><option value="docker-config">Mavjud <code>docker login</code> seansidan</option></select></label>
        <label>Nomi<input name="name" maxlength="120"></label>
        <p class="hint-text">Yopiq registry uchun parol muhit o‘zgaruvchisida: <code>THREATCHAIN_REGISTRY_&lt;HOST&gt;_USERNAME</code> / <code>…_PASSWORD</code>.</p>
        <div class="modal-actions"><button type="button" class="secondary" data-close>Yopish</button><button class="primary" data-submit>Ro‘yxatga olish</button></div>
        <p class="modal-feedback"></p>
      </form>
      <form id="reg-web" data-panel="web" hidden>
        <label>Nishon ID<input name="id" required maxlength="40" placeholder="masalan: staging-api"></label>
        <label>URL<input name="url" required placeholder="https://staging.example.test"></label>
        <label>Ruxsat bergan mas’ul<input name="owner" required maxlength="120" placeholder="Ism va lavozim"></label>
        <label>So‘rovlar orasidagi kechikish (soniya)<input name="rate_delay" type="number" min="0.5" max="30" step="0.5" placeholder="0.5"></label>
        <label><input name="authenticated" type="checkbox"> Nishon autentifikatsiya talab qiladi</label>
        <p class="hint-text">Faqat ruxsat berilgan nishon. Token muhit o‘zgaruvchisida: <code>THREATCHAIN_WEB_AUTH_&lt;ID&gt;</code>.</p>
        <div class="modal-actions"><button type="button" class="secondary" data-close>Yopish</button><button class="primary" data-submit>Ro‘yxatga olish</button></div>
        <p class="modal-feedback"></p>
      </form>`, box => {
      box.querySelectorAll('[data-tab]').forEach(tab => tab.addEventListener('click', () => {
        box.querySelectorAll('[data-tab]').forEach(t => t.setAttribute('aria-pressed', String(t === tab)));
        box.querySelectorAll('[data-panel]').forEach(p => { p.hidden = p.dataset.panel !== tab.dataset.tab; });
      }));
      box.querySelectorAll('[data-close]').forEach(b => b.addEventListener('click', closeModal));

      /* Folder picker. The endpoint answers only when the server was started
         with --allow-registration, the same flag registration itself needs, so
         a refusal here is the same refusal the form would give. */
      const browser = box.querySelector('#reg-browser');
      async function openFolder(path) {
        browser.hidden = false;
        browser.innerHTML = '<p class="hint-text">Yuklanmoqda…</p>';
        try {
          const list = await api('/api/registry/browse' + (path ? '?path=' + encodeURIComponent(path) : ''));
          browser.innerHTML = `<div class="folder-head"><span>${e(list.path)}</span>
            <button type="button" class="primary" data-use="${e(list.path)}" data-compose="${e(list.compose || '')}">Shu papkani olish</button></div>
            <ul class="folder-list">
            ${list.parent ? `<li><button type="button" data-open="${e(list.parent)}">${'\u2191'} yuqoriga</button></li>` : ''}
            ${list.entries.map(item => `<li><button type="button" data-open="${e(item.path)}">${e(item.name)}</button>${item.compose ? `<span class="tag">${e(item.compose)}</span>` : ''}</li>`).join('')}
            </ul>`;
        } catch (error) {
          browser.innerHTML = `<p class="modal-feedback bad">${e(error.message)}</p>`;
        }
      }
      browser.addEventListener('click', event => {
        const step = event.target.closest('[data-open]');
        if (step) { openFolder(step.dataset.open); return; }
        const use = event.target.closest('[data-use]');
        if (!use) return;
        box.querySelector('#reg-root').value = use.dataset.use;
        if (use.dataset.compose) box.querySelector('#reg-project [name="compose"]').value = use.dataset.compose;
        browser.hidden = true;
      });
      box.querySelector('#reg-pick').addEventListener('click', () => openFolder(''));
      box.querySelector('#reg-project').addEventListener('submit', event => {
        event.preventDefault();
        const form = new FormData(event.target);
        submit(box, '/api/registry/project', {
          id: form.get('id').trim(), root: form.get('root').trim(),
          compose: form.get('compose').trim(), name: form.get('name').trim()
        }, r => `Ro‘yxatga olindi: ${r.id}. Sahifani yangilang yoki skanerni tanlang.`);
      });
      box.querySelector('#reg-remote').addEventListener('submit', event => {
        event.preventDefault();
        const form = new FormData(event.target);
        submit(box, '/api/registry/remote', {
          id: form.get('id').trim(), url: form.get('url').trim(),
          ref: form.get('ref').trim(), name: form.get('name').trim()
        }, r => `Masofaviy repozitoriy ro‘yxatga olindi: ${r.id}`);
      });
      box.querySelector('#reg-image').addEventListener('submit', event => {
        event.preventDefault();
        const form = new FormData(event.target);
        submit(box, '/api/registry/image', {
          id: form.get('id').trim(), reference: form.get('reference').trim(),
          name: form.get('name').trim(), auth: form.get('auth')
        }, r => `Image ro‘yxatga olindi: ${r.id}` + (r.pinned ? '' : ' (teg — digest har skanda yoziladi)'));
      });
      box.querySelector('#reg-web').addEventListener('submit', event => {
        event.preventDefault();
        const form = new FormData(event.target);
        const delay = parseFloat(form.get('rate_delay'));
        submit(box, '/api/registry/web', {
          id: form.get('id').trim(), url: form.get('url').trim(), owner: form.get('owner').trim(),
          authenticated: form.get('authenticated') === 'on',
          ...(Number.isFinite(delay) ? {rate_delay: delay} : {})
        }, r => `Nishon ro‘yxatga olindi: ${r.id} · ${r.url}`
             + (r.auth_variable ? ` — ${r.auth_variable} o‘zgaruvchisini o‘rnating` : ''));
      });
    }),

    settings: async () => {
      let status = {};
      try { status = await api('/api/settings'); } catch (error) { status = {error: error.message}; }
      openModal('Sozlamalar', `
        <h3>NVD API kaliti</h3>
        <p class="hint-text">Holat: <strong>${status.nvd_api_key?.present ? 'o‘rnatilgan (' + e(status.nvd_api_key.source) + ')' : 'o‘rnatilmagan'}</strong>${status.nvd_api_key?.masked ? ' · ' + e(status.nvd_api_key.masked) : ''}</p>
        <form id="settings-nvd">
          <label>Yangi kalit<input name="key" type="password" autocomplete="off" placeholder="nvd.nist.gov/developers/request-an-api-key"></label>
          <div class="modal-actions"><button type="button" class="secondary" data-clear>Kalitni o‘chirish</button><button class="primary" data-submit>Saqlash</button></div>
          <p class="modal-feedback"></p>
        </form>
        <h3>Muhit</h3>
        <table class="kv"><tbody>
          <tr><td>Versiya</td><td>${e(status.version || '—')}</td></tr>
          <tr><td>Python</td><td>${e(status.python || '—')}</td></tr>
          <tr><td>Bo‘sh disk</td><td>${e(status.free_disk_gb ?? '—')} GB</td></tr>
          <tr><td>Kod barmoq izi</td><td>${e(status.code_fingerprint || '—')}</td></tr>
        </tbody></table>
`, box => {
        box.querySelector('#settings-nvd').addEventListener('submit', event => {
          event.preventDefault();
          const value = new FormData(event.target).get('key').trim();
          if (!value) { feedback(box, 'Kalit bo‘sh.', false); return; }
          submit(box, '/api/settings/nvd-key', {key: value}, () => 'Saqlandi. Keyingi CVE tekshiruvida ishlatiladi.');
          event.target.reset();
        });
        box.querySelector('[data-clear]').addEventListener('click', () =>
          submit(box, '/api/settings/nvd-key', {key: ''}, () => 'Kalit o‘chirildi.'));
      });
    },

    export: async () => {
      let projects = [];
      try { projects = (await api('/api/portfolio')).projects; } catch (error) { projects = []; }
      openModal('Eksport markazi', `
        <h3>Loyiha bo‘yicha</h3>
        <label>Loyiha<select id="export-project">${projects.map(p => `<option value="${e(p.id)}">${e(p.name)}</option>`).join('') || '<option value="">Loyiha yo‘q</option>'}</select></label>
        <p class="modal-feedback"></p>
        <div class="modal-actions"><button class="secondary" id="export-sbom">Loyiha SBOM (CycloneDX) ↓</button></div>
        <h3>Hisobot bo‘yicha</h3>
        <table class="kv"><tbody>
          <tr><td>Umumiy tekshiruv</td><td>SARIF · Markdown · JSON — “Umumiy tekshiruv” bo‘limidagi hisobot ustida</td></tr>
          <tr><td>Repository</td><td>SARIF · JSON</td></tr>
          <tr><td>Kod, CVE, IaC, Sayt</td><td>JSON · Markdown</td></tr>
          <tr><td>Docker image</td><td>JSON · CycloneDX SBOM</td></tr>
        </tbody></table>
`, box => {
        box.querySelector('#export-sbom').addEventListener('click', () => {
          const project = box.querySelector('#export-project').value;
          if (!project) { feedback(box, 'Avval loyiha tanlang.', false); return; }
          window.location.href = '/api/images/sbom?project=' + encodeURIComponent(project);
        });
      });
    },

  };

  document.querySelectorAll('[data-modal]').forEach(button =>
    button.addEventListener('click', () => WINDOWS[button.dataset.modal]?.()));

  /* ---- keyboard -------------------------------------------------------- */
  const GOTO = {t: 'findings', l: 'portfolio', u: 'assessments', b: 'readiness', p: 'project'};
  let pendingGoto = false;
  document.addEventListener('keydown', event => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(event.target.tagName) || event.target.isContentEditable;
    if (event.key === 'Escape') {
      if (!$('modal').hidden) closeModal();
      else if (!$('drawer').hidden) $('drawer-close').click();
      return;
    }
    if (typing || event.metaKey || event.ctrlKey || event.altKey) return;
    if (event.key === '/') { event.preventDefault(); $('global-search').focus(); return; }
    if (pendingGoto && GOTO[event.key]) { pendingGoto = false; view(GOTO[event.key]); return; }
    pendingGoto = event.key === 'g';
  });

  /* ---- global search --------------------------------------------------- */
  /* Typing searches. The request is held back briefly so one word does not
     become one request per letter; Enter sends it immediately. */
  let typingTimer = null;
  function runSearch() {
    clearTimeout(typingTimer);
    document.dispatchEvent(new CustomEvent('search-requested', {detail: $('global-search').value.trim()}));
    view('findings');
  }
  $('global-search').addEventListener('input', () => {
    clearTimeout(typingTimer);
    typingTimer = setTimeout(runSearch, 250);
  });
  $('commandbar').addEventListener('submit', event => { event.preventDefault(); runSearch(); });

  /* ---- sidebar: recent scans ------------------------------------------ */
  /* The sidebar always said "no scans yet": nothing ever filled it. It now
     lists the same rows as the dashboard feed (server: dashboard.recent_scans)
     and opens the stage a row belongs to. Refreshed whenever a view is shown,
     so a scan finished in one section appears without a page reload. */
  const STAGE_TITLE = {code: 'Kod', dependencies: 'CVE', iac: 'IaC', images: 'Image', web: 'Sayt', repository: 'Repository'};
  const STATE_TITLE = {completed: 'tugadi', partial: 'qisman', failed: 'yiqildi', running: 'ishlamoqda', queued: 'navbatda',
                       cancelled: 'bekor qilindi', no_supported_packages: 'manifest yo‘q'};
  let historyLoading = false;
  async function loadHistory() {
    const box = $('history');
    if (!box || historyLoading) return;
    historyLoading = true;
    try {
      const rows = (await api('/api/dashboard')).recent || [];
      box.innerHTML = rows.length ? rows.map(r => `<button type="button" data-history-stage="${e(r.stage)}">
          <b>${e(STAGE_TITLE[r.stage] || r.stage)}</b> · ${e(r.target)} · ${e(STATE_TITLE[r.state] || r.state || '—')}${r.count == null ? '' : ' · ' + e(r.count)}
          <time>${e(time(r.created_at))}</time></button>`).join('')
        : '<p>Hali tekshiruv yo‘q.</p>';
    } catch (error) {
      box.innerHTML = '<p>Ro‘yxat yuklanmadi.</p>';
    } finally {
      historyLoading = false;
    }
  }
  $('history')?.addEventListener('click', event => {
    const button = event.target.closest('[data-history-stage]');
    if (button && STAGE_TITLE[button.dataset.historyStage]) view(button.dataset.historyStage);
  });
  document.addEventListener('view-shown', loadHistory);
  loadHistory();
})();
