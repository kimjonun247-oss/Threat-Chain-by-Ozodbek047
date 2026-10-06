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
  function applyTheme(mode: string) {
    document.documentElement.setAttribute('data-theme', mode);
    const button = $('theme-toggle');
    if (button) { button.setAttribute('aria-pressed', String(mode === 'dark')); button.title = mode === 'dark' ? 'Yorug‘ rejimga o‘tish' : 'Qorong‘u rejimga o‘tish'; }
    try { localStorage.setItem(THEME_KEY, mode); } catch (error) { /* private mode: the choice simply is not remembered */ }
  }
  let stored: string | null;
  try { stored = localStorage.getItem(THEME_KEY); } catch (error) { stored = null; }
  applyTheme(stored || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
  $('theme-toggle')?.addEventListener('click', () =>
    applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark'));

  /* ---- modal windows --------------------------------------------------- */
  let lastFocus: ApiData = null;
  function closeModal() {
    $('modal').hidden = true;
    $('modal-body').innerHTML = '';
    if (lastFocus && document.contains(lastFocus)) lastFocus.focus();
  }
  function openModal(title: string, html: string, onReady: ApiData) {
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
  $('modal').addEventListener('mousedown', event => { if ((event.target as Field) === $('modal')) closeModal(); });

  function feedback(box: Field, message: string, ok: ApiData) {
    const line = box.querySelector('.modal-feedback');
    if (!line) return;
    line.textContent = message;
    line.className = 'modal-feedback ' + (ok ? 'ok' : 'bad');
  }

  async function submit(box: Field, path: string, payload: ApiData, done: ApiData) {
    const button = box.querySelector('[data-submit]');
    if (button) button.disabled = true;
    try {
      const result = await api(path, payload);
      feedback(box, done(result), true);
      document.dispatchEvent(new CustomEvent('registry-changed'));
    } catch (error) {
      feedback(box, messageOf(error), false);
    } finally {
      if (button) button.disabled = false;
    }
  }

  /* ---- the windows ------------------------------------------------------ */
  const WINDOWS: Record<string, () => void | Promise<void>> = {
    register: () => openModal('Nishon qo‘shish', `
      <div class="facets" role="tablist">
        <button class="chip" data-tab="project" aria-pressed="true">Manba loyihasi</button>
        <button class="chip" data-tab="remote" aria-pressed="false">Masofaviy repozitoriy</button>
        <button class="chip" data-tab="image" aria-pressed="false">Docker image</button>
        <button class="chip" data-tab="web" aria-pressed="false">Sayt / API</button>
        <button class="chip" data-tab="remove" aria-pressed="false">Ro‘yxatdan chiqarish</button>
      </div>
      <form id="reg-project" data-panel="project">
        <div class="reg-gate" id="reg-gate" hidden><p>Xavfsizlik uchun brauzerdan manba papkasini ro‘yxatga olish <strong>o‘chirilgan</strong>. Yoqilsa, server uy papkangizdagi papkalarni ko‘rsatadi va siz tanlagan papkani o‘qib indekslaydi — bu ongli qaror. Ko‘p foydalanuvchi serverda yoqmang; qayta ishga tushirilganda o‘zi o‘chadi.</p><button type="button" class="primary" id="reg-enable"><svg class="ic"><use href="#i-check"/></svg> Ro‘yxatga olishni yoqish</button></div>
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
        <label><input name="replace" type="checkbox"> Mavjud bo‘lsa yangilash (masalan, eski tegni yangisiga almashtirish)</label>
        <p class="hint-text">Yopiq registry uchun parol muhit o‘zgaruvchisida: <code>THREATCHAIN_REGISTRY_&lt;HOST&gt;_USERNAME</code> / <code>…_PASSWORD</code>.</p>
        <div class="modal-actions"><button type="button" class="secondary" data-close>Yopish</button><button class="primary" data-submit>Ro‘yxatga olish</button></div>
        <p class="modal-feedback"></p>
      </form>
      <form id="reg-web" data-panel="web" hidden>
        <label>Nishon ID<input name="id" required maxlength="40" placeholder="masalan: staging-api"></label>
        <label>URL<input name="url" required placeholder="https://staging.example.test"></label>
        <label>Ruxsat bergan mas’ul<input name="owner" required maxlength="120" placeholder="Ism va lavozim"></label>
        <label>So‘rovlar orasidagi kechikish (soniya)<input name="rate_delay" type="number" min="0.5" max="30" step="0.5" placeholder="0.5"></label>
        <fieldset class="window-fields"><legend>Ruxsat oynasi (ixtiyoriy)</legend>
          <label>Kunlar<input name="window_days" placeholder="mon,tue,wed,thu,fri"></label>
          <label>Boshlanish<input name="window_start" type="time"></label>
          <label>Tugash<input name="window_end" type="time"></label>
          <label>Vaqt zonasi<input name="window_tz" placeholder="+05:00" maxlength="40"></label>
          <label>Kunlik so‘rov limiti<input name="daily_budget" type="number" min="1" max="100000" step="1" placeholder="cheklanmagan"></label>
        </fieldset>
        <label><input name="authenticated" type="checkbox"> Nishon autentifikatsiya talab qiladi</label>
        <label><input name="replace" type="checkbox"> Mavjud bo‘lsa yangilash (ruxsat qaytadan qayd etiladi)</label>
        <p class="hint-text">Faqat ruxsat berilgan nishon. Token muhit o‘zgaruvchisida: <code>THREATCHAIN_WEB_AUTH_&lt;ID&gt;</code>.</p>
        <div class="modal-actions"><button type="button" class="secondary" data-close>Yopish</button><button class="primary" data-submit>Ro‘yxatga olish</button></div>
        <p class="modal-feedback"></p>
      </form>
      <form id="reg-remove" data-panel="remove" hidden>
        <label>Turi<select name="kind"><option value="image">Docker image</option><option value="web">Sayt / API</option><option value="code">Manba / masofaviy repozitoriy</option><option value="repository">Repository (Compose) profili</option></select></label>
        <label>ID<input name="id" required maxlength="40" placeholder="ro‘yxatdagi ID"></label>
        <p class="hint-text">Faqat ro‘yxat yozuvi o‘chiriladi. Oldingi hisobotlar dalil sifatida tarixda qoladi, loyiha fayllariga tegilmaydi.</p>
        <div class="modal-actions"><button type="button" class="secondary" data-close>Yopish</button><button class="primary" data-submit>Ro‘yxatdan chiqarish</button></div>
        <p class="modal-feedback"></p>
      </form>`, (box: Field) => {
      box.querySelectorAll('[data-tab]').forEach((tab: Field) => tab.addEventListener('click', () => {
        box.querySelectorAll('[data-tab]').forEach((t: ApiData) => t.setAttribute('aria-pressed', String(t === tab)));
        box.querySelectorAll('[data-panel]').forEach((p: ApiData) => { p.hidden = p.dataset.panel !== tab.dataset.tab; });
      }));
      box.querySelectorAll('[data-close]').forEach((b: ApiData) => b.addEventListener('click', closeModal));

      /* Folder picker. The endpoint answers only when the server was started
         with --allow-registration, the same flag registration itself needs, so
         a refusal here is the same refusal the form would give. */
      const browser = box.querySelector('#reg-browser');
      async function openFolder(path: string) {
        browser.hidden = false;
        browser.innerHTML = '<p class="hint-text">Yuklanmoqda…</p>';
        try {
          const list = await api('/api/registry/browse' + (path ? '?path=' + encodeURIComponent(path) : ''));
          browser.innerHTML = `<div class="folder-head"><span>${e(list.path)}</span>
            <button type="button" class="primary" data-use="${e(list.path)}" data-compose="${e(list.compose || '')}">Shu papkani olish</button></div>
            <ul class="folder-list">
            ${list.parent ? `<li><button type="button" data-open="${e(list.parent)}">${'\u2191'} yuqoriga</button></li>` : ''}
            ${list.entries.map((item: ApiData) => `<li><button type="button" data-open="${e(item.path)}">${e(item.name)}</button>${item.compose ? `<span class="tag">${e(item.compose)}</span>` : ''}</li>`).join('')}
            </ul>`;
        } catch (error) {
          browser.innerHTML = `<p class="modal-feedback bad">${e(messageOf(error))}</p>`;
        }
      }
      browser.addEventListener('click', (event: Event) => {
        const step = (event.target as Field).closest('[data-open]');
        if (step) { openFolder(step.dataset.open ?? ''); return; }
        const use = (event.target as Field).closest('[data-use]');
        if (!use) return;
        box.querySelector('#reg-root').value = use.dataset.use ?? '';
        if (use.dataset.compose) box.querySelector('#reg-project [name="compose"]').value = use.dataset.compose;
        browser.hidden = true;
      });
      box.querySelector('#reg-pick').addEventListener('click', () => openFolder(''));

      /* Folder registration is off by default (the same boundary as the
         --allow-registration flag). Rather than send the operator to a terminal,
         the gate here turns it on for the running server after a warning. */
      api('/api/settings').then((s: ApiData) => {
        if (!s.registration_enabled) (box.querySelector('#reg-gate') as Field).hidden = false;
      }).catch(() => { /* settings unavailable: the picker itself still reports the gate on use */ });
      box.querySelector('#reg-enable').addEventListener('click', async () => {
        if (!confirm('Brauzerdan papka ro‘yxatga olishni yoqasizmi? Server uy papkangizdagi papkalarni o‘qiy oladi va tanlagan papkangizni indekslaydi. Faqat o‘zingiz ishonchli lokal mashinada yoqing.')) return;
        try {
          await api('/api/settings/allow-registration', {enabled: true});
          (box.querySelector('#reg-gate') as Field).hidden = true;
        } catch (error) { feedback(box.querySelector('#reg-project'), messageOf(error), false); }
      });
      box.querySelector('#reg-project').addEventListener('submit', (event: Event) => {
        event.preventDefault();
        const form = formData((event.target as Field));
        submit(box, '/api/registry/project', {
          id: form.get('id').trim(), root: form.get('root').trim(),
          compose: form.get('compose').trim(), name: form.get('name').trim()
        }, (r: ApiData) => `Ro‘yxatga olindi: ${r.id}. Sahifani yangilang yoki skanerni tanlang.`);
      });
      box.querySelector('#reg-remote').addEventListener('submit', (event: Event) => {
        event.preventDefault();
        const form = formData((event.target as Field));
        submit(box, '/api/registry/remote', {
          id: form.get('id').trim(), url: form.get('url').trim(),
          ref: form.get('ref').trim(), name: form.get('name').trim()
        }, (r: ApiData) => `Masofaviy repozitoriy ro‘yxatga olindi: ${r.id}`);
      });
      box.querySelector('#reg-image').addEventListener('submit', (event: Event) => {
        event.preventDefault();
        const form = formData((event.target as Field));
        submit(box, '/api/registry/image', {
          id: form.get('id').trim(), reference: form.get('reference').trim(),
          name: form.get('name').trim(), auth: form.get('auth'), replace: form.get('replace') === 'on'
        }, (r: ApiData) => `Image ro‘yxatga olindi: ${r.id}` + (r.pinned ? '' : ' (teg — digest har skanda yoziladi)'));
      });
      box.querySelector('#reg-web').addEventListener('submit', (event: Event) => {
        event.preventDefault();
        const form = formData((event.target as Field));
        const delay = parseFloat(form.get('rate_delay'));
        const budget = parseInt(form.get('daily_budget'), 10);
        const start = form.get('window_start'), end = form.get('window_end');
        const window = start && end ? {
          start, end, timezone: form.get('window_tz').trim() || 'UTC',
          ...(form.get('window_days').trim() ? {days: form.get('window_days').split(',').map(d => d.trim()).filter(Boolean)} : {})
        } : null;
        submit(box, '/api/registry/web', {
          id: form.get('id').trim(), url: form.get('url').trim(), owner: form.get('owner').trim(),
          authenticated: form.get('authenticated') === 'on', replace: form.get('replace') === 'on',
          ...(Number.isFinite(delay) ? {rate_delay: delay} : {}),
          ...(window ? {scan_window: window} : {}),
          ...(Number.isFinite(budget) ? {daily_request_budget: budget} : {})
        }, (r: ApiData) => `Nishon ro‘yxatga olindi: ${r.id} · ${r.url}`
             + (r.scan_window ? ` · oyna ${r.scan_window.days.join(',')} ${r.scan_window.start}–${r.scan_window.end} (${r.scan_window.timezone})` : '')
             + (r.daily_request_budget ? ` · kuniga ≤${r.daily_request_budget} so‘rov` : '')
             + (r.auth_variable ? ` — ${r.auth_variable} o‘zgaruvchisini o‘rnating` : ''));
      });
      box.querySelector('#reg-remove').addEventListener('submit', (event: Event) => {
        event.preventDefault();
        const form = formData((event.target as Field));
        const id = form.get('id').trim();
        if (!confirm(`“${id}” ro‘yxatdan chiqarilsinmi? Hisobotlar tarixda qoladi.`)) return;
        submit(box, '/api/registry/remove', {kind: form.get('kind'), id}, (r: ApiData) => `Ro‘yxatdan chiqarildi: ${r.id}. ${r.note}`);
      });
    }),

    settings: async () => {
      let status: ApiData, channels: ApiData, queue: ApiData;
      try { status = await api('/api/settings'); } catch (error) { status = {error: messageOf(error)}; }
      try { channels = await api('/api/settings/notifications'); } catch (error) { channels = {}; }
      try { queue = await api('/api/jobs'); } catch (error) { queue = {}; }
      let audit: ApiData = null;
      if (document.body.dataset.role === 'admin') { try { audit = await api('/api/audit?limit=100'); } catch (error) { audit = null; } }
      const auditRows = audit ? audit.entries.map((row: ApiData) => `<tr><td>${e(time(row.at))}</td><td>${e(row.user || '—')}</td><td>${e(row.action)}${row.path ? ' ' + e(row.path) : ''}</td><td>${e(row.status ?? '')}</td><td>${e(row.address || '')}</td><td><small>${e(row.details ? JSON.stringify(row.details) : '')}</small></td></tr>`).join('') : '';
      const mail = channels.email || {};
      const set = (item: ApiData) => item?.present ? `o‘rnatilgan ${e(item.masked || '')}` : 'o‘rnatilmagan';
      openModal('Sozlamalar', `
        <h3>NVD API kaliti</h3>
        <p class="hint-text">Holat: <strong>${status.nvd_api_key?.present ? 'o‘rnatilgan (' + e(status.nvd_api_key.source) + ')' : 'o‘rnatilmagan'}</strong>${status.nvd_api_key?.masked ? ' · ' + e(status.nvd_api_key.masked) : ''}</p>
        <form id="settings-nvd">
          <label>Yangi kalit<input name="key" type="password" autocomplete="off" placeholder="nvd.nist.gov/developers/request-an-api-key"></label>
          <div class="modal-actions"><button type="button" class="secondary" data-clear>Kalitni o‘chirish</button><button class="primary" data-submit>Saqlash</button></div>
          <p class="modal-feedback"></p>
        </form>
        <h3>Xabar kanallari</h3>
        <p class="hint-text">Jadvaldagi skan natijasi o‘zgarganda yuboriladi. Manzil va parol hech qachon qaytarilmaydi; bo‘sh qoldirilgan maydon saqlangan qiymatni o‘zgartirmaydi.</p>
        <form id="settings-notify">
          <label>Webhook (JSON POST) · ${set(channels.webhook)}<input name="webhook_url" type="password" autocomplete="off" placeholder="https://…"></label>
          <label>Slack incoming webhook · ${set(channels.slack)}<input name="slack_webhook_url" type="password" autocomplete="off" placeholder="https://hooks.slack.com/services/…"></label>
          <fieldset class="window-fields"><legend>Email (SMTP) · ${mail.present ? 'o‘rnatilgan' : 'o‘rnatilmagan'}</legend>
            <label>Server<input name="host" value="${e(mail.host || '')}" placeholder="smtp.example.com"></label>
            <label>Port<input name="port" type="number" min="1" max="65535" value="${e(mail.port || 587)}"></label>
            <label>Himoya<select name="security">${['starttls', 'ssl', 'none'].map(v => `<option${mail.security === v ? ' selected' : ''}>${v}</option>`).join('')}</select></label>
            <label>Login<input name="username" value="${e(mail.username || '')}" autocomplete="off"></label>
            <label>Parol${mail.password_from_env ? ' (THREATCHAIN_SMTP_PASSWORD ustun)' : mail.password_present ? ' (saqlangan)' : ''}<input name="password" type="password" autocomplete="off"></label>
            <label>Kimdan<input name="sender" value="${e(mail.sender || '')}" placeholder="threatchain@example.com"></label>
            <label>Kimga (vergul bilan)<input name="recipients" value="${e((mail.recipients || []).join(', '))}"></label>
          </fieldset>
          <div class="modal-actions"><button type="button" class="secondary" data-test>Sinov xabari</button><button type="button" class="secondary" data-clear-notify>Hammasini o‘chirish</button><button class="primary" data-submit>Saqlash</button></div>
          <p class="modal-feedback"></p>
        </form>
        <form id="settings-deep">
          <div class="deep-head"><h3>Chuqur tahlil (CodeQL)</h3>
            <label class="deep-toggle"><input type="checkbox" name="codeql"${status.deep_analysis?.codeql ? ' checked' : ''} aria-label="Kod skanida CodeQL bosqichini qo‘shish"></label></div>
          <p class="hint-text">Fayllararo ma’lumot oqimi (taint) tahlili: Python, JS/TS, Ruby, Java/Kotlin, C#. Sekin (daqiqalar) va alohida litsenziyali: ochiq kod va ilmiy ish uchun bepul, xususiy kod uchun GitHub Advanced Security kerak. ${status.deep_analysis?.installed ? 'O‘rnatilgan.' : 'O‘rnatilmagan: <code>python3 setup_codeql.py</code>.'}</p></form>
        <h3>Navbat</h3>
        <form id="settings-queue">
          <label>Bir vaqtda ishlaydigan skanlar (1–4; bir turdagi skan baribir bittadan)<input name="max" type="number" min="1" max="4" value="${e(queue.max_parallel || 1)}"></label>
          <div class="modal-actions"><button class="primary" data-submit>Saqlash</button></div>
          <p class="modal-feedback"></p>
        </form>
        ${audit ? `<h3>Audit jurnali (so‘nggi 100)</h3>
        <p class="hint-text">Foydalanuvchilar: ${audit.users.map((u: ApiData) => e(u.name) + ' (' + e(u.role) + ')').join(', ')}. Foydalanuvchilar faqat server konsolida boshqariladi: <code>python3 app.py --add-user ISM --role operator</code>.</p>
        <div class="audit-list table-wrap"><table><thead><tr><th>Vaqt</th><th>Kim</th><th>Amal</th><th>Kod</th><th>Manzil</th><th>ID’lar</th></tr></thead><tbody>${auditRows}</tbody></table></div>` : ''}
        <h3>Natijalarni tozalash</h3>
        <p class="hint-text">Barcha skan natijalarini — hisobotlar va qarorlarni — o‘chiradi. Ro‘yxatga olingan nishonlar, sozlamalar va o‘rnatilgan vositalar saqlanadi. Yangi tizimni tekshirishdan oldin eski natijalar aralashib ketmasligi uchun ishlating.</p>
        <div class="modal-actions"><button type="button" class="danger" id="settings-clear-results"><svg class="ic"><use href="#i-x"/></svg> Barcha natijalarni tozalash</button></div>
        <p class="modal-feedback" id="clear-feedback"></p>
        <h3>Muhit</h3>
        <table class="kv"><tbody>
          <tr><td>Versiya</td><td>${e(status.version || '—')}</td></tr>
          <tr><td>Python</td><td>${e(status.python || '—')}</td></tr>
          <tr><td>Bo‘sh disk</td><td>${e(status.free_disk_gb ?? '—')} GB</td></tr>
          <tr><td>Kod barmoq izi</td><td>${e(status.code_fingerprint || '—')}</td></tr>
        </tbody></table>
`, (box: Field) => {
        box.querySelector('#settings-clear-results').addEventListener('click', async () => {
          if (!confirm('Barcha skan natijalari (hisobotlar va qarorlar) o‘chiriladi. Nishonlar va sozlamalar saqlanadi. Davom etilsinmi?')) return;
          try {
            const result = await api('/api/reset/results', {confirm: true});
            box.querySelector('#clear-feedback').textContent = `Tozalandi: ${result.total} ta yozuv o‘chirildi. Dashboard yangilandi.`;
            document.dispatchEvent(new CustomEvent('view-shown', {detail: 'readiness'}));
          } catch (error) { showError(error); }
        });
        box.querySelector('#settings-nvd').addEventListener('submit', (event: Event) => {
          event.preventDefault();
          const value = formData((event.target as Field)).get('key').trim();
          if (!value) { feedback(box, 'Kalit bo‘sh.', false); return; }
          submit(box, '/api/settings/nvd-key', {key: value}, () => 'Saqlandi. Keyingi CVE tekshiruvida ishlatiladi.');
          (event.target as Field).reset();
        });
        box.querySelector('[data-clear]').addEventListener('click', () =>
          submit(box, '/api/settings/nvd-key', {key: ''}, () => 'Kalit o‘chirildi.'));
        const notifyForm = box.querySelector('#settings-notify');
        notifyForm.addEventListener('submit', (event: Event) => {
          event.preventDefault();
          const form = formData(notifyForm);
          const text = (name: string) => (form.get(name) || '').trim();
          const payload: ApiData = {};
          if (text('webhook_url')) payload.webhook_url = text('webhook_url');
          if (text('slack_webhook_url')) payload.slack_webhook_url = text('slack_webhook_url');
          if (text('host')) {
            payload.email = {host: text('host'), port: parseInt(text('port'), 10) || 587, security: form.get('security'),
                             username: text('username'), sender: text('sender'), recipients: text('recipients')};
            if (form.get('password')) payload.email.password = form.get('password');
          }
          submit(notifyForm, '/api/settings/notifications', payload, () => 'Saqlandi.');
          notifyForm.querySelectorAll('input[type=password]').forEach((input: ApiData) => { input.value = ''; });
        });
        notifyForm.querySelector('[data-test]').addEventListener('click', async () => {
          try {
            const result = await api('/api/notifications/test', {confirm: true});
            feedback(notifyForm, result.results.length
              ? result.results.map((r: ApiData) => `${r.channel}: ${r.ok ? 'yuborildi' : 'xato ' + r.error}`).join(' · ')
              : 'Kanal sozlanmagan.', result.results.every((r: ApiData) => r.ok));
          } catch (error) { feedback(notifyForm, messageOf(error), false); }
        });
        notifyForm.querySelector('[data-clear-notify]').addEventListener('click', () => {
          if (confirm('Barcha xabar kanallari o‘chirilsinmi?'))
            submit(notifyForm, '/api/settings/notifications', {webhook_url: '', slack_webhook_url: '', email: false}, () => 'O‘chirildi.');
        });
        const deepForm = box.querySelector('#settings-deep');
        // No save button: the toggle writes the setting the moment it changes.
        // A plain class carries the on/off look (heading, description and label),
        // set here rather than with :has() so it never lags a programmatic change.
        const syncDeep = () => deepForm.classList.toggle('on', deepForm.elements.codeql.checked);
        deepForm.addEventListener('submit', (event: Event) => event.preventDefault());
        deepForm.elements.codeql.addEventListener('change', () => {
          syncDeep();
          submit(deepForm, '/api/settings/deep-analysis', {codeql: deepForm.elements.codeql.checked},
                 (r: ApiData) => (r.codeql ? 'Yoqildi.' : 'O‘chirildi.') + (r.note ? ' ' + r.note : ''));
        });
        syncDeep();
        const queueForm = box.querySelector('#settings-queue');
        queueForm.addEventListener('submit', (event: Event) => {
          event.preventDefault();
          submit(queueForm, '/api/settings/queue', {max_parallel_scans: parseInt(formData(queueForm).get('max'), 10)},
                 (r: ApiData) => `Saqlandi: bir vaqtda ${r.max_parallel_scans} ta.`);
        });
      });
    },

    export: async () => {
      let projects: ApiData[];
      try { projects = (await api('/api/portfolio')).projects; } catch (error) { projects = []; }
      openModal('Eksport markazi', `
        <h3>Loyiha bo‘yicha</h3>
        <label>Loyiha<select id="export-project">${projects.map((p: ApiData) => `<option value="${e(p.id)}">${e(p.name)}</option>`).join('') || '<option value="">Loyiha yo‘q</option>'}</select></label>
        <p class="modal-feedback"></p>
        <div class="modal-actions"><button class="secondary" id="export-sbom">Loyiha SBOM (CycloneDX) ↓</button></div>
        <h3>Hisobot bo‘yicha</h3>
        <table class="kv"><tbody>
          <tr><td>Umumiy tekshiruv</td><td>SARIF · Markdown · JSON — “Umumiy tekshiruv” bo‘limidagi hisobot ustida</td></tr>
          <tr><td>Repository</td><td>SARIF · JSON</td></tr>
          <tr><td>Kod, CVE, IaC, Sayt</td><td>JSON · Markdown</td></tr>
          <tr><td>Docker image</td><td>JSON · CycloneDX SBOM</td></tr>
        </tbody></table>
`, (box: Field) => {
        box.querySelector('#export-sbom').addEventListener('click', () => {
          const project = box.querySelector('#export-project').value;
          if (!project) { feedback(box, 'Avval loyiha tanlang.', false); return; }
          window.location.href = '/api/images/sbom?project=' + encodeURIComponent(project);
        });
      });
    },

    /* The project wizard: group already-registered targets of every layer under
       one project id, so the assessment form can fill and run them in one click.
       It only groups -- registration stays in the "Nishon qo'shish" window, and
       nothing here invents a score. */
    projectWizard: async () => {
      let sources: ApiData[] = [], webs: ApiData[] = [], images: ApiData[] = [], repositories: ApiData[] = [], iacs: ApiData[] = [];
      try { [sources, webs, images, repositories, iacs] = await Promise.all([api('/api/scanners/targets'), api('/api/web/targets'), api('/api/images/targets'), api('/api/repository/profiles'), api('/api/iac/targets')]); }
      catch (error) { /* empty lists simply render as no options */ }
      const opts = (rows: ApiData[], avail = false) => '<option value="">— tanlanmagan —</option>' +
        (rows || []).filter((t: ApiData) => !avail || t.available).map((t: ApiData) => `<option value="${e(t.id)}">${e(t.name)}</option>`).join('');
      openModal('Loyiha ustasi — barcha qatlamni bitta loyihaga bog‘lash', `
        <form id="wizard-project">
          <label>Loyiha ID<input name="id" required maxlength="40" placeholder="masalan: mening-app"></label>
          <label>Nomi<input name="name" required maxlength="120" placeholder="Ko‘rinadigan nom"></label>
          <label>Mas’ul (ixtiyoriy)<input name="owner" maxlength="120" placeholder="Ism va lavozim"></label>
          <p class="hint-text">Har qatlam uchun ro‘yxatga olingan nishonni tanlang. Bo‘sh qatlam loyihaga bog‘lanmaydi (skanda o‘tkazib yuboriladi). Bu forma faqat guruhlaydi — skan qilmaydi va umumiy ball chiqarmaydi.</p>
          <label>Manba kodi <small>(Kod + CVE)</small><select name="code">${opts(sources, true)}</select></label>
          <label>Konfiguratsiya <small>(IaC)</small><select name="iac">${opts(iacs, true)}</select></label>
          <label>Repository <small>(Compose)</small><select name="repository">${opts(repositories)}</select></label>
          <label>Docker image <small>(bir nechta tanlash mumkin)</small><select name="images" multiple size="3">${(images || []).map((t: ApiData) => `<option value="${e(t.id)}">${e(t.name)}</option>`).join('')}</select></label>
          <button type="button" class="wiz-toggle" data-new="image">＋ Yangi image</button>
          <div class="wiz-new" data-newfor="image" hidden>
            <label>Image manzili<input name="image_reference" placeholder="registry/app:1.0 yoki nom@sha256:…"></label>
            <label>Registry autentifikatsiyasi<select name="image_auth"><option value="none">Kerak emas (ochiq registry)</option><option value="environment">Muhit o‘zgaruvchisidan</option><option value="docker-config">docker login seansidan</option></select></label>
          </div>
          <label>Sayt / API<select name="web">${opts(webs)}</select></label>
          <button type="button" class="wiz-toggle" data-new="web">＋ Yangi sayt / API</button>
          <div class="wiz-new" data-newfor="web" hidden>
            <label>URL<input name="web_url" placeholder="https://staging.example.test"></label>
            <label>Ruxsat bergan mas’ul<input name="web_owner" placeholder="Ism va lavozim"></label>
            <label class="wiz-check"><input name="web_authenticated" type="checkbox"> Nishon autentifikatsiya talab qiladi</label>
            <p class="hint-text">Faqat ruxsatli, ochiq (internetdagi) nishon. Lokal/intranet manzil brauzerdan ro‘yxatga olinmaydi — buning uchun CLI: <code>check_web.py --allow-private</code>.</p>
          </div>
          <div class="modal-actions"><button type="button" class="secondary" id="wizard-register">＋ Boshqa nishon</button><button class="primary" data-submit>Loyihani yaratish</button></div>
          <p class="modal-feedback"></p>
        </form>
`, (box: Field) => {
        box.querySelector('#wizard-register').addEventListener('click', () => WINDOWS.register());
        const wizForm = box.querySelector('#wizard-project');
        // Per-layer "＋ Yangi" toggles reveal that layer's registration fields.
        const newMode: Record<string, boolean> = {image: false, web: false};
        box.querySelectorAll('.wiz-toggle').forEach((btn: ApiData) => btn.addEventListener('click', () => {
          const which = btn.dataset.new;
          newMode[which] = !newMode[which];
          (box.querySelector(`[data-newfor="${which}"]`) as Field).hidden = !newMode[which];
          btn.textContent = (newMode[which] ? '− ' : '＋ ') + (which === 'image' ? 'Yangi image' : 'Yangi sayt / API');
        }));
        wizForm.addEventListener('submit', async (event: Event) => {
          event.preventDefault();
          const button = wizForm.querySelector('[data-submit]');
          button.disabled = true;
          try {
            const form = formData(wizForm);
            const projId = form.get('id').trim();
            if (!projId || !form.get('name').trim()) { feedback(box, 'Loyiha ID va nomi kerak.', false); return; }
            const stages: ApiData = {};
            const code = form.get('code'); if (code) { stages.code = [code]; stages.dependencies = [code]; }
            const iac = form.get('iac'); if (iac) stages.iac = [iac];
            const repo = form.get('repository'); if (repo) stages.repository = [repo];
            // A "new" layer is registered first; its returned id then goes into the
            // grouping. Registration failures (a private URL, a taken id) surface
            // here and stop the wizard before any grouping is written.
            if (newMode.image) {
              const ref = form.get('image_reference').trim();
              if (!ref) { feedback(box, 'Yangi image manzilini kiriting.', false); return; }
              feedback(box, 'Image ro‘yxatga olinmoqda…', true);
              const r = await api('/api/registry/image', {id: projId + '-img', reference: ref, auth: form.get('image_auth') || 'none'});
              stages.images = [r.id];
            } else {
              const imgs = [...(wizForm.querySelector('[name="images"]') as Field).selectedOptions].map((o: ApiData) => o.value).filter(Boolean);
              if (imgs.length) stages.images = imgs;
            }
            if (newMode.web) {
              const url = form.get('web_url').trim(), owner = form.get('web_owner').trim();
              if (!url || !owner) { feedback(box, 'Yangi sayt uchun URL va mas’ul kerak.', false); return; }
              feedback(box, 'Sayt nishoni ro‘yxatga olinmoqda…', true);
              const r = await api('/api/registry/web', {id: projId + '-web', url, owner, authenticated: form.get('web_authenticated') === 'on'});
              stages.web = [r.id];
            } else {
              const web = form.get('web'); if (web) stages.web = [web];
            }
            if (!Object.keys(stages).length) { feedback(box, 'Kamida bitta qatlam uchun nishon tanlang yoki qo‘shing.', false); return; }
            const created = await api('/api/portfolio/register', {id: projId, name: form.get('name').trim(), owner: form.get('owner').trim(), stages});
            feedback(box, `Loyiha yaratildi: ${created.name}. Umumiy tekshiruv formasi to‘ldirildi.`, true);
            document.dispatchEvent(new CustomEvent('assessment-project', {detail: created.id}));
            document.dispatchEvent(new CustomEvent('registry-changed'));
            setTimeout(closeModal, 900);
          } catch (error) { feedback(box, messageOf(error), false); }
          finally { button.disabled = false; }
        });
      });
    },

  };

  document.querySelectorAll('[data-modal]').forEach(button =>
    button.addEventListener('click', () => WINDOWS[button.dataset.modal ?? '']?.()));
  $('assessment-new-project')?.addEventListener('click', () => WINDOWS.projectWizard());

  /* ---- keyboard -------------------------------------------------------- */
  const GOTO: Record<string, string> = {t: 'findings', l: 'portfolio', u: 'assessments', b: 'readiness', p: 'project'};
  let pendingGoto = false;
  document.addEventListener('keydown', event => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test((event.target as Field).tagName) || (event.target as Field).isContentEditable;
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
  let typingTimer: ApiData = null;
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
  const STAGE_TITLE: Record<string, string> = {code: 'Kod', dependencies: 'CVE', iac: 'IaC', images: 'Image', web: 'Sayt', repository: 'Repository'};
  const STATE_TITLE: Record<string, string> = {completed: 'tugadi', partial: 'qisman', failed: 'yiqildi', running: 'ishlamoqda', queued: 'navbatda',
                       cancelled: 'bekor qilindi', no_supported_packages: 'manifest yo‘q'};
  // Fed by the overview's own /api/dashboard answer (dashboard-data) instead of a
  // second identical request; other views refresh it at most every 20 seconds.
  const HISTORY_TTL = 20000;
  let historyAt = 0;
  function renderHistory(rows: ApiData[]) {
    historyAt = Date.now();
    const box = $('history');
    if (!box) return;
    box.innerHTML = rows.length ? rows.map((r: ApiData) => `<button type="button" data-history-stage="${e(r.stage)}">
        <b>${e(STAGE_TITLE[r.stage] || r.stage)}</b> · ${e(r.target)} · ${e(STATE_TITLE[r.state] || r.state || '—')}${r.count == null ? '' : ' · ' + e(r.count)}
        <time>${e(time(r.created_at))}</time></button>`).join('')
      : '<p>Hali tekshiruv yo‘q.</p>';
  }
  async function loadHistory(event: CustomEvent<string>) {
    if (event?.detail === 'readiness' || Date.now() - historyAt < HISTORY_TTL) return;
    try { renderHistory((await api('/api/dashboard')).recent || []); }
    catch (error) { if ($('history')) $('history').innerHTML = '<p>Ro‘yxat yuklanmadi.</p>'; }
  }
  document.addEventListener('dashboard-data', event => renderHistory((event as CustomEvent).detail.recent || []));
  $('history')?.addEventListener('click', event => {
    const button = (event.target as Field).closest('[data-history-stage]');
    const stage = button?.dataset.historyStage ?? '';
    if (STAGE_TITLE[stage]) view(stage);
  });
  document.addEventListener('view-shown', loadHistory);
})();
