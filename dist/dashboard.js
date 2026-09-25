'use strict';
/* The overview screen: system state and scan results as charts.

   Drawn as inline SVG with CSS classes for colour and attributes for geometry.
   That keeps it inside `style-src 'self'` -- a chart library would have needed
   either a build step or an inline style, and neither is allowed here, and it
   is also why the stacked bars are <rect> elements: a div stack would need an
   inline width per segment.

   Two rules from the rest of the project are visible in what is drawn:
   severity, stage and status are separate tallies and are never summed into
   one number, and the coverage gaps are drawn beside the totals so an
   unscanned project cannot read as a clean one. */
(() => {
  const e = escapeHTML;
  const SEV = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNRATED'];
  const SEV_LABEL = {CRITICAL: 'Kritik', HIGH: 'Yuqori', MEDIUM: 'O‘rta', LOW: 'Past', UNRATED: 'Info'};
  const STATUS = {untriaged: 'Ko‘rilmagan', investigating: 'Tekshirilmoqda', confirmed: 'Tasdiqlangan',
                  fix_planned: 'Tuzatish rejada', false_positive: 'Noto‘g‘ri signal',
                  accepted_risk: 'Xavf qabul qilingan', fixed: 'Tuzatilgan'};
  const OWASP = {A01: 'A01 · Kirish nazorati', A02: 'A02 · Noto‘g‘ri sozlash', A03: 'A03 · Ta’minot zanjiri',
                 A04: 'A04 · Kriptografiya', A05: 'A05 · Injection', A06: 'A06 · Xavfli dizayn',
                 A07: 'A07 · Autentifikatsiya', A08: 'A08 · Yaxlitlik', A09: 'A09 · Jurnal va monitoring',
                 A10: 'A10 · Istisno holatlar'};
  const STAGE = {code: ['Kod', 'i-code'], repository: ['Repository', 'i-server'], dependencies: ['CVE', 'i-package'],
                 iac: ['IaC', 'i-sliders'], images: ['Image', 'i-box'], web: ['Sayt', 'i-globe'],
                 chain: ['Zanjir', 'i-link']};
  const STATE_ICON = {completed: 'i-check', partial: 'i-alert', failed: 'i-x', cancelled: 'i-x',
                      never_scanned: 'i-alert', not_registered: 'i-x', no_supported_packages: 'i-check'};

  const icon = (name, cls) => `<svg class="ic ${cls || ''}"><use href="#${name}"/></svg>`;

  function tile(value, label, glyph, tone, goto, gotoLabel) {
    return `<article class="tile">
      <div class="tile-top"><span class="tile-badge ${tone}">${icon(glyph)}</span>
        <span class="tile-num"><b>${e(value)}</b><small>${e(label)}</small></span></div>
      ${goto ? `<button class="tile-foot" data-goto="${e(goto)}">${e(gotoLabel)} ${icon('i-chevron')}</button>`
             : `<p class="tile-foot tile-foot-flat">${e(gotoLabel)}</p>`}
    </article>`;
  }

  /* The severity legend, shared by both charts. */
  function legend(counts) {
    return `<ul class="sev-legend">${SEV.map(key =>
      `<li><span class="dot sev-dot-${key}"></span>${e(SEV_LABEL[key])} <b>${counts[key] || 0}</b></li>`).join('')}</ul>`;
  }

  /* A pie needs no library: one circle per slice, its dash offset by the
     slices before it, with the stroke wide enough to close the middle. */
  function pie(counts) {
    const total = SEV.reduce((sum, key) => sum + (counts[key] || 0), 0);
    if (!total) return `<p class="cell-sub">Topilma yo‘q.</p>`;
    const R = 35, C = 2 * Math.PI * R;
    let offset = 0;
    const slices = SEV.map(key => {
      const value = counts[key] || 0;
      if (!value) return '';
      const length = C * value / total;
      const slice = `<circle class="slice sev-ring-${key}" cx="70" cy="70" r="${R}"
        stroke-dasharray="${length.toFixed(3)} ${(C - length).toFixed(3)}"
        stroke-dashoffset="${(-offset).toFixed(3)}"><title>${e(SEV_LABEL[key])}: ${value}</title></circle>`;
      offset += length;
      return slice;
    }).join('');
    return `<div class="pie-wrap"><svg viewBox="0 0 140 140" class="pie" role="img"
      aria-label="Og‘irlik bo‘yicha taqsimot">${slices}</svg></div>`;
  }

  /* Severity split per scanner. The five numbers sit side by side in one row;
     the row is not a score, only the same five tallies drawn together. */
  function stacks(rows) {
    if (!rows.length) return `<p class="cell-sub">Ma’lumot yo‘q.</p>`;
    // Each row is its own 100%: with 8484 image findings next to 2 IaC ones a
    // shared scale would flatten every small scanner into an invisible line.
    // The absolute count stays on the right of the row.
    return `<ul class="stacks">${rows.map(r => {
      const span = 100;
      let x = 0;
      const segs = SEV.map(key => {
        const value = r.counts[key] || 0;
        if (!value) return '';
        const width = span * value / r.total;
        const rect = `<rect class="seg-${key}" x="${x.toFixed(3)}" y="0" width="${width.toFixed(3)}" height="10">
          <title>${e(STAGE[r.stage] ? STAGE[r.stage][0] : r.stage)} · ${e(SEV_LABEL[key])}: ${value}</title></rect>`;
        x += width;
        return rect;
      }).join('');
      return `<li><span class="bar-label">${icon((STAGE[r.stage] || ['', 'i-list'])[1])}${e(STAGE[r.stage] ? STAGE[r.stage][0] : r.stage)}</span>
        <svg class="stack" viewBox="0 0 100 10" preserveAspectRatio="none">${segs}</svg>
        <b>${r.total}</b></li>`;
    }).join('')}</ul>`;
  }

  function bars(entries, iconOf, wide) {
    const rows = entries.filter(([, value]) => value > 0);
    if (!rows.length) return `<p class="cell-sub">Ma’lumot yo‘q.</p>`;
    const top = Math.max(...rows.map(([, value]) => value));
    return `<ul class="bars ${wide ? 'named' : ''}">${rows.map(([key, value, label]) => `<li>
      <span class="bar-label">${iconOf ? icon(iconOf(key)) : ''}${e(label || key)}</span>
      <span class="bar-track"><span class="bar-fill w-${Math.max(2, Math.round(value / top * 100))}"></span></span>
      <b>${value}</b></li>`).join('')}</ul>`;
  }

  function tools(list) {
    return `<ul class="chips-row">${list.map(t =>
      `<li class="chip-static ${t.installed ? 'ok' : 'bad'}">${icon(t.installed ? 'i-check' : 'i-x')}${e(t.name)}</li>`).join('')}</ul>`;
  }

  function matrix(projects) {
    const stages = Object.keys(STAGE).filter(s => s !== 'chain');
    return `<div class="table-wrap"><table class="stage-matrix">
      <thead><tr><th>Loyiha</th>${stages.map(s => `<th title="${e(STAGE[s][0])}">${icon(STAGE[s][1])}</th>`).join('')}</tr></thead>
      <tbody>${projects.map(p => `<tr><td>${e(p.name)}</td>${stages.map(s => {
        const state = p.stages[s];
        const good = state === 'completed' || state === 'no_supported_packages';
        const bad = state === 'never_scanned' || state === 'not_registered';
        return `<td class="${good ? 'state-clean' : bad ? 'state-never' : 'state-partial'}"
          title="${e(STAGE[s][0])}: ${e(state)}">${icon(STATE_ICON[state] || 'i-alert')}</td>`;
      }).join('')}</tr>`).join('')}</tbody></table></div>`;
  }

  /* The newest "Umumiy tekshiruv": one row per stage, each keeping its own
     state. A stage that was not selected says so; it is never a zero. */
  function assessment(run) {
    if (!run) return `<p class="cell-sub">Hali umumiy tekshiruv o‘tkazilmagan.</p>`;
    const STATE = {completed: ['Tugadi', 'state-clean'], partial: ['Qisman', 'state-partial'],
                   failed: ['Xato', 'state-never'], cancelled: ['Bekor', 'state-never'],
                   not_selected: ['Tanlanmagan', 'cell-sub'], no_supported_packages: ['Paket yo‘q', 'state-clean']};
    return `<p class="card-sub">${e(time(run.created_at))} · ${e((STATE[run.state] || [run.state])[0])}
      ${run.chain_findings ? ' · ' + e(run.chain_findings) + ' ta zanjir' : ''}</p>
      <ul class="feed">${run.stages.map(stage => {
        const mark = STATE[stage.state] || [stage.state, 'cell-sub'];
        return `<li>${icon((STAGE[stage.kind] || ['', 'i-list'])[1])}
          <span><b>${e(STAGE[stage.kind] ? STAGE[stage.kind][0] : stage.kind)}</b>${stage.target ? ' · ' + e(stage.target) : ''}
          <span class="cell-sub ${mark[1]}">${e(mark[0])}</span></span>
          <span class="feed-count">${stage.count ?? '—'}</span></li>`;
      }).join('')}</ul>`;
  }

  function recent(rows) {
    if (!rows.length) return `<p class="cell-sub">Hali skan yo‘q.</p>`;
    return `<ul class="feed">${rows.slice(0, 8).map(r => `<li>
      ${icon(STAGE[r.stage] ? STAGE[r.stage][1] : 'i-list')}
      <span><b>${e(STAGE[r.stage] ? STAGE[r.stage][0] : r.stage)}</b> · ${e(r.target)}
      <span class="cell-sub">${e(time(r.created_at))}</span></span>
      <span class="feed-count ${r.state === 'completed' ? '' : 'state-partial'}">${r.count ?? '—'}</span></li>`).join('')}</ul>`;
  }

  async function load() {
    try {
      const d = await api('/api/dashboard');
      document.dispatchEvent(new CustomEvent('dashboard-data', {detail: d}));
      const s = d.system, t = d.totals, c = d.coverage, st = t.status || {};
      const gaps = c.unscanned + c.incomplete;
      const decided = t.findings - (st.untriaged || 0);
      $('dash').innerHTML = `
      <div class="tile-row">
        ${tile(t.findings, 'Jami topilma', 'i-shield', 'tone-teal', 'findings', 'Ro‘yxatni ochish')}
        ${tile(t.severity.CRITICAL, 'Kritik topilma', 'i-alert', 'tone-red', 'findings', 'Topilmalar')}
        ${tile(t.severity.HIGH, 'Yuqori topilma', 'i-flag', 'tone-orange', 'findings', 'Topilmalar')}
        ${tile(t.overdue, 'SLA muddati o‘tgan', 'i-clock', 'tone-red', 'findings', 'Topilmalar')}
      </div>
      <div class="tile-row">
        ${tile(st.untriaged || 0, 'Ko‘rilmagan', 'i-list', 'tone-yellow', 'findings', 'Topilmalar')}
        ${tile(decided, 'Qaror qabul qilingan', 'i-check', 'tone-green', 'findings', 'Topilmalar')}
        ${tile(st.false_positive || 0, 'Noto‘g‘ri signal', 'i-x', 'tone-gray', 'findings', 'Topilmalar')}
        ${tile(t.stages.chain || 0, 'Zanjir topilmasi', 'i-link', 'tone-blue', 'findings', 'Topilmalar')}
      </div>
      <div class="tile-row">
        ${tile(d.projects.length, 'Loyiha', 'i-grid', 'tone-teal', 'portfolio', 'Loyihalar')}
        ${tile(c.scanned, 'Tekshirilgan nishon', 'i-target', 'tone-green', 'portfolio', 'Qamrov')}
        ${tile(gaps, 'Tekshirilmagan qatlam', 'i-alert', 'tone-orange', 'portfolio', 'Qamrov')}
        ${tile(s.rules.semgrep + s.rules.chain + s.rules.cross_scanner + (s.rules.custom || 0),
               'Faol qoida', 'i-sliders', 'tone-blue', '', 'Semgrep · RP · SX')}
      </div>
      ${gaps ? `<p class="coverage-note">${icon('i-alert')} ${e(gaps)} ta nishon natija bermadi: ${e(c.unscanned_targets.map(x => x.stage + '/' + x.target).join(', ') || '—')}</p>` : ''}
      <div class="dash-grid wide">
        <section class="card"><h3>${icon('i-shield')} Og‘irlik bo‘yicha taqsimot</h3>
          ${legend(t.severity)}${pie(t.severity)}</section>
        <section class="card"><h3>${icon('i-list')} Skaner bo‘yicha og‘irlik</h3>
          <p class="card-sub">Har bir qator o‘z ichida 100% taqsimlangan; o‘ngdagi son — o‘sha skanerning umumiy topilmasi.</p>
          ${legend(t.severity)}${stacks(d.severity_by_stage || [])}</section>
      </div>
      <div class="dash-grid wide">
        <section class="card"><h3>${icon('i-play')} Oxirgi umumiy tekshiruv</h3>${assessment(d.last_assessment)}</section>
        <section class="card"><h3>${icon('i-grid')} Loyiha × qatlam qamrovi</h3>${matrix(d.projects)}</section>
      </div>
      <div class="dash-grid wide">
        <section class="card"><h3>${icon('i-clock')} Oxirgi skanlar</h3>${recent(d.recent)}</section>
        <section class="card"><h3>${icon('i-check')} Qaror holati</h3>
          ${bars(Object.entries(st).map(([k, v]) => [k, v, STATUS[k] || k]))}</section>
      </div>
      <div class="dash-grid wide">
        <section class="card"><h3>${icon('i-target')} OWASP Top 10:2025</h3>
          <p class="card-sub">Topilmalar CWE raqami orqali toifalanadi.</p>
          ${bars(Object.entries(t.owasp).filter(([k]) => k !== '—').sort((a, b) => a[0].localeCompare(b[0]))
            .map(([k, v]) => [k, v, OWASP[k] || k]), null, true)}</section>
      </div>
      <section class="card"><h3>${icon('i-gear')} Tizim</h3>
        ${tools(s.tools)}
        <ul class="chips-row">
          <li class="chip-static">v${e(s.version)}</li>
          <li class="chip-static">Python ${e(s.python)}</li>
          <li class="chip-static">${e(s.free_disk_gb)} GB</li>
          <li class="chip-static">${e(s.rules.semgrep)} qoida · ${e(s.rules.languages)} til</li>
          <li class="chip-static">RP ${e(s.rules.chain)} · SX ${e(s.rules.cross_scanner)}</li>
          <li class="chip-static ${s.nvd_key ? 'ok' : 'bad'}">${icon(s.nvd_key ? 'i-check' : 'i-x')} NVD</li>
        </ul>
        ${s.disk_warning ? `<p class="coverage-note">${icon('i-alert')} ${e(s.disk_warning)}</p>` : ''}
        <p class="cell-sub">${e(t.note)}</p>
      </section>`;
    } catch (error) { showError(error); }
  }

  /* The tiles are rebuilt on every load, so their links are handled here rather
     than bound once at start-up like the sidebar's. */
  $('dash').addEventListener('click', event => {
    const link = event.target.closest('[data-goto]');
    if (link) view(link.dataset.goto);
  });
  $('readiness-refresh').addEventListener('click', load);
  $('open-assessment').addEventListener('click', () => view('assessments'));
  document.addEventListener('view-shown', event => { if (event.detail === 'readiness') load(); });
})();
