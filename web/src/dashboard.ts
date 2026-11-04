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
  const SEV_LABEL = SEVERITY_LABEL;
  const STATUS = TRIAGE_STATUS;
  const OWASP: Record<string, string> = {A01: 'A01 · Kirish nazorati', A02: 'A02 · Noto‘g‘ri sozlash', A03: 'A03 · Ta’minot zanjiri',
                 A04: 'A04 · Kriptografiya', A05: 'A05 · Injection', A06: 'A06 · Xavfli dizayn',
                 A07: 'A07 · Autentifikatsiya', A08: 'A08 · Yaxlitlik', A09: 'A09 · Jurnal va monitoring',
                 A10: 'A10 · Istisno holatlar'};
  const STAGE: Record<string, string[]> = {code: [STAGE_SHORT.code, 'i-code'], repository: [STAGE_SHORT.repository, 'i-server'],
                 dependencies: [STAGE_SHORT.dependencies, 'i-package'], iac: [STAGE_SHORT.iac, 'i-sliders'],
                 images: [STAGE_SHORT.images, 'i-box'], web: [STAGE_SHORT.web, 'i-globe'], chain: [STAGE_SHORT.chain, 'i-link']};
  const STATE_ICON: Record<string, string> = {completed: 'i-check', partial: 'i-alert', failed: 'i-x', cancelled: 'i-x',
                      never_scanned: 'i-alert', not_registered: 'i-x', no_supported_packages: 'i-check'};

  const icon = (name: string, cls?: string) => `<svg class="ic ${cls || ''}"><use href="#${name}"/></svg>`;

  // A tile that opens the findings board opens it already filtered to what the
  // tile counts ("Kritik topilma" shows the critical ones, not all of them).
  function tile(value: string | number, label: string, glyph: ApiData, tone: ApiData, goto: ApiData, gotoLabel: ApiData,
                filter = '') {
    return `<article class="tile">
      <div class="tile-top"><span class="tile-badge ${tone}">${icon(glyph)}</span>
        <span class="tile-num"><b>${e(value)}</b><small>${e(label)}</small></span></div>
      ${goto ? `<button class="tile-foot" data-goto="${e(goto)}" data-filter="${e(filter)}">${e(gotoLabel)} ${icon('i-chevron')}</button>`
             : `<p class="tile-foot tile-foot-flat">${e(gotoLabel)}</p>`}
    </article>`;
  }

  /* The severity legend, shared by both charts. */
  function legend(counts: ApiData) {
    return `<ul class="sev-legend">${SEV.map(key =>
      `<li><span class="dot sev-dot-${key}"></span>${e(SEV_LABEL[key])} <b>${counts[key] || 0}</b></li>`).join('')}</ul>`;
  }

  /* Severity split per scanner. The five numbers sit side by side in one row;
     the row is not a score, only the same five tallies drawn together. */
  function stacks(rows: ApiData[]) {
    if (!rows.length) return `<p class="cell-sub">Ma’lumot yo‘q.</p>`;
    // Each row is its own 100%: with 8484 image findings next to 2 IaC ones a
    // shared scale would flatten every small scanner into an invisible line.
    // The absolute count stays on the right of the row.
    return `<ul class="stacks">${rows.map((r: ApiData) => {
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

  function bars(entries: ApiData, iconOf?: ApiData, wide?: ApiData) {
    const rows = entries.filter(([, value]: ApiData) => value > 0);
    if (!rows.length) return `<p class="cell-sub">Ma’lumot yo‘q.</p>`;
    const top = Math.max(...rows.map(([, value]: ApiData) => value));
    // The fill width is a `w-<n>` class and only multiples of five exist (with a
    // 2% floor for a still-visible sliver); an arbitrary percentage would name a
    // class the stylesheet has no rule for, and the fill would then default to
    // the full track width -- which made every bar look identical regardless of
    // its number. Snapping to the grid keeps the lengths in proportion.
    const width = (value: number) => {
      const pct = Math.round(value / top * 20) * 5;
      return pct < 2 ? 2 : pct;
    };
    return `<ul class="bars ${wide ? 'named' : ''}">${rows.map(([key, value, label]: ApiData) => `<li>
      <span class="bar-label">${iconOf ? icon(iconOf(key)) : ''}${e(label || key)}</span>
      <span class="bar-track"><span class="bar-fill w-${width(value)}"></span></span>
      <b>${value}</b></li>`).join('')}</ul>`;
  }

  function tools(list: ApiData[]) {
    return `<ul class="chips-row">${list.map((t: ApiData) =>
      `<li class="chip-static ${t.installed ? 'ok' : 'bad'}">${icon(t.installed ? 'i-check' : 'i-x')}${e(t.name)}</li>`).join('')}</ul>`;
  }

  function matrix(projects: ApiData) {
    const stages = Object.keys(STAGE).filter(s => s !== 'chain');
    return `<div class="table-wrap"><table class="stage-matrix">
      <thead><tr><th>Loyiha</th>${stages.map(s => `<th>${icon(STAGE[s][1])}<span class="matrix-label">${e(STAGE[s][0])}</span></th>`).join('')}</tr></thead>
      <tbody>${projects.map((p: ApiData) => `<tr><td>${e(p.name)}</td>${stages.map(s => {
        const state = p.stages[s];
        const good = state === 'completed' || state === 'no_supported_packages';
        const bad = state === 'never_scanned' || state === 'not_registered';
        return `<td class="${good ? 'state-clean' : bad ? 'state-never' : 'state-partial'}"
          title="${e(STAGE[s][0])}: ${e(RUN_STATE[state] || state)}">${icon(STATE_ICON[state] || 'i-alert')}<span class="sr-only">${e(RUN_STATE[state] || state)}</span></td>`;
      }).join('')}</tr>`).join('')}</tbody></table></div>`;
  }

  /* The newest "Umumiy tekshiruv": one row per stage, each keeping its own
     state. A stage that was not selected says so; it is never a zero. */
  function assessment(run: ApiData) {
    if (!run) return `<p class="cell-sub">Hali umumiy tekshiruv o‘tkazilmagan.</p>`;
    const STATE: Record<string, string[]> = {completed: ['Tugadi', 'state-clean'], partial: ['Qisman', 'state-partial'],
                   failed: ['Xato', 'state-never'], cancelled: ['Bekor', 'state-never'],
                   not_selected: ['Tanlanmagan', 'cell-sub'], no_supported_packages: ['Paket yo‘q', 'state-clean']};
    return `<p class="card-sub">${e(time(run.created_at))} · ${e((STATE[run.state] || [run.state])[0])}
      ${run.chain_findings ? ' · ' + e(run.chain_findings) + ' ta zanjir' : ''}</p>
      <ul class="feed">${run.stages.map((stage: ApiData) => {
        const mark = STATE[stage.state] || [stage.state, 'cell-sub'];
        return `<li>${icon((STAGE[stage.kind] || ['', 'i-list'])[1])}
          <span><b>${e(STAGE[stage.kind] ? STAGE[stage.kind][0] : stage.kind)}</b>${stage.target ? ' · ' + e(stage.target) : ''}
          <span class="cell-sub ${mark[1]}">${e(mark[0])}</span></span>
          <span class="feed-count">${stage.count ?? '—'}</span></li>`;
      }).join('')}</ul>`;
  }

  async function load(btn?: HTMLButtonElement) {
    // The refresh button re-fetches identical data when nothing changed, so
    // without a visible signal it looks dead. Spin and disable it while the
    // request is in flight, and stamp the time so a no-change refresh is still
    // visibly a refresh.
    if (btn) { btn.classList.add('spinning'); btn.disabled = true; }
    try {
      const d = await api('/api/dashboard');
      document.dispatchEvent(new CustomEvent('dashboard-data', {detail: d}));
      const s = d.system, t = d.totals, c = d.coverage, st = t.status || {};
      const gaps = c.unscanned + c.incomplete;
      const named = (x: ApiData) => (STAGE_SHORT[x.stage] || x.stage) + ' · ' + x.target;
      // Closed by a decision: the count the 'state=closed' filter shows.
      const closed = (st.false_positive || 0) + (st.accepted_risk || 0) + (st.fixed || 0);
      $('dash').innerHTML = `
      <p class="refresh-stamp">Yangilandi: ${e(new Date().toLocaleTimeString('uz-UZ', {hour: '2-digit', minute: '2-digit', hour12: false}))}</p>
      <div class="tile-row tile-hero">
        ${tile(`${t.severity.CRITICAL || 0} / ${t.severity.HIGH || 0}`, 'Kritik / yuqori topilma', 'i-alert', 'tone-red',
               'findings', 'Eng xavflilarini ko‘rish', (t.severity.CRITICAL ? 'severity=CRITICAL' : 'severity=HIGH') + '&state=open')}
        ${tile(t.overdue, 'Tuzatish muddati o‘tgan', 'i-clock', 'tone-red', 'findings', 'Muddati o‘tganlar', 'state=overdue')}
        ${tile(gaps, 'Natija bermagan nishon', 'i-alert', 'tone-orange', 'portfolio', 'Nima tekshirilmaganini ko‘rish')}
      </div>
      <div class="tile-row tile-minor">
        ${tile(t.findings, 'Jami topilma', 'i-shield', 'tone-teal', 'findings', 'Hammasi')}
        ${tile(st.untriaged || 0, 'Ko‘rilmagan', 'i-list', 'tone-yellow', 'findings', 'Ko‘rilmaganlar', 'status=untriaged')}
        ${tile(closed, 'Yopilgan', 'i-check', 'tone-green', 'findings', 'Yopilganlar', 'state=closed')}
        ${tile(t.stages.chain || 0, 'Zanjir topilmasi', 'i-link', 'tone-blue', 'findings', 'Zanjirlar', 'stage=chain')}
      </div>
      ${gaps ? `<p class="coverage-note">${icon('i-alert')} ${[
        c.unscanned ? `${e(c.unscanned)} ta nishon hech tekshirilmagan: ${e((c.unscanned_targets || []).map(named).join(', ') || '—')}` : '',
        c.incomplete ? `${e(c.incomplete)} ta tekshiruv natijasiz tugagan: ${e((c.incomplete_targets || []).map(named).join(', ') || '—')}` : '',
      ].filter(Boolean).join('. ')}. Bu “toza” degani emas.</p>` : ''}
      <div class="dash-grid wide">
        <section class="card"><h3>${icon('i-list')} Og‘irlik — skaner bo‘yicha</h3>
          <p class="card-sub">Har bir qator o‘z ichida 100% taqsimlangan; o‘ngdagi son — o‘sha skanerning topilmalari.</p>
          ${legend(t.severity)}${stacks(d.severity_by_stage || [])}</section>
      </div>
      <div class="dash-grid wide">
        <section class="card"><h3>${icon('i-play')} Oxirgi to‘liq tekshiruv</h3>${assessment(d.last_assessment)}</section>
        <section class="card"><h3>${icon('i-grid')} Loyiha × qatlam qamrovi</h3>${matrix(d.projects)}</section>
      </div>
      <div class="dash-grid wide">
        <section class="card"><h3>${icon('i-check')} Qaror holati</h3>
          ${bars(Object.entries<ApiData>(st).map(([k, v]) => [k, v, STATUS[k] || k]))}</section>
      </div>
      <div class="dash-grid wide">
        <section class="card"><h3>${icon('i-target')} OWASP Top 10:2025</h3>
          <p class="card-sub">Topilmalar CWE raqami orqali toifalanadi.</p>
          ${bars(Object.entries<ApiData>(t.owasp).filter(([k]) => k !== '—').sort((a, b) => a[0].localeCompare(b[0]))
            .map(([k, v]) => [k, v, OWASP[k] || k]), null, true)}</section>
      </div>
      <section class="card"><h3>${icon('i-gear')} Skanerlar</h3>
        ${tools(s.tools)}
        <ul class="chips-row">
          <li class="chip-static">Semgrep ${e(s.rules.semgrep)} qoida · ${e(s.rules.languages)} til</li>
          <li class="chip-static">Compose ${e(s.rules.chain)} · Zanjir ${e(s.rules.cross_scanner)} qoida</li>
          <li class="chip-static ${s.nvd_key ? 'ok' : 'bad'}">${icon(s.nvd_key ? 'i-check' : 'i-x')} NVD</li>
        </ul>
        ${s.disk_warning ? `<p class="coverage-note">${icon('i-alert')} ${e(s.disk_warning)}</p>` : ''}
        <p class="cell-sub">${e(t.note)}</p>
      </section>`;
    } catch (error) { showError(error); }
    finally { if (btn) { btn.classList.remove('spinning'); btn.disabled = false; } }
  }

  /* The tiles are rebuilt on every load, so their links are handled here rather
     than bound once at start-up like the sidebar's. */
  $('dash').addEventListener('click', event => {
    const link = (event.target as Field).closest('[data-goto]');
    if (!link) return;
    if (link.dataset.goto === 'findings') openFindings(Object.fromEntries(new URLSearchParams(link.dataset.filter || '')));
    else view(link.dataset.goto ?? '');
  });
  $('readiness-refresh').addEventListener('click', event => load(event.currentTarget as HTMLButtonElement));
  document.addEventListener('view-shown', event => { if ((event as CustomEvent).detail === 'readiness') load(); });
})();
