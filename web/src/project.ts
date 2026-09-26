'use strict';
/* One project on one screen: which layers were scanned, which were never
   touched, what is open, what is overdue, and the chains that span them.

   The portfolio table answers "which of my projects has a gap". This answers
   "what is the state of this one", which is the question you have once you
   picked a project out of that table. Neither ever adds the layers together. */
(() => {
  const e = escapeHTML;
  const STAGE_NAMES: Record<string, string> = {code: 'Kod va sirlar', repository: 'Repository (Compose)', dependencies: 'CVE va kutubxonalar',
                       iac: 'Konfiguratsiya (IaC)', images: 'Docker image', web: 'Sayt va API'};
  const STATE_TEXT: Record<string, string> = {completed: 'Tugagan', partial: 'Qisman qamrov', failed: 'Tugallanmagan',
                      never_scanned: 'Hech qachon tekshirilmagan', not_registered: 'Ro‘yxatga olinmagan',
                      cancelled: 'Bekor qilingan'};
  let projects: ApiData[] = [];

  function stateClass(state: ApiData) {
    if (state === 'never_scanned' || state === 'not_registered') return 'state-never';
    if (state === 'partial' || state === 'failed') return 'state-partial';
    return 'state-clean';
  }

  function matrix(project: ApiData) {
    const rows = Object.entries<ApiData>(project.stages).map(([stage, info]) => `<tr>
      <td>${e(STAGE_NAMES[stage] || stage)}</td>
      <td class="${stateClass(info.state)}">${e(STATE_TEXT[info.state] || info.state)}</td>
      <td>${info.count === null ? '—' : e(info.count)}</td>
      <td>${info.last_scan ? e(time(info.last_scan)) : '—'}</td>
      <td><span class="cell-sub">${e((info.targets || []).join(', ') || 'Nishon bog‘lanmagan')}</span></td>
    </tr>`).join('');
    return `<div class="table-wrap"><table class="stage-matrix"><thead><tr><th>Qatlam</th><th>Holat</th><th>Kuzatuv</th><th>Oxirgi skan</th><th>Nishonlar</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function sparkline(points: ApiData) {
    if (!points.length) return '<p class="cell-sub">Trend uchun kamida bitta skan kerak.</p>';
    const top = Math.max(...points.map((p: ApiData) => p.count || 0), 1);
    const bars = points.map((point: ApiData) => {
      const step = Math.max(1, Math.round((point.count || 0) / top * 10));
      return `<span class="h-${step} ${point.state === 'partial' ? 'bar-partial' : ''}" title="${e(time(point.created_at))} · ${e(point.count)} · ${e(STATE_TEXT[point.state] || point.state)}"></span>`;
    }).join('');
    return `<div class="spark">${bars}</div><p class="cell-sub">Eski → yangi. Pasayish tuzatish degani emas.</p>`;
  }

  async function render(id: string) {
    const project = projects.find(p => p.id === id);
    if (!project) { $('project-result').innerHTML = '<p class="empty">Loyiha topilmadi.</p>'; return; }
    $('project-result').className = '';
    const gaps = project.gaps || [];
    let findings: ApiData = {total: 0, facets: {severity: {}, status: {}}, rows: []};
    let triage: ApiData, trend: ApiData[] = [];
    try { findings = await api('/api/findings?limit=5&project=' + encodeURIComponent(id)); } catch (error) { /* shown as zero below */ }
    try { triage = await api('/api/triage/' + encodeURIComponent(id)); } catch (error) { triage = null; }
    const firstScanned = Object.entries<ApiData>(project.stages).find(([, info]) => info.scanned);
    if (firstScanned) {
      try { trend = (await api(`/api/portfolio/trend?project=${encodeURIComponent(id)}&stage=${firstScanned[0]}&limit=20`)).points || []; }
      catch (error) { trend = []; }
    }
    const severity: ApiData = findings.facets.severity || {};
    const open = (findings.rows || []).length;
    $('project-result').innerHTML = `
      <div class="scanner-cards">
        <article class="scanner-card"><h3>Topilmalar</h3><strong>${e(findings.total)}</strong><p>Qo‘shilmagan</p></article>
        <article class="scanner-card"><h3>Kritik / yuqori</h3><strong>${e(severity.CRITICAL || 0)} / ${e(severity.HIGH || 0)}</strong></article>
        <article class="scanner-card"><h3>Muddati o‘tgan</h3><strong>${e(triage?.overdue ?? '—')}</strong><p>SLA: ${e(Object.entries<ApiData>(triage?.sla_days || {}).map(([k, v]) => k + ' ' + v + 'k').join(' · ') || '—')}</p></article>
        <article class="scanner-card"><h3>Tekshirilmagan qatlam</h3><strong class="${gaps.length ? 'state-never' : 'state-clean'}">${e(gaps.length)}</strong><p>${e(gaps.map((g: ApiData) => STAGE_NAMES[g] || g).join(', ') || 'Hammasi tekshirilgan')}</p></article>
      </div>
      ${gaps.length ? `<div class="coverage-note"><p><strong>Tekshirilmagan qatlam toza emas:</strong> ${e(gaps.map((g: ApiData) => STAGE_NAMES[g] || g).join(', '))}</p></div>` : ''}
      <h3 class="section-heading">Qatlamlar matritsasi</h3>
      ${matrix(project)}
      <h3 class="section-heading">Trend — ${e(STAGE_NAMES[firstScanned?.[0] ?? ''] || '—')}</h3>
      ${sparkline(trend)}
      <h3 class="section-heading">Eng og‘ir ochiq topilmalar</h3>
      ${open ? findings.rows.map((row: ApiData) => `<p><span class="sev sev-${e(row.severity_scale || 'UNRATED')}">${e(row.severity_scale || 'INFO')}</span> <strong>${e(row.title || row.rule_id)}</strong><span class="cell-sub">${e(row.subject)} · ${e(row.target)}</span></p>`).join('') : '<p class="cell-sub">Ko‘rsatiladigan topilma yo‘q.</p>'}
      <p><button class="secondary" id="project-open-findings">Bu loyihaning barcha topilmalari →</button></p>
      <p class="baseline-note">${e(project.unknown_targets?.length ? 'Diqqat: ' + project.unknown_targets.join(', ') + ' nishonlari hech bir ro‘yxatda topilmadi.' : '')}</p>`;
    $('project-open-findings').addEventListener('click', () => {
      location.hash = '#/findings?project=' + encodeURIComponent(id);
      view('findings');
      document.dispatchEvent(new CustomEvent('view-shown', {detail: 'findings'}));
    });
  }

  document.addEventListener('view-shown', async event => {
    if ((event as CustomEvent).detail !== 'project') return;
    try {
      projects = (await api('/api/portfolio')).projects;
      const picker = $('project-picker');
      if (!picker.options.length) {
        picker.innerHTML = projects.map((p: ApiData) => `<option value="${e(p.id)}">${e(p.name)}</option>`).join('');
        picker.addEventListener('change', () => render(picker.value));
      }
      if (projects.length) await render(picker.value || projects[0].id);
      else $('project-result').innerHTML = '<p class="empty">Hali loyiha yo‘q. “Nishon qo‘shish” oynasidan boshlang.</p>';
    } catch (error) { showError(error); }
  });
})();
