'use strict';
(() => {
  const e = escapeHTML;
  const labels = {completed:'Tugagan',partial:'Qisman qamrov',failed:'Tugallanmagan',cancelled:'Bekor qilingan',running:'Tekshirilmoqda',queued:'Navbatda',external_or_interrupted:'Boshqa jarayon yoki uzilgan skan'};
  const badge = severity => severity==='CRITICAL'?'red':severity==='HIGH'?'red':severity==='MEDIUM'?'amber':'neutral';
  let job = null, report = null, filter = '', severity = 'all';

  function rows() {
    const all = (report.findings||[]).filter(f =>
      (severity==='all'||f.severity===severity) &&
      JSON.stringify([f.rule_id,f.path,f.title,f.message]).toLowerCase().includes(filter));
    $('iac-findings').innerHTML = all.map(f=>`<details class="repo-finding"><summary><span class="badge ${badge(f.severity)}">${e(f.severity)}</span><strong>${e(f.rule_id)}</strong><span>${e(f.path)}${f.line?':'+e(f.line):''}</span></summary><div class="finding-body"><p><strong>${e(f.title)}</strong></p><p>${e(f.message)}</p><p>${e((f.cwe_ids||[]).join(', ')||'CWE xaritada yo‘q')} ${owaspBadges(f.owasp_top10_2025)} ${verifiedBadge(f)}</p><p class="muted">${e(f.check_type)} · ${e(f.provider)}${f.service?' / '+e(f.service):''}</p><p class="remediation"><strong>Tavsiya:</strong> ${e(f.remediation)}</p>${f.reference?`<p class="muted">${e(f.reference)}</p>`:''}</div></details>`).join('')
      || '<p class="empty">Topilma yo‘q — xavfsizlik xulosasi emas.</p>';
    $('iac-count').textContent = `${all.length} ta topilma ko‘rsatilmoqda (jami ${(report.findings||[]).length})`;
  }

  function render(row) {
    report = row;
    $('iac-result').className = '';
    const counts = row.severity_counts || {};
    const coverage = (row.coverage||[]).map(c=>`<p>${e(c.path)} · ${e(c.type)} · ${e(c.checks)} tekshiruv</p>`).join('') || '<p>Qamrov ma’lumoti yo‘q.</p>';
    $('iac-result').innerHTML = `<div class="scanner-summary"><strong>${e(labels[row.state]||row.state)}</strong><span>${e(row.target)} · ${e(time(row.created_at))}</span><a href="/api/iac/reports/${encodeURIComponent(row.id)}/download">JSON ↓</a><a href="/api/iac/reports/${encodeURIComponent(row.id)}/markdown">O‘qiladigan hisobot ↓</a></div>`
      + `<div class="scanner-cards"><article class="scanner-card"><h3>Topilmalar</h3><strong>${e(row.count||0)}</strong><p>${e(row.files||0)} ta fayl nusxasi</p></article>`
      + `<article class="scanner-card"><h3>Kritik / yuqori</h3><strong>${e(counts.CRITICAL||0)} / ${e(counts.HIGH||0)}</strong></article>`
      + `<article class="scanner-card"><h3>Trivy config</h3><strong>${e(row.tool?.version||'—')}</strong></article>`
      + `<article class="scanner-card"><h3>Tasdiqlash</h3><strong>${row.verification_summary?e(row.verification_summary.confirmed_by_evidence)+' / '+e(row.verification_summary.total):'—'}</strong><p>Qo‘lda tekshiriladi</p></article></div>`
      + `<p id="iac-baseline" class="muted"></p>`
      + (row.untagged_checks?.length?`<p class="muted gap-note">CWE xaritasida yo‘q tekshiruvlar: ${e(row.untagged_checks.join(', '))} — ${e(row.untagged_note||'')}</p>`:'')
      + `<details class="pilot-help"><summary>Qamrov</summary><p>${e(row.coverage_scope||'')}</p>${coverage}<p class="hash">Snapshot SHA-256: ${e(row.snapshot_sha256||'—')}</p></details>`
      + `<div class="dep-filters"><label>Qidirish<input id="iac-search" type="search" value="${e(filter)}" placeholder="Tekshiruv, fayl yoki matn"></label><label>Og‘irlik<select id="iac-severity">${['all','CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].map(s=>`<option value="${s}" ${severity===s?'selected':''}>${s==='all'?'Barchasi':s}</option>`).join('')}</select></label></div>`
      + `<p id="iac-count" class="muted"></p><div id="iac-findings"></div>`;
    if (!['queued','running'].includes(row.state)) fillBaseline('iac', row.id, 'iac-baseline');
    $('iac-search').addEventListener('input', event => { filter = event.target.value.toLowerCase(); rows(); });
    $('iac-severity').addEventListener('change', event => { severity = event.target.value; rows(); });
    rows();
  }

  async function history() {
    const listed = await api('/api/iac/reports');
    $('iac-history').innerHTML = listed.map(r=>`<button class="secondary scanner-history" data-iac-id="${e(r.id)}">${e(r.target)} · ${e(time(r.created_at))} · ${e(labels[r.state]||r.state)} · ${e(r.count)}</button>`).join('') || '<p>Hali tekshiruv yo‘q.</p>';
    $('iac-history').querySelectorAll('[data-iac-id]').forEach(b => b.addEventListener('click', async () => {
      if (job) return;
      try { render(await api('/api/iac/reports/' + b.dataset.iacId)); } catch (error) { showError(error); }
    }));
    return listed;
  }

  async function follow(id) {
    job = id; $('iac-scan').disabled = true; $('iac-target').disabled = true; $('iac-cancel').hidden = false;
    try {
      while (true) {
        const row = await api('/api/iac/reports/' + id);
        if (row.active_here === false) { row.state = 'external_or_interrupted'; row.progress = 'Bu job boshqa terminalda boshlangan; tugallanmagan natija.'; }
        $('iac-progress').textContent = row.progress || labels[row.state] || '';
        render(row);
        if (!['queued','running'].includes(row.state)) break;
        await new Promise(resolve => setTimeout(resolve, 1500));
      }
      await history();
    } finally { job = null; $('iac-scan').disabled = false; $('iac-target').disabled = false; $('iac-cancel').hidden = true; }
  }

  $('iac-scan').addEventListener('click', async () => {
    try { const row = await api('/api/iac/scan', {target: $('iac-target').value}); await follow(row.id); }
    catch (error) { showError(error); }
  });
  $('iac-cancel').addEventListener('click', async () => {
    try { await api('/api/iac/cancel', {report_id: job}); } catch (error) { showError(error); }
  });

  document.addEventListener('view-shown', async event => {
    if (event.detail !== 'iac' || $('iac-target').options.length) return;
    try {
      const targets = await api('/api/iac/targets');
      $('iac-target').innerHTML = targets.filter(t=>t.available).map(t=>`<option value="${e(t.id)}">${e(t.name)}</option>`).join('');
      const listed = await history();
      if (listed.length) {
        if (['queued','running'].includes(listed[0].state)) follow(listed[0].id).catch(showError);
        else render(await api('/api/iac/reports/' + listed[0].id));
      } else { $('iac-result').textContent = 'Hali konfiguratsiya tekshiruvi bajarilmagan.'; }
    } catch (error) { showError(error); }
  });
})();
