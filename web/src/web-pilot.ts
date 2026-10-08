'use strict';
(() => {
  const e = escapeHTML;
  const jobs: Record<string, string | null> = {web:null, assessment:null};
  const prefixes: Record<string, string> = {web:'/api/web', assessment:'/api/assessments'};
  const names: Record<string, string> = {code:'Semgrep + Gitleaks', repository:'Repository (Compose)', dependencies:'OSV + CISA KEV', web:'Nuclei + HTTP', images:'Trivy', iac:'Trivy config (IaC)'};
  const labels: Record<string, string> = {completed:'Tugagan', partial:'Qisman — qamrovni tekshiring', failed:'Tugallanmagan', cancelled:'Bekor qilingan', running:'Tekshirilmoqda', queued:'Navbatda', not_selected:'Tanlanmagan', no_supported_packages:'Qo‘llanadigan paket topilmadi', interrupted:'Boshqa jarayon yoki uzilgan skan'};
  const link = (prefix: string, id: string, sarif: ApiData) => `<a href="${prefix}/reports/${encodeURIComponent(id)}/download">JSON hisobot ↓</a> · <a href="${prefix}/reports/${encodeURIComponent(id)}/markdown">O‘qiladigan hisobot ↓</a>${sarif?` · <a href="${prefix}/reports/${encodeURIComponent(id)}/sarif">SARIF (CI/CD) ↓</a>`:''}`;
  const owaspBadges = (tags: ApiData) => (tags||[]).map((o: ApiData)=>`<span class="badge neutral" title="${e(o.name)}">${e(o.code)}</span>`).join(' ');
  const verifiedBadge = (f: ApiData) => f.verified?'<span class="badge green">Dalil bilan tasdiqlangan</span>':'<span class="badge amber">Qo‘lda tekshirish kerak</span>';
  const CONFIRM: Record<string, string[]> = {confirmed: ['green', 'Ikkinchi GET bilan tasdiqlandi'], not_reproduced: ['amber', 'Ikkinchi GET’da takrorlanmadi'],
                   inconclusive: ['', 'Qayta tekshirib bo‘lmadi'], dismissed: ['', 'Rad etildi']};
  const confirmBadge = (f: ApiData) => f.confirmation ? `<span class="badge ${CONFIRM[f.confirmation.state]?.[0] || ''}" title="${e(f.confirmation.method)}">${e(CONFIRM[f.confirmation.state]?.[1] || f.confirmation.state)}</span>` : '';
  let webTargets: ApiData[] = [];

  function render(kind: string, r: ApiData) {
    if (kind === 'web') syncTarget('web-target', r.target);
    else if (r.selection) {
      syncTarget('assessment-target', r.selection.target); syncTarget('assessment-repository', r.selection.repository_target);
      syncTarget('assessment-web', r.selection.web_target); syncTarget('assessment-image', r.selection.image_target);
      syncTarget('assessment-iac', r.selection.iac_target);
    }
    const target = $(kind+'-result'); target.className = '';
    const start = `<div class="scanner-summary"><strong>${e(labels[r.state]||r.state)}</strong><span>${e(time(r.created_at))}</span><span>${link(prefixes[kind],r.id,kind==='assessment')}</span></div><p id="${kind}-baseline" class="muted"></p>`;
    if(kind === 'assessment') {
      const v=r.verification_summary;
      const chainFindings=r.chain_findings||[];
      target.innerHTML = start + (v?`<p class="baseline-note">Tasdiqlash: ${e(v.confirmed_by_evidence)} dalil bilan tasdiqlangan / ${e(v.manual_review_required)} qo‘lda tekshirish (jami ${e(v.total)}).</p>`:'') + `<div class="scanner-cards">${r.stages.map((s: ApiData)=>`<article class="scanner-card"><h3>${e(names[s.kind])}</h3><p>${e(s.target||'Tanlanmagan')}</p><strong>${e(labels[s.state]||s.state)}</strong>${s.count!==undefined?`<p>${e(s.count)} kuzatuv / moslik</p>`:''}${s.report_id?`<a href="/api/${s.kind==='code'?'scanners':s.kind}/reports/${encodeURIComponent(s.report_id)}/download">Bosqich dalili ↓</a>`:''}<p>${e(s.message||'')}</p>${s.report?.tools?Object.entries<ApiData>(s.report.tools).map(([name,t])=>`<p>${e(name)}: ${e(labels[t.state]||t.state)}${t.message?' · '+e(t.message):''}</p>`).join(''):''}</article>`).join('')}</div><p class="cell-sub">Tanlanmagan bosqich tekshirilmagan.</p>${chainSection(chainFindings, r.chain_gaps||[])}`;
    } else {
      target.innerHTML = start + `<p>${e(r.url)} · ${e(r.requests??0)} so‘rov · ${e(r.count)} kuzatuv</p><p>${e(r.message||'')}</p><details class="pilot-help"><summary>Qamrov va bajarilgan yo‘llar</summary><p>Nuclei: ${e(r.tool?.version||'Bajarilishi tasdiqlanmagan')} · ${e(r.tool?.templates??0)} qoida</p><p>Bir manbadagi bosib chiqilgan sahifalar: ${e((r.crawled_pages||[]).length)} (${e((r.crawled_pages||[]).join(', ')||'—')})</p><p>Redirect: ${e(r.coverage?.redirects??0)} · kirish cheklangan: ${e(r.coverage?.restricted_responses??0)} · javob chegaralangan: ${e(r.coverage?.truncated_responses??0)}</p><p>Tekshirilmagan yo‘llar: ${e((r.coverage?.unvisited_paths||[]).join(', ')||'Yo‘q / jarayon hali tugamagan')}</p>${(r.evidence||[]).map((row: ApiData)=>`<p><code>${e(row.path)}</code> · HTTP ${e(row.status)} · ${e(row.bytes_read)} bayt${row.truncated?' · cheklangan javob':''}</p>`).join('')}</details>${(r.findings||[]).map((f: ApiData)=>`<details class="repo-finding"><summary><span class="badge ${f.severity==='HIGH'?'red':f.severity==='MEDIUM'?'amber':'neutral'}">${e(f.severity)}</span><strong>${e(f.title)}</strong><span>${e(f.path)}</span></summary><div class="finding-body"><p>${e(f.tool)} ${verifiedBadge(f)} ${confirmBadge(f)}</p><p>${e((f.cwe_ids||[]).join(', ')||'CWE aniqlanmagan')} ${owaspBadges(f.owasp_top10_2025)}</p><p>${e(typeof f.evidence==='string'?f.evidence:('HTTP '+f.evidence.status+' · '+f.evidence.bytes_read+' bayt'))}</p><p>${e(f.remediation)}</p><p class="muted">${e(f.verification_note||'')}</p>${f.evidence?.body_sha256?`<p class="hash">Javob xeshi: ${e(f.evidence.body_sha256)}</p>`:''}</div></details>`).join('')||'<p class="empty">Topilma yo‘q. Yakuniy holat va qamrovni tekshiring.</p>'}${(r.dismissed_findings||[]).length?`<details class="pilot-help"><summary>Ikkinchi tekshiruvda rad etilgan kuzatuvlar (${e(r.dismissed_findings.length)})</summary>${r.dismissed_findings.map((f: ApiData)=>`<p><strong>${e(f.title)}</strong> — ${e(f.confirmation.method)}</p>`).join('')}</details>`:''}`;
    }
    // Both views render `start`, so one call covers the assessment and the web
    // scan. A running report has nothing final to compare yet.
    if(!['queued','running'].includes(r.state))fillBaseline(kind==='assessment'?'assessment':'web',r.id,kind+'-baseline');
  }
  // Which two scanners each chain rule joins. Shown on every finding because
  // "this came from two independent scans" is the whole point of an SX rule --
  // without it the reader cannot tell a chain from an ordinary finding.
  const chainSources: Record<string, string> = {'SX-001':'Kod (Gitleaks) + Repository (Compose)',
                        'SX-002':'Repository (Compose) + Docker image (Trivy)',
                        'SX-003':'Repository (RP-006) + Docker image (Trivy)',
                        'SX-004':'Kod (Semgrep/CodeQL/PMD) + Repository (Compose)',
                        'SX-005':'Repository (Compose) + Docker image (Trivy · EOL)',
                        'SX-006':'CVE (OSV/KEV) + Repository (Compose)',
                        'SX-007':'Kod (sir/zaiflik) + Repository (RP-007/008)'};
  function chainEvidence(f: ApiData) {
    const v = f.evidence || {};
    const rows = [['Compose xizmati', v.compose_service], ['Host portlari', v.host_ports],
                  ['Image', v.image_target], ['Image digest', v.image_reference],
                  ['Paket', v.package && `${v.package} ${v.installed_version||''}`], ['CVE', v.advisory_id],
                  ['Og‘irlik', v.severity], ['CISA KEV', v.known_exploited===true?`Ha · ${v.kev_added_on||''}`:v.known_exploited===false?'Yo‘q':'Tekshirilmagan'],
                  ['EPSS', v.epss!==undefined&&v.epss!==null?`${(v.epss*100).toFixed(1)}% (persentil ${v.epss_percentile})`:null],
                  ['Tuzatilgan versiya', v.fixed_version], ['Bog‘lanish usuli', v.link],
                  ['Sir fayli', v.gitleaks_path && `${v.gitleaks_path}:${v.gitleaks_line??''}`],
                  ['Gitleaks qoidasi', v.gitleaks_rule_id], ['Build konteksti', v.build_context]];
    const shown = rows.filter(([,value]) => value !== undefined && value !== null && value !== '');
    return shown.length ? `<div class="table-wrap"><table><tbody>${shown.map(([label,value])=>`<tr><td>${e(label)}</td><td>${e(value)}</td></tr>`).join('')}</tbody></table></div>` : '';
  }
  function chainSection(items: ApiData[], gaps: ApiData) {
    if (!items.length && !gaps.length) return '';
    // Gaps are shown even when there are no findings: "not checked" and
    // "nothing found" must never look the same.
    const gapList = gaps.length ? `<div class="pilot-help"><h3>Tekshirilmagan qismlar</h3><ul class="muted">${gaps.map((g: ApiData)=>`<li>${e(g.detail)}</li>`).join('')}</ul></div>` : '';
    if (!items.length) return `<div class="section-heading"><h2>Cross-skaner zanjirlari</h2></div><p class="muted">Zanjir topilmadi — xavfsizlik xulosasi emas.</p>${gapList}`;
    return `<div class="section-heading"><h2>Cross-skaner zanjirlari — ${e(items.length)} ta</h2></div><p class="muted">Ikki mustaqil skaner natijasi birlashtirildi; hech biri amalda tasdiqlanmagan.</p>${items.map((f: ApiData)=>`<details class="repo-finding"><summary><span class="badge ${f.level==='error'?'red':'amber'}">${e(f.rule_id)}</span><strong>${e(f.title)}</strong><span>${e(f.service_id)}</span></summary><div class="finding-body"><p class="muted">Manba: ${e(chainSources[f.rule_id]||'Ikki bosqich')}</p><p>${e(f.detail)}</p><p>${e((f.cwe_ids||[]).join(', '))} ${owaspBadges(f.owasp_top10_2025)} ${verifiedBadge(f)}</p>${chainEvidence(f)}<p class="muted">${e(f.verification_note||'')}</p><p class="remediation"><strong>Tavsiya:</strong> ${e(f.remediation)}</p></div></details>`).join('')}${gapList}`;
  }
  async function history(kind: string) {
    const rows = await api(prefixes[kind]+'/reports');
    $(kind+'-history').innerHTML = rows.map((r: ApiData)=>`<button class="secondary scanner-history" data-report="${e(r.id)}">${e(time(r.created_at))} · ${e(r.target||r.selection?.target||r.selection?.web_target||r.selection?.image_target||'Tekshiruv')} · ${e(labels[r.state]||r.state)}</button>`).join('') || '<p>Hali tekshiruv yo‘q.</p>';
    $(kind+'-history').querySelectorAll('[data-report]').forEach(b=>b.addEventListener('click',async()=>{if(jobs[kind])return;try{render(kind,await api(prefixes[kind]+'/reports/'+b.dataset.report));}catch(error){showError(error);}}));
    return rows;
  }
  async function follow(kind: string,id: string) {
    jobs[kind]=id; $(kind+'-scan').disabled=true; $(kind+'-cancel').hidden=false;
    try {
      const r=await pollReport(prefixes[kind]+'/reports/'+id,(s: ApiData)=>{$(kind+'-progress').textContent=s.progress||labels[s.state]||s.state;});
      if(r.active_here===false) {r.state='interrupted';r.progress='Oldingi server yoki boshqa terminaldagi jarayon. Uning holatini tekshiring.';}
      $(kind+'-progress').textContent=r.progress||labels[r.state]||r.state;
      render(kind,r);
      await history(kind);
    } finally {jobs[kind]=null;$(kind+'-scan').disabled=false;$(kind+'-cancel').hidden=true;}
  }
  $('open-assessment').addEventListener('click',()=>view('assessments'));
  for(const kind of ['web','assessment']) {
    $(kind+'-scan').addEventListener('click',async()=>{
      try {
        $('error').hidden=true;
        const payload=kind==='web'?{target:$('web-target').value,online:true}:{target:$('assessment-target').value,web_target:$('assessment-web').value,image_target:$('assessment-image').value,repository_target:$('assessment-repository').value,iac_target:$('assessment-iac').value,online:true};
        const r=await api(prefixes[kind]+'/scan',payload);await follow(kind,r.id);
      } catch(error) {showError(error);}
    });
    $(kind+'-cancel').addEventListener('click',async()=>{try{const r=await api(prefixes[kind]+'/cancel',{report_id:jobs[kind]});$(kind+'-progress').textContent=r.message||'Bekor qilish so‘raldi.';}catch(error){showError(error);}});
  }
  function scope(){const t=webTargets.find(t=>t.id===$('web-target').value);$('web-scope').textContent=t?`${t.url} · mas’ul: ${t.owner}`:'';}
  $('web-target').addEventListener('change',scope);
  // The assessment form's targets and its "project quick-fill", loaded once and
  // reloaded whenever a project is created, so a new grouping appears at once.
  const optionRows=(rows: ApiData[])=>rows.map((t: ApiData)=>`<option value="${e(t.id)}">${e(t.name)}</option>`).join('');
  const NONE='<option value="">Tanlanmagan</option>';
  const STAGE_TO_SELECT: Record<string, string>={code:'assessment-target',repository:'assessment-repository',images:'assessment-image',iac:'assessment-iac',web:'assessment-web'};
  let assessmentProjects: ApiData[]=[], quickFillBound=false;
  function applyProject(pid: string){
    const proj=assessmentProjects.find((p: ApiData)=>p.id===pid);
    if(!proj)return;
    // A project's target for a stage goes into that stage's dropdown; a stage the
    // project never registered is left empty (it is skipped, not silently clean).
    for(const [stage,sel] of Object.entries(STAGE_TO_SELECT)){
      const wanted=((proj.stages?.[stage]?.targets)||[])[0]||'';
      const box=$(sel);
      box.value=[...box.options].some((o: ApiData)=>o.value===wanted)?wanted:'';
    }
  }
  async function loadAssessmentTargets(){
    const [sources,webs,images,repositories,iacs,portfolio]=await Promise.all([api('/api/scanners/targets'),api('/api/web/targets'),api('/api/images/targets'),api('/api/repository/profiles'),api('/api/iac/targets'),api('/api/portfolio')]);
    webTargets=webs;$('web-target').innerHTML=optionRows(webs);scope();
    const codeValue=$('assessment-target').value;
    $('assessment-target').innerHTML=NONE+optionRows(sources.filter((s: ApiData)=>s.available));
    $('assessment-target').value=codeValue||'crapi-full';
    $('assessment-web').innerHTML=NONE+optionRows(webs);$('assessment-image').innerHTML=NONE+optionRows(images);
    $('assessment-repository').innerHTML=NONE+optionRows(repositories);
    $('assessment-iac').innerHTML=NONE+optionRows((iacs||[]).filter((t: ApiData)=>t.available));
    assessmentProjects=(portfolio&&portfolio.projects)||[];
    const chosen=$('assessment-project').value;
    $('assessment-project').innerHTML='<option value="">— qatlamlarni qo‘lda tanlash —</option>'+optionRows(assessmentProjects);
    if([...$('assessment-project').options].some((o: ApiData)=>o.value===chosen))$('assessment-project').value=chosen;
    if(!quickFillBound){quickFillBound=true;$('assessment-project').addEventListener('change',()=>applyProject($('assessment-project').value));}
  }
  // Fired by the project wizard (shell.js) after a grouping is created: reload the
  // lists, select the new project, fill its layers and show the assessment.
  document.addEventListener('assessment-project',async(event: ApiData)=>{
    try{
      await loadAssessmentTargets();
      const pid=(event as CustomEvent).detail;
      const sel=$('assessment-project');
      if([...sel.options].some((o: ApiData)=>o.value===pid)){sel.value=pid;applyProject(pid);}
      view('assessments');
    }catch(error){showError(error);}
  });
  async function init() {
    try {
      await loadAssessmentTargets();
      const control=await api('/api/web/control-evidence');
      const controlNames: Record<string, string>={vulnerable:'Zaif sun’iy misol',fixed:'Tuzatilgan sun’iy misol',soft404:'Har bir yo‘lga bir xil javob','full-range':'Bo‘lak so‘ralganda to‘liq kelgan javob'};
      $('web-control').innerHTML=`<p>${control.passed?'Nazorat sinovi o‘tgan.':'Nazorat sinovi tasdiqlanmagan.'} Bu real kompaniya skani emas.</p>${(control.results||[]).map((r: ApiData)=>`<p>${e(controlNames[r.mode]||r.mode)}: ${e(r.nuclei_matches)} Nuclei mosligi · ${e(r.requests)} so‘rov · ${e(labels[r.state]||r.state)}</p>`).join('')}<p>Fallback javobdagi sezgir mazmun alohida tekshiriladi; bir xil javob ma’lumot sizib chiqishini inkor qilmaydi.</p>`;
      for(const kind of ['web','assessment']) {const rows=await history(kind);if(rows.length){if(['queued','running'].includes(rows[0].state))follow(kind,rows[0].id).catch(showError);else render(kind,await api(prefixes[kind]+'/reports/'+rows[0].id));}}
    } catch(error) {showError(error);}
  }
  whenShown(['web', 'assessments'], init);
})();
