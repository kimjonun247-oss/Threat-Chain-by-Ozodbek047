'use strict';
(() => {
  let running=false;
  const labels={queued:'Navbatda',running:'Tekshirilmoqda',completed:'Tekshiruv tugadi',partial:'Qisman bajarildi',failed:'Tekshiruv tugallanmadi'};
  const e=escapeHTML;
  const owaspBadges=tags=>(tags||[]).map(o=>`<span class="badge neutral" title="${e(o.name)}">${e(o.code)}</span>`).join(' ');
  const severityBadge=s=>s?`<span class="badge ${s==='ERROR'?'red':s==='WARNING'?'amber':'neutral'}">${e(s)}</span>`:'';
  // Rule authors' own severity; ERROR first so the few serious rows are not lost
  // among the many advisory ones. Findings without a severity keep their order last.
  const rank={ERROR:0,WARNING:1,INFO:2};
  const bySeverity=(a,b)=>(rank[a.severity]??3)-(rank[b.severity]??3);
  // The official rule pack took a crAPI scan from 6 findings to 144, so the
  // table is paged and filtered the same way the dependency table already is.
  const PER_PAGE=25;
  let current=null,page=0,filter='',severity='all';

  function rows(){
    if(!current)return [];
    const needle=filter.trim().toLowerCase();
    return (current.findings||[]).filter(f=>
      (severity==='all'||f.severity===severity||(severity==='NONE'&&!f.severity))&&
      (!needle||[f.rule_id,f.path,f.tool,f.message].some(v=>String(v||'').toLowerCase().includes(needle)))
    ).sort(bySeverity);
  }

  function results(){
    const matched=rows();
    const pages=Math.max(1,Math.ceil(matched.length/PER_PAGE));
    page=Math.min(page,pages-1);
    const body=$('code-findings');
    if(!body)return;
    body.innerHTML=matched.length?`<div class="scanner-table"><table><thead><tr><th>Vosita</th><th>Daraja</th><th>Fayl va satr</th><th>Kuzatuv</th><th>CWE / OWASP</th><th>Holat</th></tr></thead><tbody>${matched.slice(page*PER_PAGE,page*PER_PAGE+PER_PAGE).map(f=>`<tr><td>${e(f.tool)}</td><td>${severityBadge(f.severity)||'—'}</td><td>${e(f.path)}:${e(f.line)}</td><td><strong>${e(f.rule_id)}</strong><p>${e(f.message)}</p></td><td>${e((f.cwe_ids||[]).join(', ')||'—')} ${owaspBadges(f.owasp_top10_2025)}</td><td>Qo‘lda tekshirish kerak${f.secret_value?'<br>Qiymat yashirilgan':''}</td></tr>`).join('')}</tbody></table></div>`
      :'<p class="empty">Ushbu filtrga mos kuzatuv yo‘q.</p>';
    $('code-page').textContent=`${matched.length} ta kuzatuv · ${page+1}/${pages} sahifa`;
    $('code-prev').disabled=page===0;
    $('code-next').disabled=(page+1)*PER_PAGE>=matched.length;
  }

  function render(report){
    syncTarget('code-target',report.target);
    const tools=Object.entries(report.tools||{}).map(([name,item])=>{
      const pack=item.rule_pack?`<p class="muted">Qoida bazasi: ${e(item.rule_pack.source)} @ ${e(String(item.rule_pack.commit).slice(0,12))} · ${e(item.rule_pack.languages.length)} til</p>`:'';
      // A gap keeps the stage at `partial`, but it is spelled out with the files
      // and the remedy instead of only a number.
      const names={helm_template:'Helm shabloni',other:'Boshqa sintaksis'};
      const gaps=Object.entries(item.error_files||{}).map(([key,g])=>
        `<details class="gap-detail"><summary>${e(names[key]||key)}: ${e(g.count)} ta fayl tahlil qilinmadi</summary><p class="muted">${e(g.action)}</p><ul>${g.files.map(f=>`<li><code>${e(f)}</code></li>`).join('')}</ul></details>`).join('');
      const kinds=!gaps&&item.error_kinds&&Object.keys(item.error_kinds).length?`<p class="muted">Tahlil qilinmagan: ${e(Object.entries(item.error_kinds).map(([k,v])=>k+' — '+v).join('; '))}</p>`:'';
      return `<article class="scanner-card"><h3>${e({semgrep:'Semgrep',gitleaks:'Gitleaks',pmd:'PMD · Apex'}[name]||name)}</h3><strong>${e(labels[item.state]||item.state)}</strong><p>${e(item.count||0)} ta kuzatuv${item.version?' · v'+e(item.version):''}</p><p class="muted">${e(item.rule_set||item.message||'')}</p>${pack}${kinds}${gaps}</article>`;
    }).join('');
    const verification=report.verification_summary;
    const findings=report.findings||[];
    // A re-render of the same report keeps the reader's page and filter;
    // switching reports resets them, so page 7 of an old scan is never shown
    // against a new one.
    if(!current||current.id!==report.id)page=0;
    current=report;
    $('code-result').className='';
    $('code-result').innerHTML=`<div class="scanner-summary"><strong>${e(labels[report.state]||report.state)}</strong><span>${e(report.target)} · ${e(time(report.created_at))}</span><a href="/api/scanners/reports/${encodeURIComponent(report.id)}/download">JSON hisobot ↓</a></div><div class="scanner-cards">${tools}${verification?`<article class="scanner-card"><h3>Tasdiqlash</h3><strong>${e(verification.confirmed_by_evidence)} / ${e(verification.total)}</strong><p>Statik kuzatuv doim qo‘lda tekshirishni talab qiladi</p></article>`:''}</div>${report.message?'<p class="baseline-note">'+e(report.message)+'</p>':''}${report.coverage?`<p class="muted">${e(report.coverage.files)} ta fayl nusxasi · ${e(report.coverage.scope)}<br>O‘tkazib yuborilgan: ${e(JSON.stringify(report.coverage.skipped))}</p>`:''}<p id="code-baseline" class="muted"></p>${findings.length?`<div class="dep-filters"><label>Qidirish<input id="code-search" type="search" placeholder="Qoida, fayl yoki matn" value="${e(filter)}"></label><label>Daraja<select id="code-severity">${[['all','Barchasi'],['ERROR','ERROR'],['WARNING','WARNING'],['INFO','INFO'],['NONE','Darajasiz']].map(([v,t])=>`<option value="${v}" ${severity===v?'selected':''}>${e(t)}</option>`).join('')}</select></label></div><div id="code-findings"></div><div class="scanner-summary"><button id="code-prev" class="secondary">← Oldingi</button><span id="code-page"></span><button id="code-next" class="secondary">Keyingi →</button></div>`:`<p>${['queued','running'].includes(report.state)?'Natija kutilmoqda…':report.state==='completed'?'Ushbu qamrovda kuzatuv topilmadi.':'Natija yo‘qligi muvaffaqiyatli tekshiruv degani emas.'}</p>`}`;
    // Only a finished scan has something to compare; a running one would race.
    if(!['queued','running'].includes(report.state))fillBaseline('code',report.id,'code-baseline');
    if(findings.length){
      $('code-search').addEventListener('input',event=>{filter=event.target.value;page=0;results();});
      $('code-severity').addEventListener('change',event=>{severity=event.target.value;page=0;results();});
      $('code-prev').addEventListener('click',()=>{page--;results();});
      $('code-next').addEventListener('click',()=>{page++;results();});
      results();
    }
  }
  async function loadHistory(){
    const rows=await api('/api/scanners/reports');
    $('code-history').innerHTML=rows.map(row=>`<button class="secondary scanner-history" data-scan-id="${e(row.id)}">${e(time(row.created_at))} · ${e(row.target)} · ${e(labels[row.state]||row.state)} · ${e(row.count||0)}</button>`).join('')||'<p>Hali tekshiruv yo‘q.</p>';
    $('code-history').querySelectorAll('[data-scan-id]').forEach(button=>button.addEventListener('click',async()=>{try{render(await api('/api/scanners/reports/'+button.dataset.scanId));}catch(error){showError(error);}}));
    return rows;
  }
  async function follow(id){
    running=true;$('code-scan').disabled=true;$('code-target').disabled=true;
    try{
      while(true){
        const report=await api('/api/scanners/reports/'+id);render(report);
        $('code-progress').textContent=labels[report.state]||report.state;
        if(!['queued','running'].includes(report.state))break;
        await new Promise(resolve=>setTimeout(resolve,1500));
      }
      await loadHistory();
    }finally{running=false;$('code-scan').disabled=false;$('code-target').disabled=false;}
  }
  async function initCode(){
    $('code-scan').addEventListener('click',async()=>{
      if(running)return;
      try{const job=await api('/api/scanners/scan',{target:$('code-target').value});await follow(job.id);}catch(error){showError(error);}
    });
    try{
      const targets=await api('/api/scanners/targets');
      $('code-target').innerHTML=targets.map(t=>`<option value="${e(t.id)}" ${t.available?'':'disabled'}>${e(t.name)}${t.available?'':' · manba yo‘q'}</option>`).join('');
      const history=await loadHistory();
      if(history.length){if(['queued','running'].includes(history[0].state))follow(history[0].id).catch(showError);else render(await api('/api/scanners/reports/'+history[0].id));}
      else $('code-result').textContent='Loyihani tanlab birinchi tekshiruvni boshlang.';
      const pilot=await api('/api/scanners/pilot');
      const names={baseline_bad:'Tekshiruv o‘chiq: ishonchsiz sertifikat qabul qilindi',fixed_bad:'Tekshiruv yoqilgan: ishonchsiz sertifikat rad etildi',fixed_good:'Ishonchli sertifikat va to‘g‘ri nom bilan aloqa ishladi',fixed_wrong_name:'Noto‘g‘ri xizmat nomi rad etildi'};
      $('pilot-result').className='';
      $('pilot-result').innerHTML=`<h3>${pilot.state==='controlled_test_confirmed'?'Nazorat tajribasida tasdiqlandi':'Dalil mavjud emas yoki tekshirish kerak'}</h3>${pilot.finished_at?'<p>'+e(time(pilot.finished_at))+'</p>':''}<ul>${Object.entries(pilot.checks).map(([name,passed])=>`<li>${passed?'✓':'✕'} ${e(names[name]||name)}</li>`).join('')}</ul><p>${e(pilot.scope)}</p>`;
    }catch(error){showError(error);}
  }
  whenShown(['code'], initCode);
})();
