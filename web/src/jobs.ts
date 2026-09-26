'use strict';
// Scan queue and schedules (zanjir/jobs.py). The list refreshes itself every
// 5 s while the view is open and the tab is visible -- never in the background.
(() => {
  const e = escapeHTML;
  const KINDS: Record<string, string> = {code: 'Kod va sirlar', dependencies: 'Kutubxona (CVE)', images: 'Docker image', iac: 'IaC', web: 'Sayt va API'};
  const STAGE: Record<string, string> = {code: 'code', dependencies: 'dependencies', images: 'images', iac: 'iac', web: 'web'};
  const STATES: Record<string, string[]> = {
    queued: ['', 'Navbatda'], waiting: ['amber', 'Ruxsat oynasini kutmoqda'], running: ['', 'Ishlayapti'],
    completed: ['green', 'Tugadi'], partial: ['amber', 'Qisman'], failed: ['red', 'Bajarilmadi'],
    cancelled: ['', 'Bekor qilindi'], interrupted: ['red', 'Server to‘xtaganda uzildi'],
    no_supported_packages: ['amber', 'Manifest yo‘q'],
  };
  const NOTIFY: Record<string, string> = {on_change: 'natija o‘zgarsa', always: 'har safar', never: 'xabar yo‘q'};
  let targets: Record<string, ApiData> = {};
  let timer: ApiData = null;

  const badge = (state: ApiData) => {
    const [cls, label] = STATES[state] || ['', state];
    return `<span class="badge ${cls}">${e(label)}</span>`;
  };
  const when = (value: string) => value ? e(time(value)) : '—';

  function fillTargets(kindSelect: ApiData, targetSelect: ApiData) {
    const list = targets[STAGE[kindSelect.value]] || [];
    targetSelect.innerHTML = list.length ? list.map((id: string) => `<option>${e(id)}</option>`).join('')
      : '<option value="">Ro‘yxatda nishon yo‘q</option>';
  }

  function renderJobs(data: ApiData) {
    const rows = data.jobs.map((job: ApiData) => {
      const change = job.change ? (job.change.first ? 'birinchi skan'
        : `+${job.change.counts.new} / −${job.change.counts.gone}${job.change.changed ? '' : ' (o‘zgarmadi)'}`) : '';
      const sent = (job.notifications || []).map((n: ApiData) => `${e(n.channel)}: ${n.ok ? '✓' : '✗ ' + e(n.error || '')}`).join(', ');
      const cancel = ['queued', 'waiting', 'running'].includes(job.state)
        ? `<button class="ghost small" data-cancel="${e(job.id)}">Bekor qilish</button>` : '';
      return `<tr><td>${badge(job.state)}</td><td>${e(KINDS[job.kind] || job.kind)}</td><td>${e(job.target || '—')}</td>
        <td>${job.source === 'schedule' ? 'jadval · ' + e(job.schedule_id) : 'qo‘lda'}</td>
        <td>${when(job.created_at)}</td><td>${job.not_before && job.state !== 'running' ? when(job.not_before) : '—'}</td>
        <td><small>${e(job.message || '')}</small>${change ? `<br><small>${e(change)}</small>` : ''}${sent ? `<br><small>${sent}</small>` : ''}</td>
        <td>${e(job.report_id || '')}</td><td>${cancel}</td></tr>`;
    }).join('');
    $('jobs-list').innerHTML = rows ? `<div class="table-wrap"><table><thead><tr><th>Holat</th><th>Tur</th><th>Nishon</th><th>Manba</th>
      <th>Qo‘shilgan</th><th>Eng erta</th><th>Izoh</th><th>Hisobot</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`
      : '<p class="muted">Navbat bo‘sh.</p>';
    $('jobs-note').textContent = `${data.note} Bir vaqtda: ${data.max_parallel} ta skan.` +
      (data.worker_running ? '' : ' Diqqat: navbat ishchisi ishlamayapti (server app.py orqali ishga tushirilganmi?).');
    const schedules = data.schedules.map((row: ApiData) => `<tr><td>${e(row.id)}</td><td>${e(KINDS[row.kind] || row.kind)}</td>
      <td>${e(row.target || '—')}</td><td>${e(row.days.join(', '))} · ${e(row.at)} (${e(row.timezone)})</td>
      <td>${e(NOTIFY[row.notify] || row.notify)}</td><td>${row.enabled ? when(row.next_run) : 'o‘chirilgan'}</td>
      <td><button class="ghost small" data-remove-schedule="${e(row.id)}">O‘chirish</button></td></tr>`).join('');
    $('schedule-list').innerHTML = schedules ? `<div class="table-wrap"><table><thead><tr><th>ID</th><th>Tur</th><th>Nishon</th>
      <th>Vaqt</th><th>Xabar</th><th>Keyingi ishga tushish</th><th></th></tr></thead><tbody>${schedules}</tbody></table></div>`
      : '<p class="muted">Jadval yo‘q.</p>';
  }

  async function load() {
    renderJobs(await api('/api/jobs'));
  }

  function schedule() {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      if (!$('jobs-view').hidden && !document.hidden) { try { await load(); } catch (error) { /* next tick */ } }
      if (!$('jobs-view').hidden) schedule();
    }, 5000);
  }

  async function start() {
    const data = await api('/api/portfolio/targets');
    targets = Object.fromEntries(data.stages.map((stage: ApiData) => [stage.key, stage.targets]));
    for (const [kind, target] of [['job-kind', 'job-target'], ['schedule-kind', 'schedule-target']]) {
      $(kind).innerHTML = Object.entries<ApiData>(KINDS).map(([key, label]) => `<option value="${key}">${e(label)}</option>`).join('');
      $(kind).addEventListener('change', () => fillTargets($(kind), $(target)));
      fillTargets($(kind), $(target));
    }
    await load();
    schedule();
  }

  document.addEventListener('DOMContentLoaded', () => {
    whenShown(['jobs'], () => start().catch(showError));
    document.addEventListener('view-shown', event => { if ((event as CustomEvent).detail === 'jobs' && Object.keys(targets).length) { load().catch(showError); schedule(); } });
    $('jobs-refresh').addEventListener('click', () => load().catch(showError));
    $('job-form').addEventListener('submit', async event => {
      event.preventDefault();
      try {
        const job = await api('/api/jobs', {kind: $('job-kind').value, target: $('job-target').value, notify: $('job-notify').value});
        $('job-feedback').textContent = job.duplicate ? 'Bu skan allaqachon navbatda.' : 'Navbatga qo‘shildi.';
        await load();
      } catch (error) { $('job-feedback').textContent = messageOf(error); }
    });
    $('schedule-form').addEventListener('submit', async event => {
      event.preventDefault();
      const form = formData((event.target as Field));
      try {
        const row = await api('/api/schedules', {
          id: form.get('id').trim(), kind: form.get('kind'), target: form.get('target'),
          days: form.get('days').trim() || 'mon-sun', at: form.get('at'),
          timezone: form.get('timezone').trim() || 'UTC', notify: form.get('notify'),
        });
        $('schedule-feedback').textContent = `Saqlandi. Keyingi ishga tushish: ${row.next_run ? time(row.next_run) : '—'}`;
        await load();
      } catch (error) { $('schedule-feedback').textContent = messageOf(error); }
    });
    $('jobs-view').addEventListener('click', async event => {
      const cancel = (event.target as Field).closest('[data-cancel]');
      const remove = (event.target as Field).closest('[data-remove-schedule]');
      try {
        if (cancel) { await api('/api/jobs/cancel', {id: cancel.dataset.cancel}); await load(); }
        if (remove && confirm(`“${remove.dataset.removeSchedule}” jadvali o‘chirilsinmi?`)) {
          await api('/api/schedules/remove', {id: remove.dataset.removeSchedule}); await load();
        }
      } catch (error) { showError(error); }
    });
  });
})();
