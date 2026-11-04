'use strict';
/* The decision form shown under a finding on the Compose and CVE pages.

   It writes to /api/triage, the store the findings board, the dashboard and the
   project page read. Each page used to post to a review file of its own that
   nothing else read, so a risk accepted on the Compose page still counted as
   "not reviewed" on the dashboard (UI review 2026-11-04, P0). */

/** The current decision of a report finding, as attached by the server. */
function decisionOf(finding: ApiData): ApiData {
  return finding.triage || {};
}

/** The short label for the finding's summary line. */
function decisionLabel(finding: ApiData): string {
  const view = decisionOf(finding);
  if (view.stale) return 'Qaror eski manba holatiga tegishli';
  return TRIAGE_STATUS[view.status || 'untriaged'];
}

function decisionForm(finding: ApiData): string {
  const e = escapeHTML;
  if (!finding.fingerprint) {
    return '<p class="muted">Bu hisobot identifikatorsiz eski formatda: qaror berish uchun qayta tekshiring.</p>';
  }
  const view = decisionOf(finding);
  const options = Object.entries(TRIAGE_STATUS).filter(([value]) => value !== 'untriaged')
    .map(([value, label]) => `<option value="${value}" ${view.status === value ? 'selected' : ''}>${e(label)}</option>`).join('');
  const saved = view.updated_at ? 'Saqlangan: ' + time(view.updated_at) : (view.stale_note || 'Qaror statik dalilni o‘zgartirmaydi.');
  return `<form class="review-form" data-decision="${e(finding.fingerprint)}">
    <label>Holat<select name="status" required><option value="" ${view.status ? '' : 'selected'} disabled>— tanlang —</option>${options}</select></label>
    <label>Mas’ul<input name="owner" required maxlength="120" placeholder="Jamoa yoki mas’ul" value="${e(view.owner || '')}"></label>
    <label class="review-note">Qaror asosi<textarea name="note" required maxlength="1000" rows="2" placeholder="Tekshiruv yoki qarorning sababini yozing">${e(view.note || '')}</textarea></label>
    <button class="secondary" type="submit">Qarorni saqlash</button>
    <p class="review-feedback" role="status">${e(saved)}</p>
  </form>`;
}

/** Wire every decision form under `root` to one report of one stage. */
function bindDecisionForms(root: Element, stage: string, reportId: string,
                           onSaved?: (fingerprint: string, status: string) => void): void {
  root.querySelectorAll('form[data-decision]').forEach(form => form.addEventListener('submit', async event => {
    event.preventDefault();
    const fields = formData(form);
    const button = form.querySelector('button');
    const line = form.querySelector('.review-feedback');
    button.disabled = true;
    try {
      const fingerprint = form.dataset.decision ?? '';
      const saved = await api('/api/triage', {stage, report_id: reportId, fingerprint,
                                              status: fields.get('status'), owner: fields.get('owner').trim(),
                                              note: fields.get('note').trim()});
      const record = (saved.decisions || {})[fingerprint] || {};
      line.textContent = 'Saqlandi' + (record.updated_at ? ' · ' + time(record.updated_at) : '') +
        '. Topilmalar va Bosh sahifada ham ko‘rinadi.';
      if (onSaved) onSaved(fingerprint, fields.get('status'));
    } catch (error) {
      line.textContent = messageOf(error);
    } finally {
      button.disabled = false;
    }
  }));
}
