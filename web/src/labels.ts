'use strict';
/* One name for each thing the dashboard shows.

   The UI review of 2026-11-04 found one status under three names on three
   pages ("Noto‘g‘ri signal", "Noto‘g‘ri signal deb baholangan", ...), a failed
   scan under eight ("yiqildi", "Bajarilmadi", "Tugallanmagan", "Xato" ...) and
   four severity scales, because every page kept its own map. The maps more
   than one page needs live here; a page keeps a local map only for words no
   other page shows. The same words are used by the Markdown reports
   (zanjir/report_text.py). */

// A decision about a finding (zanjir/triage.py STATUSES), plus "no decision yet".
const TRIAGE_STATUS: Record<string, string> = {
  untriaged: 'Ko‘rilmagan', investigating: 'Tekshirilmoqda', confirmed: 'Tasdiqlangan',
  fix_planned: 'Tuzatish rejalashtirilgan', false_positive: 'Yolg‘on signal',
  accepted_risk: 'Xavf qabul qilingan', fixed: 'Tuzatilgan'};

// A layer, short (chips, table cells) and full (headings, selects).
const STAGE_SHORT: Record<string, string> = {
  code: 'Kod', repository: 'Compose', dependencies: 'CVE', iac: 'IaC', images: 'Image', web: 'Sayt', chain: 'Zanjir'};
const STAGE_LONG: Record<string, string> = {
  code: 'Kod va sirlar', repository: 'Compose va tarmoq', dependencies: 'Kutubxonalar (CVE)',
  iac: 'Konfiguratsiya (IaC)', images: 'Docker image', web: 'Sayt va API', chain: 'Skanerlararo zanjir'};

// The state of one scan (a report) or of one layer of a project.
const RUN_STATE: Record<string, string> = {
  queued: 'Navbatda', waiting: 'Ruxsat oynasini kutmoqda', running: 'Tekshirilmoqda', completed: 'Tugadi',
  partial: 'Qisman — qamrov to‘liq emas', failed: 'Xato bilan tugadi', cancelled: 'Bekor qilindi',
  interrupted: 'Server to‘xtaganda uzildi', external_or_interrupted: 'Boshqa oynada boshlangan yoki uzilgan',
  no_supported_packages: 'Versiyali paket fayli topilmadi', not_selected: 'Tanlanmagan',
  never_scanned: 'Hech tekshirilmagan', not_registered: 'Obyekt ulanmagan'};

// The one severity scale (zanjir/triage.py SEVERITY_SCALE). A finding no
// scanner rated is "Baholanmagan", never a quiet "Info".
const SEVERITY_LABEL: Record<string, string> = {
  CRITICAL: 'Kritik', HIGH: 'Yuqori', MEDIUM: 'O‘rta', LOW: 'Past', UNRATED: 'Baholanmagan'};
// A scanner's own words, mapped onto that scale for display.
const SEVERITY_OF: Record<string, string> = {
  CRITICAL: 'CRITICAL', HIGH: 'HIGH', ERROR: 'HIGH', MEDIUM: 'MEDIUM', WARNING: 'MEDIUM',
  LOW: 'LOW', INFO: 'LOW', NOTE: 'LOW', INFORMATIONAL: 'LOW'};
/** Severity in words, from any scanner's own label (or none). */
function severityLabel(raw: unknown): string {
  return SEVERITY_LABEL[SEVERITY_OF[String(raw || '').toUpperCase()] || 'UNRATED'];
}
/** Badge colour for a severity, the same on every page. */
function severityTone(raw: unknown): string {
  const scale = SEVERITY_OF[String(raw || '').toUpperCase()];
  return scale === 'CRITICAL' || scale === 'HIGH' ? 'red' : scale === 'MEDIUM' ? 'amber' : 'neutral';
}
/** A severity badge: the scale word, coloured; nothing for an unrated finding. */
function severityBadge(raw: unknown): string {
  return raw ? `<span class="badge ${severityTone(raw)}">${escapeHTML(severityLabel(raw))}</span>` : '';
}
/** Why a scan did not finish, in words, with the scanner's own message folded away.

   A failed code scan used to print "[Errno 2] No such file or directory: 'C:\…'"
   as the page text (English, a local path, one unbreakable line that widened
   a phone screen to 1069 px), and a failed CVE report showed no reason at all. */
function failureNote(report: ApiData): string {
  if (!report || !['failed', 'cancelled', 'partial', 'interrupted'].includes(report.state)) {
    return report?.message ? `<p class="baseline-note">${escapeHTML(report.message)}</p>` : '';
  }
  const lead = report.state === 'cancelled' ? 'Tekshiruv bekor qilindi.'
    : report.state === 'partial' ? 'Tekshiruv qisman bajarildi: ba’zi qismlar tekshirilmadi.'
    : 'Tekshiruv xato bilan tugadi.';
  const detail = [report.progress, report.message, report.error].filter((text, i, all) => text && all.indexOf(text) === i);
  return `<div class="error-note"><p><strong>${escapeHTML(lead)}</strong> Bu natija “toza” degani emas — qayta tekshiring.</p>` +
    (detail.length ? `<details class="raw-evidence"><summary>Texnik sabab</summary><p class="wrap-anywhere">${detail.map(text => escapeHTML(text)).join('<br>')}</p></details>` : '') +
    '</div>';
}
/** This browser's UTC offset, e.g. "+05:00".

   A schedule or scan window left without a time zone used to be stored as
   UTC while the field suggested "+05:00": 02:30 then ran at 07:30 in
   Tashkent. An empty field now means the operator's own time. */
function localOffset(): string {
  const minutes = -new Date().getTimezoneOffset();
  const sign = minutes < 0 ? '-' : '+';
  const abs = Math.abs(minutes);
  return `${sign}${String(Math.floor(abs / 60)).padStart(2, '0')}:${String(abs % 60).padStart(2, '0')}`;
}
