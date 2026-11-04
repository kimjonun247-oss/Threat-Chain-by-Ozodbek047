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
