// Generated from web/src/labels.ts by web/build.mjs -- edit the source, not this file.
"use strict";
const TRIAGE_STATUS = {
  untriaged: "Ko‘rilmagan",
  investigating: "Tekshirilmoqda",
  confirmed: "Tasdiqlangan",
  fix_planned: "Tuzatish rejalashtirilgan",
  false_positive: "Yolg‘on signal",
  accepted_risk: "Xavf qabul qilingan",
  fixed: "Tuzatilgan"
};
const STAGE_SHORT = {
  code: "Kod",
  repository: "Compose",
  dependencies: "CVE",
  iac: "IaC",
  images: "Image",
  web: "Sayt",
  chain: "Zanjir"
};
const STAGE_LONG = {
  code: "Kod va sirlar",
  repository: "Compose va tarmoq",
  dependencies: "Kutubxonalar (CVE)",
  iac: "Konfiguratsiya (IaC)",
  images: "Docker image",
  web: "Sayt va API",
  chain: "Skanerlararo zanjir"
};
const RUN_STATE = {
  queued: "Navbatda",
  waiting: "Ruxsat oynasini kutmoqda",
  running: "Tekshirilmoqda",
  completed: "Tugadi",
  partial: "Qisman — qamrov to‘liq emas",
  failed: "Xato bilan tugadi",
  cancelled: "Bekor qilindi",
  interrupted: "Server to‘xtaganda uzildi",
  external_or_interrupted: "Boshqa oynada boshlangan yoki uzilgan",
  no_supported_packages: "Versiyali paket fayli topilmadi",
  not_selected: "Tanlanmagan",
  never_scanned: "Hech tekshirilmagan",
  not_registered: "Obyekt ulanmagan"
};
const SEVERITY_LABEL = {
  CRITICAL: "Kritik",
  HIGH: "Yuqori",
  MEDIUM: "O‘rta",
  LOW: "Past",
  UNRATED: "Baholanmagan"
};
const SEVERITY_OF = {
  CRITICAL: "CRITICAL",
  HIGH: "HIGH",
  ERROR: "HIGH",
  MEDIUM: "MEDIUM",
  WARNING: "MEDIUM",
  LOW: "LOW",
  INFO: "LOW",
  NOTE: "LOW",
  INFORMATIONAL: "LOW"
};
function severityLabel(raw) {
  return SEVERITY_LABEL[SEVERITY_OF[String(raw || "").toUpperCase()] || "UNRATED"];
}
function severityTone(raw) {
  const scale = SEVERITY_OF[String(raw || "").toUpperCase()];
  return scale === "CRITICAL" || scale === "HIGH" ? "red" : scale === "MEDIUM" ? "amber" : "neutral";
}
function severityBadge(raw) {
  return raw ? `<span class="badge ${severityTone(raw)}">${escapeHTML(severityLabel(raw))}</span>` : "";
}
