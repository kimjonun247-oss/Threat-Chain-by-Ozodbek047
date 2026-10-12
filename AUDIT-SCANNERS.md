# Skanerlar domen-mantig'i auditi

Har bir skanerning mazmuni qatorma-qator ko'rildi: stub/soxta qismlar, noto'g'ri
aniqlash mantig'i, xato sozlash. Severity: 🔴 kritik · 🟠 jiddiy · 🟡 o'rta.

---

## Topilgan muammolar (TUZATILDI)

### SCAN-1 ✅ Ildiz-build xizmatlarda manba-zanjirlari (SX-001/004/006/007) hech qachon ishlamaydi
**Dalil:** `repository.py:510-514` da `build: .` (ildizdan quriladi — ENG keng tarqalgan
Compose holati) → `build_context='.'`. `chains.py` da topilma→xizmat bog'lash:
`path == build_context or path.startswith(build_context + '/')` (chains.py:112, 157, 293).
`build_context='.'` → `prefix='./'`, lekin topilma yo'llari `path_in_snapshot` dan
`app.py` / `src/x.py` ko'rinishida keladi (`./` siz, scanners.py:447-456). Shuning uchun
**hech bir topilma ildiz-kontekstli xizmatga bog'lanmaydi**.

**Ta'siri:** SX-001 (sir+ochiq), SX-004 (zaiflik+ochiq), SX-006 (dep CVE+ochiq),
SX-007 (escape+kirish) — manba-kontekstga tayanadigan barcha zanjirlar `build: .`
xizmatlar uchun **jim ishlamaydi**. Skaner "ishlaydi" (hisobot chiqaradi), lekin
korrelatsiya o'lik — aynan "yolg'ondan ishlaydi".

**Nega niqoblangan:** `samples/chain-demo/docker-compose.yml` `build: ./app` (subkatalog →
`app`) ishlatadi, shuning uchun demoda SX-001 ishlaydi. verify_platform buni sezmaydi.

**Tuzatma yo'nalishi:** `build_context` ni normalizatsiyada ildiz uchun `''` ga keltirish
(`.` va `./` → `''`), va `chains.py` bog'lashda bo'sh kontekst "hamma yo'l mos keladi"
degani bo'lsin (ildizdan quriladigan xizmat butun manbani qamraydi). SX-001/004/006/007
to'rtalasida bir xil tuzatish.

### SCAN-2 ✅ OSV severity top-level CVSS ni e'tiborsiz qoldiradi → CVE under-rating
**Dalil:** `advisories.py:157` faqat `record['database_specific']['severity']` (GHSA-ga
xos sifat yorlig'i) ni o'qiydi. OSV yozuvining **top-level `severity`** massivi
(`[{type:"CVSS_V3", score:"CVSS:3.1/..."}]`) o'qilmaydi. GHSA yorlig'i yo'q, lekin CVSS
bor yozuvlar (NVD/PySEC manbali — keng tarqalgan) → `severity='UNKNOWN'` →
`priority='REVIEW'` (advisories.py:170-172). `enrich()` NVD'dan **faqat CWE** tortadi
(advisories.py:205-208), CVSS'ni emas — garchi NVD javobida CVSS bo'lsa ham.

**Ta'siri:** CVSS 9.8 bo'lgan (lekin GHSA yorlig'isiz) real CVE P1 emas, REVIEW sifatida
ko'rsatiladi. Bu SLA muddatini (CRITICAL=7 kun) bermaydi, va CRITICAL-asosli zanjir
triggerlarini zaiflashtiradi: `SX-002` (CHAIN_SEVERITY='CRITICAL') va `SX-006`
(`priority=='P1'`) bunday CVE'ni o'tkazib yuboradi. False-negative emas (topilma
ko'rinadi), lekin jiddiy mis-prioritization.

**Tuzatma yo'nalishi:** OSV top-level `severity` CVSS vektoridan/ballidan sifat bandiga
map qilish (0–3.9 LOW, 4–6.9 MEDIUM, 7–8.9 HIGH, 9–10 CRITICAL) va `database_specific`
yorlig'i bilan birga eng yuqorisini olish. Ixtiyoriy: `enrich()` da NVD CVSS'ni ham
ishlatish (allaqachon tortiladigan javobdan).

---

## Ko'rib chiqilib, TO'G'RI deb tasdiqlangan (soxta emas)

- **Kod skaneri** (scanners.py): semgrep/gitleaks/pmd to'g'ri bayroqlar bilan
  (`--disable-nosem`, `--ignore-gitleaks-allow`, `--redact=100`), oqim faylga yoziladi
  (deadlock yo'q), exit-kodi/natija izchillik tekshiruvi, muloyim xatolik — tool yiqilsa
  `failed`, hammasi tugamasa `partial`. Soxta "toza" yo'q.
- **CodeQL** (deep_analysis.py): haqiqiy `database create --build-mode=none` + `analyze`
  (security-extended, `--no-download` offline), SARIF data-flow pars, path-traversal
  tekshiruvi. `enabled()` bilan gated — o'chirilganda report'ga umuman qo'shilmaydi
  (soxta toza yo'q).
- **Dependency/OSV** (advisories.py): versiya moslashtirish **OSV server-tomonida**
  (`/querybatch` package+version → faqat ta'sir qiluvchi advisory'lar). Uy-qurma versiya
  taqqoslash yo'q → noto'g'ri-versiya false-negative yo'q. Ekosistema nomlari aniq
  ('PyPI','npm','Go','Maven' group:artifact, 'NuGet','Packagist','crates.io','RubyGems').
  PyPI PEP 503 normalizatsiya.
- **Ustuvorlik** P1/P2/P3/REVIEW: KEV + severity dan to'g'ri (advisories.py:172).
- **EPSS** boyitish: FIRST.org dan batch, alias bo'yicha max — haqiqiy, ishlaydi.
- **Taxonomy** CWE→OWASP: jonli MITRE-manbali xarita (249 CWE, 10 kategoriya), to'g'ri
  mosliklar (CWE-89→A05, CWE-502→A08...). setup_cwe.py o'lik emas.
- **Fingerprint** (findings.py): tamoyilli dizayn, tradeoff'lar hujjatlashtirilgan.
- **webscan**: haqiqiy HTTP tekshiruvlar (CSP/HSTS/CORS/cookie Secure+HttpOnly/
  directory-listing/error-disclosure) + nuclei (4MB cap, diskka yozmaydi).
- **Image zanjirlari** SX-002/003/005: image→xizmat bog'lanishi, bo'shliqlar (gap)
  halol hisobotlanadi (unlinked/ambiguous/not-scanned/partial/kev-unavailable).

## Kuzatuv (bug emas, ma'lum tradeoff)
- **Bir xil satr fingerprint to'qnashuvi** (findings.py): ikkita bir xil matnli zaif satr
  (masalan ikkita `eval(x)`) bir xil fingerprint oladi → bitta sifatida birlashadi.
  Ataylab: qator raqamini chiqarib tashlash triage'ni tahrirlarga chidamli qiladi.
  Hujjatlashtirilgan narx; ikkita alohida joy bitta qaror/tafsilotni ulashadi.
