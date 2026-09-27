# Muammolar ro'yxati — 2026-09-17 to'liq sinovi

Loyihaning beshala bosqichi yakunlangach o'tkazilgan to'liq sinovda (271 test, 18 CLI skripti,
34 API endpoint, 9 web bo'limi, jonli crAPI laboratoriyasi) aniqlangan muammolar.

Holat: **A** — sinov davomida tuzatilgan, **B** — ochiq nuqson, **C** — ma'lum qamrov chegarasi,
**D** — muhit/operatsion.

---

## A. Sinov davomida tuzatilgan

Bularni qayta izlamaslik uchun yozib qo'yilgan.

| # | Muammo | Sabab | Tuzatish |
|---|---|---|---|
| A1 | `/api/assessments/reports/<id>/sarif` 404 qaytardi | Kod to'g'ri edi; server 14:20 da ishga tushgan, `app.py` 18:07 da tahrirlangan — eski jarayon eski marshrutni ushlab turgan | Server qayta ishga tushirildi (kod o'zgarmadi) |
| A2 | `check_all.py` ishlamay qolgan | 1-bosqichda `pipeline.validate()` ga `repository_target` qo'shilgan, skript yangilanmagan | `--repository-target` argumenti qo'shildi |
| A3 | `validate_pipeline.py` umuman ishga tushmasdi | `from zanjir.lab import listener` — modul `zanjir.httptest` ga qayta nomlangan, barcha testlar yangilangan, bu fayl unutilgan | Import tuzatildi |
| A4 | `validate_pipeline.py` payload'i rad etilardi | A2 bilan bir xil sabab — `repository_target` yo'q | Payload'ga maydon qo'shildi |
| A5 | `verify_pilot_api.py` `readiness` tekshiruvi yiqilardi | 0.6 da offline rejim olib tashlanganda rejim nomi `local_single_user_pilot` → `online_evidence_based_pilot` ga o'zgargan; skript eski qiymatda qolgan | Yangi qiymatga o'tkazildi |
| A6 | `verify_pilot_api.py` `health` tekshiruvi yiqilardi | Versiya `0.5.0` deb qattiq yozilgan, ilova `0.6.0` qaytaradi | Qattiq yozilgan versiya o'rniga `/api/health` va `readiness` mosligi tekshiriladi — yana eskirmaydi |
| A7 | Portfelda crAPI kod bosqichi "10 nishon" deb ko'rsatilardi | `BUNDLED` guruh `normalise()` dan o'tmagan, satr `len()` bilan sanalgan | `projects()` da normallashtiriladi |
| A8 | `crapi-full` portfelda ikki marta chiqardi | `derived()` faqat guruh kalitlarini chetlab o'tardi, guruh ichidagi nishon ID'larini emas | `claimed()` qo'shildi |
| A9 | Trend diagrammasi ko'rinmasdi | CSP `style-src 'self'` inline `style="width:…"` ni bloklaydi | CSP bo'shatilmadi; kenglik CSS sinflari orqali beriladi |
| A10 | TLS nazorat testi yiqilardi | Sertifikatlarda `SubjectKeyIdentifier`/`AuthorityKeyIdentifier` yo'q, OpenSSL 3.2+ talab qiladi | Ikkala kengaytma qo'shildi |
| A11 | TLS blokida mazmun kelgach ham `.empty` sinfi qolardi | `render()` `className` ni tozalamasdi | Tozalanadigan qilindi |
| A12 | Portfelda crAPI Repository bosqichi birdan "Tekshirilmagan" bo'lib qoldi | **Men yozgan test ishlab chiqarish ma'lumotlariga yozgan**: `test_chain_demo_sample.py` har safar `repo_store.scan_profile()` ni chaqirib `repository-runs/` ga haqiqiy hisobot yozardi; 57 ta test artefakti to'planib, 30 qatorlik ro'yxat oynasidan crAPI'ning haqiqiy dalillarini siqib chiqargan | Test `REPO_RUNS` ni vaqtinchalik papkaga yo'naltiradigan qilindi; 57 ta artefakt o'chirildi, 27 ta crAPI dalili saqlandi. To'liq to'plam endi hisobot papkalariga umuman yozmaydi |
| A14 | Yiqilgan image tekshiruvi hisobotida `message: null` qolardi | Tashqi 11 daqiqalik chegara `TimeoutError` beradi, lekin izoh faqat `ValueError` uchun yozilardi — operator hech qanday sababsiz "failed" ko'rardi. `crapi-identity` da aynan shu holat yuz berdi | Har bir yiqilish yo'liga o'qiladigan sabab berildi: chegara o'z matnini tushuntiradi va qayta urinishni taklif qiladi; kutilmagan tur uchun ham umumiy izoh yoziladi |
| A15 | Qoida paketini `--force` bilan qayta o'rnatish yiqilsa, qoidalarsiz holat qolardi | `install()` eski paketni tekshirishdan **oldin** o'chirardi; manifest'siz qoida fayllari esa "o'rnatilmagan" deb o'qilib, skan jimgina 7 ta lokal qoidaga tushardi | Yangi paket yonma-yon quriladi va faqat to'liq bo'lgach almashtiriladi; manifest'siz qoida fayllari endi xato sifatida ko'rsatiladi |
| A16 | Birlashtirilgan qoida fayli har bir qoidani ikki marta yuklatardi | Fayl registr papkasi ichida edi; `--config <papka>` uni ham o'qirdi | Fayl papkadan tashqariga ko'chirildi; buni test qo'riqlaydi |
| A17 | Trivy Aqua'ga anonim foydalanish ma'lumotini yuborardi | Trivy standarti; loyihaning "faqat paket nomi va versiya chiqadi" siyosatiga zid | Har bir Trivy chaqiruviga `--disable-telemetry --skip-version-check` qo'shildi (Semgrep va Nuclei'da allaqachon bor edi) |
| A18 | Test to'plami har yurishda dalil papkasiga hisobot yozardi | Mening B2 testim CLI'ni haqiqatan ishga tushirgan — A12 bilan bir xil xato | Test germetik qilindi; butun to'plam uchun qo'riqchi qo'shildi (`test_aa_…`/`test_zz_…`): to'plam boshidagi va oxiridagi dalil papkalari solishtiriladi. Aniq bog'lanadigan 4 ta artefakt o'chirildi; qolgan 53 ta `validation-osv-control` hisoboti orasidan test artefaktlarini ishonchli ajratib bo'lmagani uchun **o'chirilmadi** |
| A19 | Toza nusxada Semgrep va Gitleaks'ni o'rnatib bo'lmasdi | `.tools/` git'da e'tiborsiz; `setup_all.py` faqat Trivy, Nuclei, qoida paketi va PMD'ni o'rnatardi. Bu mashinadagi macOS nusxalari qo'lda qo'yilgan edi | `setup_scanners.py`: Gitleaks — rasmiy reliz, SHA-256 checksums fayli bilan; Semgrep — pinlangan versiya, loyiha ichidagi venv. `setup_all.py` ning birinchi (majburiy) qadami |
| A20 | Sintetik nazorat hisobotlari umumiy ro'yxatning yarmidan ko'pini egallagan | `validate_pilot.py` har yurishda yangi juftlik yaratar, eskisi ro'yxatda qolardi | 56 ta hisobot **arxivlandi** (o'chirilmadi): `dependency-runs/_archive/`. `validate_pilot.py` endi eskirgan juftlikni o'zi arxivlaydi; dalil sifatida havola qilingan juftlik joyida qoladi |
| A21 | Portfel skanerlangan image'ni "tekshirilmagan" deb ko'rsatdi | Portfel UI ro'yxati bilan bir xil `history()` ni ishlatardi — u faqat oxirgi 30 ta hisobotni qaytaradi. 36 ta image hisobotidan keyin `crapi-workshop` skani oynadan tushib ketdi. Bu 4-bosqichdagi mening xatoim; ma'lumot ko'paygach yuzaga chiqdi | `history()` ga `limit` parametri; portfel barcha qatorlarni o'qiydi (indeks tufayli arzon). Regressiya testi qo'shildi |
| A23 | Testlar haqiqiy triage do'koniga yozdi | B2 da tugagan skan yangi joyga — `profiles/triage/` ga — yoza boshladi. Hisobot papkalarini patch qiladigan testlar bu do'kon haqida bilmasdi, va to'plamning birinchi yurishi u yerda 3 ta haqiqiy loyiha yaratdi. Bu A12/A18 bilan bir sinfdagi xato, uchinchi marta | Dalil qo'riqchisi (`tests/evidence_guard.py`) endi `profiles/triage` ni ham kuzatadi — qoida shu: **skan yozadigan har qanday papka ro'yxatda bo'lishi kerak**. Izolyatsiya bitta qatorga tushirildi (`tests/isolation.py`), skan bajaradigan 9 ta test sinfiga qo'shildi; iflos yozuvlar o'chirildi |
| A28 | Windows'da masofaviy repozitoriy skani hech qachon ishlamasdi | B6 da klon buyrug'iga `core.hooksPath=/dev/null` berilgan edi — bu yo'l Windows'da mavjud emas, ya'ni git birinchi bayroqdayoq yiqilardi. B8 dagi Windows auditida topildi; macOS'da yuritilgan testlar buni hech qachon ko'rsatmasdi | Bo'sh vaqtinchalik papka ishlatiladi (u klon bilan birga o'chiriladi). `tests/test_platform_paths.py` endi yangi 8 ta modulda POSIX-ga xos yo'l (`/dev/null`, `/tmp/`, `/etc/`, `/var/`) qolmaganini doimiy tekshiradi |
| A25 | Har bir web so'rovi yuborilmasdan yiqilardi | B6 da qo'shilgan `User-Agent` da tipografik apostrof (U+2019) bor edi; `http.client` sarlavha qiymatini latin-1 bilan kodlaydi va `UnicodeEncodeError` beradi. Ya'ni yangi User-Agent bilan **birorta so'rov ham** ketmasdi | Qiymat sof ASCII qilindi; test `USER_AGENT.encode('latin-1')` ni tekshiradi |
| A26 | macOS'da masofaviy repozitoriy skani doim yiqilardi | `/var` — `/private/var` ga symlink. Klon yo'li resolve qilinmagani uchun `snapshot()` ning "fayl manba ichida" tekshiruvi har safar "Manba yo'li loyiha chegarasidan chiqdi" deb yiqilardi | `remote_source.clone()` vaqtinchalik papkani `.resolve()` bilan qaytaradi |
| A27 | Masofaviy loyiha ro'yxatda `KeyError` berardi | `scanners.targets()` har bir profilda `root` kaliti borligini nazarda tutardi; masofaviy profilda u yo'q | Masofaviy profil uchun `available: true` (lokal papka yo'q — klon skan vaqtida olinadi) va `source`/`url`/`ref` maydonlari qaytariladi |
| A24 | Compose fayli o'rniga YAML bo'lmagan fayl ko'rsatilsa, brauzer javobsiz qolardi | **A22 ning takrori.** O'shanda faqat `custom_rules.py` tuzatilgan; `repository.py` dagi `parse_yaml()` da aynan o'sha naqsh qolib ketgan edi — `yaml.parse()` va `get_single_node()` o'ralmagan, `yaml.YAMLError` esa `ValueError` emas. B7 ni audit qilishda `/etc/hosts` ni compose sifatida ko'rsatib topildi | `parse_yaml()` butunlay o'ralди va xato qator raqami bilan qaytadi; `webscan.py` dagi template yuklash ham o'raldi. **Sinf darajasida test** qo'shildi: `zanjir/` ichidagi har bir `yaml.parse/safe_load` chaqiruvi yonida `yaml.YAMLError` ushlagichi borligi tekshiriladi, ya'ni yangi qo'shilgan qo'riqlanmagan chaqiruv testni yiqitadi |
| A22 | Qoida muharririda YAML xatosi yozilsa, brauzer javobsiz qolardi | `custom_rules.parse()` ning chuqurlik/alias tekshiruvi `yaml.parse()` ni `safe_load` dan **oldin** chaqiradi va o'rab olinmagan edi. `yaml.YAMLError` `ValueError` emas, shuning uchun `app.py` dagi `except ValueError` uni ushlamagan — so'rov ishlovchisi yiqilib, ulanish javobsiz yopilgan | Tekshiruv sikli ham `except yaml.YAMLError` ichiga olindi; endi 400 va aniq xabar qaytadi ("YAML o'qilmadi: …"). **B0 bosqichidagi yangi API shartnomasi testi topdi** |
| A13 | Image bosqichi "9/9 nishon tekshirilgan" deb ko'rsatardi | Yiqilgan skan ham "tekshirilgan" deb sanalardi — hisobot yozuvi bor, lekin natija yo'q | `scanned_targets` endi faqat `completed` bo'lganlarni sanaydi; `attempted_targets` va `incomplete_targets` alohida. Endi "7/9 nishon natija berdi · Tugamagan: chatbot, identity" |

---

## B. Nuqsonlar

> **2026-09-17 bartaraf etish sessiyasi:** B1–B7 ning hammasi, so'ng C1, C4 va D3 ham yopildi.
> Testlar 258 → **399**. C va D bo‘limlari ham yopildi; optimallashtirish rejasi bajarildi.

### ~~B1. Yordamchi skriptlar test bilan umuman qoplanmagan~~ ✅ TUZATILDI

`tests/test_cli_scripts.py` qo'shildi (13 ta test), `pipeline.SELECTION_FIELDS` konstantasi
kiritildi. Endi quyidagilar avtomatik ushlanadi:

- har bir skript import bo'lishi (A3 turidagi eskirgan import);
- `zanjir.*` importlari haqiqatan mavjud modulga ishora qilishi;
- `--help` ishlashi va ish bajarmasligi;
- pipeline payload'i `pipeline.validate()` talabiga **aynan** mos kelishi — bu A2/A4 ni
  paydo bo'lgan zahoti ushlaydi, chunki endi maydonlar ro'yxati bitta manbadan olinadi;
- har bir tanlov maydoni uchun CLI bayrog'i borligi;
- eskirgan versiya/rejim satri qattiq yozilmaganligi (A5/A6);
- stdout'ga faqat JSON chiqishi (B2);
- `/api/health` va `readiness` versiyasi mos kelishi.

### ~~B2. CLI stdout sof JSON emas~~ ✅ TUZATILDI

`check_dependencies.py`, `check_image.py`, `check_web.py`, `scan_code.py`, `ci_gate.py` —
odamga mo'ljallangan barcha satrlar `file=sys.stderr` ga o'tkazildi. Endi
`script > out.json` to'g'ridan-to'g'ri parse qilinadi. Shartnoma ikki test bilan
qo'riqlanadi: manba tahlili (har bir `print()` yo `file=` bilan, yo `json.dumps`) va
haqiqiy ishga tushirish natijasini parse qilish.

### ~~B6. Ishlab turgan server versiyasini bilishning yo'li yo'q~~ ✅ TUZATILDI

`/api/health` endi `code_fingerprint` (jarayon **yuklagan** kod xeshi) va `started_at`
qaytaradi; `/api/readiness` esa **diskdagi** joriy xeshni beradi. Ikkalasi farq qilsa,
boshqaruv panelida qizil ogohlantirish chiqadi:

> **Server eski kod bilan ishlayapti.** Diskdagi fayllar o'zgargan (… ≠ …).
> O'zgarishlar kuchga kirishi uchun serverni qayta ishga tushiring.

Amalda tekshirildi: fayl o'zgartirilganda xeshlar ajraldi va ogohlantirish ko'rindi.

### ~~B7. Beshta skript `--help` ni tanimay, haqiqiy ish bajarardi~~ ✅ TUZATILDI

**Bu sinov davomida yangi aniqlandi va avvalgi hisobotimdagi xatoni ham ochdi.**
`pilot_evidence.py`, `setup_nuclei.py`, `setup_tools.py`, `validate_pipeline.py`,
`validate_web.py` da `argparse` umuman yo'q edi — noma'lum argument e'tiborsiz qolar va
skript odatdagidek ishga tushardi. `validate_web.py --help` yordam o'rniga **to'liq
haqiqiy Nuclei skanini** ishga tushirardi.

Buning natijasida avvalgi "18/18 CLI kirish nuqtasi ishlaydi" degan xulosam noto'g'ri edi:
u skriptlar yordam ko'rsatganini emas, haqiqiy ish bajarib `0` qaytarganini o'lchagan.

Beshalasiga minimal `argparse` qo'shildi; endi `--help` ishlaydi va noma'lum bayroq rad
etiladi. `HelpTests` buni doimiy qo'riqlaydi.

---

### B1–B2, B6–B7 dan olingan saboq

To'rttala nuqson ham bitta sababdan: **asosiy kod va yordamchi skriptlar o'rtasida
avtomatik bog'lanish yo'q edi.** Endi bog'lanish bor — `SELECTION_FIELDS` konstantasi,
`code_fingerprint` taqqoslash va `tests/test_cli_scripts.py`.

---

## B-ochiq → yopildi

### ~~B3. Kod topilmalari jadvalida sahifalash yo'q~~ ✅ TUZATILDI

Kod jadvaliga CVE bo'limidagi naqsh ko'chirildi: sahifada 25 qator, **qidiruv** maydoni va
**daraja filtri** (`ERROR` / `WARNING` / `INFO` / darajasiz). Hisobot almashtirilganda sahifa
va filtr nolga qaytadi, xuddi shu hisobot qayta render bo'lganda esa saqlanadi.

Tekshirildi: crAPI'ning 144 topilmasi `1/6 sahifa` bo'lib chiqdi, `ERROR` filtri 18 taga,
"Dockerfile" qidiruvi 6 taga qisqartirdi.

### ~~B4. SX-001 zanjiri bundled namunada hech qachon ishlamaydi~~ ✅ TUZATILDI

`samples/chain-demo/` sun'iy namunasi qo'shildi va **bundled profil** sifatida ham
Repository, ham Manba kodi ro'yxatiga yozildi (`ALLOWED_PROFILES`,
`scanners.bundled_code_samples()`). Endi hech qanday qo'lda sozlashsiz:

- **Repository** bo'limida `chain-demo` → RP-001, RP-005, RP-006, RP-007, RP-008;
- **Umumiy tekshiruv**da ikkala bosqichga `chain-demo` → qo'shimcha **SX-001**
  (`CWE-798` + `CWE-668` → `A01` + `A07`, `verified: false`).

Namunadagi kalit **soxta** va bu `README.md`, fayl izohi hamda provenance'da aytilgan.
Tasdiqlandi: kalit hisobot, SARIF va Markdown eksportlarining hech birida yo'q —
`secret_value: "hidden"` saqlanadi.

`tests/test_chain_demo_sample.py` (15 test) namunaning o'zini qo'riqlaydi: `build:` yo'qolsa
yoki port loopback'ga o'tkazilsa, testlar yiqiladi — ya'ni loyihaning asosiy farqi jimgina
ko'rsatilmaydigan bo'lib qolmaydi.

### ~~B5. Portfel guruhlashi crAPI uchun kodda qattiq yozilgan~~ ✅ TUZATILDI

`portfolio.unknown_targets()` qo'shildi: guruh nomlagan, lekin hech bir ro'yxatda
yo'q nishonlar aniqlanadi va portfel jadvalida qizil izoh sifatida chiqadi
("Ro'yxatda yo'q nishon: …"). Ilgari bunday nishon jimgina e'tiborsiz qolar va guruh
o'zi da'vo qilganidan kamroq qamrab, sog'lomroq ko'rinardi.

Tasdiqlandi: `pilot-mongodb` ro'yxatdan chiqarilganda ogohlantirish chiqdi, qaytarilgach yo'qoldi.

## C. Qamrov chegaralari

### ~~C1. Kod bosqichi `partial`, sababi noaniq~~ ✅

Xatolar toifalarga ajratiladi, fayllari va bajariladigan harakat ko'rsatiladi. crAPI'dagi 36 ta
xatoning hammasi Helm (Go) shablonlari ekani aniqlandi. Bosqich baribir `partial` qoladi —
o'qilmagan fayl haqiqiy bo'shliq.

### ~~C2. CVE qamrovi cheklangan~~ ✅

**Beshta yangi ekotizim qo'shildi.** Faqat aniq versiya yozadigan lock formatlari o'qiladi:

| Format | Ekotizim |
|---|---|
| `Pipfile.lock`, `poetry.lock`, `uv.lock` | PyPI |
| `gradle.lockfile` | Maven |
| `Gemfile.lock` | RubyGems |
| `composer.lock` | Packagist |
| `Cargo.lock` | crates.io |

Sinovda: 14 paket → **124 haqiqiy OSV topilmasi**, 4 tasi P1.

**2026-09-25 (B8) da qo'shildi:** `pyproject.toml` dan **aniq pinlangan** (`==`) qatorlar
o'qiladi. `flask==2.3.2` ni hal qilish uchun hech qanday build vositasi kerak emas — u lock
fayldagidek aniq. Diapazon (`requests>=2.0`), versiyasiz nom va `[tool.*]` jadvallari esa
o'qilmaydi va har biri o'z sababi bilan bo'shliq sifatida ko'rsatiladi
(`python_pyproject_not_exact_pin`).

**Qasddan qo'shilmagani:** `pom.xml`, `build.gradle` — bularda versiya
diapazon yoki xossa bo'lishi mumkin va uni hal qilish uchun build vositasini ishga tushirish
kerak. Bu modul repository kodini hech qachon bajarmaydi, ya'ni versiyani **taxmin qilish**
kerak bo'lardi — taxmin qilingan versiya esa dalilga o'xshagan, lekin dalil bo'lmagan CVE
mosligini beradi. Ular endi aniq sabab bilan rad etiladi (`gradle_lockfile_missing`, `maven_lockfile_missing`),
ya'ni operator nima qilish kerakligini biladi: `./gradlew dependencies --write-locks`.

**Hal qilib bo'lmaydigan qismi:** `psycopg2-binary` (versiyasiz) va `chromadb>=0.6.1`
(diapazon) kabi satrlar. Manbaning o'zida aniq versiya yo'q — hech bir parser uni o'ylab
topa olmaydi. Bular bo'shliq bo'lib qoladi va shunday ko'rsatiladi.

### ~~C3. crAPI image qamrovi~~ ✅ 8/9

C6 tuzatilgandan keyin `identity` ham o'tdi. Qolgan bittasi — C6 ga qarang.

### ~~C4. Windows tomoni~~ ✅ tekshiruv bitta buyruqqa keltirildi

`verify_platform.py` har qanday OS da vositalarni, unit testlarni, haqiqiy kod skanini,
RP-001..008 + SX-001 zanjirini, haqiqiy Nuclei nazoratini va CI gate chiqish kodlarini
**haqiqatan ishga tushiradi** va natijani `validation-runs/platform-<os>.json` ga yozadi.
macOS'da to'liq o'tdi. Windows'da: `VERIFY-WINDOWS.cmd` (ikki marta bosish). GitHub'da:
`ci-examples/threatchain-self-test.yml` Windows/Ubuntu/macOS matritsasida.

**2026-09-25 (B8):** B5–B7 da qo'shilgan modullar Windows uchun alohida auditdan o'tkazildi va
bitta haqiqiy nuqson topildi — `remote_source.py` git'ga `core.hooksPath=/dev/null` berardi,
bu yo'l Windows'da mavjud emas va masofaviy skan u yerda **hech qachon ishlamasdi** (A28).
Endi bo'sh vaqtinchalik papka ishlatiladi. Yangi modullarda POSIX-ga xos yo'l qolmaganini
`tests/test_platform_paths.py` doimiy tekshiradi.

**Halol:** Windows natijasining o'zi hali yo'q — uni faqat Windows mashinasi bera oladi. Qolgan
ish endi bitta buyruq; A19 tufayli toza Windows nusxasida vositalar ham avtomatik o'rnatiladi.

### ~~C5. Apex qamralmaydi~~ ✅ PMD bilan qamrab olindi

OSS Semgrep Apex'ni parse qila olmaydi, lekin **PMD** (BSD, ochiq manba) Apex xavfsizlik
qoidalariga ega. `setup_pmd.py` (7.27.0, GitHub e'lon qilgan SHA-256) o'rnatadi; Java kerak.
Skan faqat loyihada `.cls`/`.trigger` bo'lsa PMD'ni ishga tushiradi. 10 ta qoidaning har biri
CWE → OWASP bilan bog'langan; hisobot matni qoidaga xos qat'iy yozuv (PMD o'z xabariga
koddagi nomlarni qo'yishi mumkin). `chain-demo` ga zaif Apex klassi qo'shildi: ApexOpenRedirect
(CWE-601), ApexSOQLInjection (CWE-89), ApexSharingViolations (CWE-284) topildi.

### ~~C6. Katta image'lar~~ ✅

- `identity` (597 s birinchi marta) → keyingi skan **4 s** (digest tasdiqlangan).
- 1 GB chegarasi olib tashlanmadi. Operator uni **bitta skan uchun ongli ravishda** oshira oladi:
  `check_image.py --target X --max-size 2GB` (eng ko'pi 4 GB). Hisobot buni o'zi aytadi
  (`size_limit`, `size_limit_raised`, `scope`). Vaqt byudjeti ham mutanosib o'sadi
  (10 daqiqa / GB) — standart 1 GB skan o'zgarmaydi.
- Yuqori chegarada tasdiqlangan digest standart chegarani **chetlab o'tolmaydi**: har bir digest
  uchun eng qat'iy isbotlangan chegara saqlanadi.
- Disk tekshiruvi: image + 1 GB joy bo'lmasa skan boshlanmaydi va sababini aytadi; 5 GB dan kam
  qolganda boshqaruv panelida ogohlantirish chiqadi.

---

## D. Muhit va operatsion

| # | Holat | Natija |
|---|---|---|
| ~~D1~~ | ~~Colima ishlab turibdi~~ ✅ | `colima stop` bajarildi; Docker ish vaqti to'xtatildi |
| ~~D2~~ | ~~NVD kaliti yo'q, sekin~~ ✅ | B7 da **Sozlamalar oynasi** qo'shildi: kalit brauzerdan kiritiladi, `profiles/settings.json` ga faqat egasi o'qiy oladigan huquq (0600) bilan yoziladi, javoblarda hech qachon to'liq ko'rsatilmaydi va so'rov tezligi serverni qayta ishga tushirmasdan o'zgaradi. Muhit o'zgaruvchisi ustun turadi. Kalitning o'zini men ololmayman — bu foydalanuvchi hisobi |
| ~~D3~~ | ~~Yagona o'rnatish buyrug'i~~ ✅ | `setup_all.py` |

---

## E. 2026-09-25 toza nusxa sinovi — topilgan va tuzatilgan

Toza nusxada vositalar o'rnatildi, server ishga tushirildi, barcha bosqichlar ataylab zaif
Flask ilovasi, eskirgan `alpine:3.10` image va ochiq `.env`/`backup.sql`/`.git/config`
beradigan lokal sayt ustida yuritildi, interfeys Playwright bilan (1400px va 390px) aylanib chiqildi.

| # | Muammo | Sabab | Tuzatish |
|---|---|---|---|
| E1 | CI gate `partial` skanni **o'tkazib yubordi** (exit 0) | Faqat `failed` exit 2 berardi; OSV ishlamasa CVE bosqichi `partial` bo'ladi va gate topilmasi yo'q deb o'tardi | `ci_gate.incomplete_stages()`; tugamagan bosqich → exit 2, eski xulq `--allow-partial` |
| E2 | Lock fayli yo'q loyihada umumiy skan doim `partial`, `--baseline last-green` hech qachon topilmasdi | `no_supported_packages` tugamagan deb sanalardi | `pipeline.FINISHED_STAGE_STATES`; portfelda "Manifest yo'q" deb alohida ko'rinadi |
| E3 | Rasmiy paketsiz kod skaneri SQLi, pickle, `yaml.load`, Flask debug'ni ko'rmasdi; birorta lokal qoida gate'ga ta'sir qilmasdi | 7 ta qoidaning hammasi `WARNING`, taint yo'q | 12 ta yangi qoida (5 taint `ERROR`); sinov ilovasida 1 → 9 topilma, loyiha kodida 0 noto'g'ri signal |
| E4 | Ochiq `.env` (faqat sirlar) va sarlavhasiz SQL dump topilmadi | Shablon ikkita mustaqil shartni birga talab qilardi | Shablonlar v2; `validate_web.py` nazorati (soft-404 bilan) o'tadi |
| E5 | `/api/rules/validate` internetsiz ~100 s qotardi, test 15 s da yiqilardi | `semgrep --validate` semgrep.dev'dan lint to'plami yuklaydi | Bo'sh papka skani orqali o'sha parser, internetsiz ~2 s |
| E6 | TLS tekshiruvchi proxy bor tarmoqda hech narsa o'rnatilmasdi | `certifi` doim `SSL_CERT_FILE` dan ustun edi; proxy doim chetlab o'tilardi | `zanjir/nettrust.py`: operator CA'si birinchi; `THREATCHAIN_USE_PROXY=1` ixtiyoriy |
| E7 | Toza nusxada 3 ta test yiqilardi | Mahalliy ro'yxat (`validation-osv-control`), semgrep.dev, buzilgan `cryptography` | Nishon qidiruvi stub qilindi; E5; `cryptography` ishlamasa test o'tkaziladi, `pilot_tls` o'qiladigan xato beradi |
| E8 | Web skan rad etilgan nishonda umumiy "tugamadi" yozardi | `ValueError` matni yo'qotilardi | Sabab hisobotga yoziladi (test bilan) |
| E9 | `check_dependencies.py`, `scan_code.py`, `check_all.py` toza nusxada tushunarsiz xato/traceback | Standart `crapi-full` manbasi omborda yo'q | Mavjud nishonlar taklif qilinadi, traceback o'rniga exit 2 |
| E10 | `yarn.lock`, `pnpm-lock.yaml` o'qilmasdi | "Qo'llanmaydi" ro'yxatida edi | Ikkala format (yarn v1/Berry, pnpm v5/v6/v9) o'qiladi; git/fayl/workspace — nomli bo'shliq |
| E11 | Portfelda bosqich ustunlari ekrandan chiqib ketardi; `crapi-full` ikki marta | `th{white-space:nowrap}`; takrorlanish | Satr sarlavhasi o'raladi; ro'yxat takrorsiz |
| E12 | "So'nggi tekshiruvlar" doim bo'sh | `#history` ni hech bir skript to'ldirmasdi | `/api/dashboard` dagi `recent` bilan to'ldiriladi, bosilganda bosqich ochiladi |
| E13 | 390px da loyiha kartasi gorizontal chiqib ketardi | Jadval qobiqsiz | `table-wrap` |
| E14 | EOL OS'li image'da bitta topilma "toza" ko'rinardi | EOSL faqat yopiq bo'limda edi | Image sahifasida aniq ogohlantirish |

**Ataylab qoldirildi:** `pom.xml`/`build.gradle` va `==` siz Python qatorlari (versiyani taxmin
qilish kerak bo'ladi); masofaviy git'ni ichki manzilga ro'yxatga olish (lokal bir foydalanuvchili
vosita, ichki GitLab ham qonuniy nishon); proxy standart holatda chetlab o'tiladi (ambient
proxy ma'lumotlari operator so'ramaguncha uzatilmaydi).

---

## F. 2026-09-25 har bir vositani alohida sinash — topilgan va tuzatilgan

Har bir skaner belgilangan to'plamda sinaldi: 30 ta ma'lum zaiflik (5 til) + xavfsiz fayllar,
10 ta haqiqiy formatdagi soxta sir, Apex, `python:3.9.0-alpine` (to'g'ridan-to'g'ri Trivy bilan
solishtirildi), Dockerfile/K8s/Terraform, har bir RP qoidasini ishga tushiradigan Compose, zaif va
tuzatilgan sayt, 9 ta mashhur loyihaning haqiqiy lockfile'i, masofaviy DVWA. Alpine `3.10` → `3.24`.

| # | Muammo | Tuzatish |
|---|---|---|
| F1 | Masofaviy git nishoni bilan umumiy tekshiruv, CVE bosqichi va CI gate `KeyError('root')` bilan yiqilardi; gate exit 1 ("to'xtatdi") qaytarardi | `check_target`/`source_for` hamma joyda; kutilmagan xato gate'da exit 2; server har qanday xatoda 500 JSON qaytaradi (ulanishni jim uzmaydi) |
| F2 | Image/web ID'ni qayta ro'yxatga olish ulanishni javobsiz uzardi; nishonni yangilash/o'chirish yo'q edi | 400 va aniq xabar; `replace: true` bilan yangilash; `POST /api/registry/remove` va oynada "Ro'yxatdan chiqarish" (hisobotlar saqlanadi) |
| F3 | Real loyihalarda gate doim exit 2: Semgrep o'qiy olmagan Dockerfile yoki saytdagi 500 sahifa "tugamagan" sanalardi | `classify_stage()`: qamrov bo'shlig'i (ko'rsatiladi, to'xtatmaydi) va tugamagan skan (exit 2) ajratildi |
| F4 | Ko'p hujjatli `pnpm-lock.yaml` o'qilmasdi (vite: 0/1414) | Barcha hujjatlar o'qiladi: 1304 paket + 110 lokal `file:` bo'shliq |
| F5 | 27 ta topilgan zaiflikdan faqat 16 tasi gate'ni to'xtatardi | Yuqori ta'sirli CWE + qoida muallifining MEDIUM/HIGH ishonchi; PMD xavfsizlik qoidalari; natija 24/30, xavfsiz fayllarda 0 |
| F6 | Crawler `/files/` → `/files` (404), papka ro'yxati topilmasdi | Oxirgi `/` saqlanadi; yangi `http-dir-listing` tekshiruvi (CWE-548) |
| F7 | `Server: web` "versiya oshkor" deb belgilanardi | `Server` sarlavhasi faqat versiya raqami bo'lsa |
| F8 | SARIF'da 5 ta bir xil nomli run, kategoriyasiz; lokal qoida xabari umumiy matn edi | Har run'da `automationDetails.id` va skaner nomi; lokal qoidalar o'z xabari bilan |
| F9 | OSV ishlamasa CVE sahifasi "0 zaiflik" ko'rsatardi | "Tugallanmadi · N ta paket tekshirilmadi" va qizil ogohlantirish |
| F10 | Cargo workspace crate'lari crates.io paketi deb sanalardi (ripgrep 11/63) | Registry manbasi bo'lmagan poetry/uv/Cargo yozuvlari — nomli bo'shliq |
| F11 | Gitleaks DB URL paroli va git tarixidagi sirni topmasdi | `connection-string-password` qoidasi (shablonlar istisno); `gitleaks git` bilan tarix, faqat yangi sirlar qo'shiladi (commit bilan) |
| F12 | SBOM'da zaifliklar yo'q edi | CycloneDX `vulnerabilities` (85/85, har biri komponentga bog'langan) |
| F13 | Qoida paketi faqat codeload orqali (bloklansa aniqlik 27/30 → 11/30) | Pinlangan commit git orqali zaxira yo'l bilan olinadi |
| F14 | Hisobot ochilganda tanlovda boshqa loyiha qolardi | `syncTarget()` barcha bo'limlarda |
| F15 | Bitta ma'lumotlar bazasi uchun 6 ta RP-005 | Bitta topilma, yetib boradigan barcha xizmatlar ro'yxati bilan |
| F16 | 200 javobdagi stack trace topilmasdi | Aniq shakllar (Python traceback, Java stek, PHP fatal) har qanday statusda |
| F17 | Semgrep va paket topmagan holatlar (PHP mysqli SQLi, lxml XXE, Java/Go servlet injeksiyalari, SSTI, prototype pollution) | 11 ta yangi lokal qoida (jami 29); benchmark 30/30, DVWA'da 12 ta PHP topilmasi — hammasi haqiqiy, `impossible.php` toza |
| F18 | Faqat image/web nishoni bor loyiha portfelda yo'q edi | "Yakka nishon" loyihasi sifatida ko'rinadi |
| F19 | Kod va Compose bir xil ID'ni ishlata olmasdi; xabar "crapi nomi band" edi | Bir xil ID ruxsat; xabar haqiqiy sababni aytadi |

**Upstream chegaralar (vosita o'zida yo'q, qayd etildi):** PMD'ning ApexOpenRedirect/ApexCRUDViolation
sinov misolida ishlamadi; fayllararo XSS (DVWA `$html` keyinroq boshqa faylda chiqariladi) Semgrep OSS
taint tahlili doirasidan tashqarida; sayoz (depth 1) masofaviy klonda git tarixi faqat oxirgi commit.

---

## Qolgan holat — 2026-09-25, 0.7.0

Ro'yxatdagi **barcha kod bandlari yopildi** (A1–A28, B1–B7, C1–C6, D1–D3). Qolgani ikkitasi,
va ikkalasi ham kod nuqsoni emas:

1. **Windows natijasining o'zi.** Tekshiruv to'liq tayyor, macOS'da 8/8 o'tadi, va Windows'ga
   xos nuqsonlar alohida auditdan o'tkazildi (A28). Ishga tushirish: `VERIFY-WINDOWS.cmd`
   yoki `ci-examples/threatchain-self-test.yml`. Natijani faqat Windows mashinasi bera oladi —
   men uni bu yerda ololmayman.
2. **Disk: 17.0 GB bo'sh.** Colima to'xtatilgan (`colima is not running`). Ogohlantirish
   chegarasi 5 GB; hozir ogohlantirish yo'q. Lab image'lari kerak bo'lmasa `colima delete`
   qo'shimcha joy bo'shatadi — bu operator qarori.

### Qamrovning ataylab qoldirilgan chegaralari

Bular "hal qilinmagan muammo" emas, balki **ongli qaror**: ularni "hal qilish" taxminga
asoslangan natija berardi.

| Chegara | Nega ataylab |
|---|---|
| `pom.xml`, `build.gradle` o'qilmaydi | Versiya diapazon yoki xossa bo'lishi mumkin; aniqlash uchun build vositasini **bajarish** kerak. Bu modul repozitoriy kodini hech qachon bajarmaydi |
| `pyproject.toml` da faqat `==` qatorlar | Diapazonni hal qilish yuqoridagi sabab bilan bir xil |
| `psycopg2-binary` (versiyasiz), `chromadb>=0.6.1` | Manbaning o'zida aniq versiya yo'q — hech bir parser uni o'ylab topa olmaydi |
| Nuclei'ning 6 ta shabloni (9000+ emas) | Har biri qo'lda ko'rib chiqilgan va faqat GET; tekshirilmagan shablonni ishlatish ruxsat doirasidan chiqishi mumkin |
| Gixy darajasidagi nginx tahlili yo'q | RP-002/003/004/009/010/011 proxy-ishonchga qaratilgan; to'liq nginx tahlili uchun Gixy'ning o'zi bor |
| Masofaviy Docker daemon, SSH host skani, agent | B6 rejasidan tashqarida; ular butunlay boshqa ishonch modeli |
| RBAC va ko'p foydalanuvchi | Lokal bir foydalanuvchili vosita; server faqat 127.0.0.1 da |
| Brauzerdan manba papkasini ro'yxatga olish | Standart holatda o'chirilgan (`--allow-registration`) — brauzerga ixtiyoriy fayl yo'lini berish serverga butun diskni o'qishga yo'l ochadi. Auditda isbotlangan |
