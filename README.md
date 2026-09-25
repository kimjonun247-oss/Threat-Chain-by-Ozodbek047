# ThreatChain 0.7 — AI ishlatilmaydigan, doim online xavfsizlik platformasi

*(loyiha ilgari "Zanjir" nomi bilan yuritilgan; kod ichidagi `zanjir/` Python paketi va `ZANJIR_CRAPI_ROOT` muhit o'zgaruvchisi nomi ichki mos kelish uchun o'zgartirilmagan.)*

Kod, kutubxonalar, container image, ruxsatli sayt/API va joylashtirish dalillarini bir joyda tekshirish. Pentester topilmani baholaydi, tuzatishni rejalashtiradi va qayta skan bilan solishtiradi. Bu bir kompyuter, bir foydalanuvchi uchun pilot; barcha CVE va barcha hujumlarni aniqlash kafolati emas.

**Yakuniy holat (2026-09-25, 0.7.0 + tuzatishlar):** 701 test o'tadi, `verify_platform.py` 9/9
qadamdan o'tadi (Linux; macOS'da 8/8), 7 ta skaner bosqichi, 11 ta zanjir qoidasi (RP-001…011) + 3 ta cross-skaner
zanjiri (SX-001…003). Python bog'liqliklari: **0 ta**.

Ochiq qolgani ikkita, ikkalasi ham kod nuqsoni emas: Windows natijasining o'zi (faqat Windows
mashinasi bera oladi) va Colima diski bo'yicha operator qarori. Tafsilot: [MUAMMOLAR.md](MUAMMOLAR.md).

## Vositalar aniqligi — alohida sinov (2026-09-25)

| Vosita | Sinov | Natija |
|---|---|---|
| Semgrep (29 lokal + 1343 rasmiy qoida) | 30 ta ma'lum zaiflik, 5 til + xavfsiz fayllar | 30/30 topildi; CI gate 24 tasida to'xtaydi; xavfsiz fayllarda gate signali 0 |
| Gitleaks | 10 ta soxta sir (tarixdagi va DB URL bilan) + 3 soxta holat | 10/10, ortiqcha signal 0, qiymat hisobotga tushmaydi |
| PMD (Apex) | 4 zaiflik + xavfsiz klass | 3/4 (upstream chegara), ortiqcha signal 0 |
| Trivy image | `python:3.9.0-alpine` | To'g'ridan-to'g'ri Trivy bilan 85/85; SBOM'da 85/85 zaiflik |
| Trivy IaC | Dockerfile + K8s + Terraform | 41/41 |
| Compose/Nginx | RP-001…011 har biri + xavfsiz Compose | 11/11 qoida; xavfsizda 0 |
| Nuclei + HTTP | zaif va tuzatilgan sayt | barcha ochiq fayllar, CORS, cookie, stack trace, papka ro'yxati; tuzatilganda faqat HTTP |
| Lockfile o'qish | npm, yarn v1/Berry, pnpm v9, Poetry, Pipenv, Composer, Go, Cargo — haqiqiy loyihalar | mustaqil hisob bilan 100% mos |

Tafsilot va tuzatilgan 19 ta muammo: [MUAMMOLAR.md](MUAMMOLAR.md) (F bo'limi).

## 0.7 dan keyingi tuzatishlar (2026-09-25 to'liq sinovi)

Toza nusxani haqiqiy vositalar bilan ishga tushirib, ataylab zaif ilova va ochiq `.env`/SQL dump
bergan sayt ustida sinab topilgan nuqsonlar. Tafsilot: [MUAMMOLAR.md](MUAMMOLAR.md) (E bo'limi).

- **CI gate tugamagan skanni o'tkazib yubormaydi.** Tanlangan bosqich `failed`/`partial`/
  `cancelled` bo'lsa (masalan OSV'ga ulanib bo'lmasa) chiqish kodi endi **2**, avval 0 edi —
  "baza ishlamadi" "zaiflik yo'q" bo'lib ko'rinardi. Eski xulq: `--allow-partial`.
  Lock fayli yo'q loyiha (`no_supported_packages`) tugagan bosqich hisoblanadi, shuning uchun
  bunday loyihada ham `--baseline last-green` endi asos topadi (avval hech qachon topmasdi).
- **Lokal Semgrep qoidalari 7 → 19**, jumladan HTTP so'rovidan kelgan qiymatni kuzatadigan
  taint qoidalari (buyruq va SQL injeksiyasi, deserializatsiya — Python va JS/TS) va
  `yaml.load`. Ular `ERROR`, ya'ni gate'ni to'xtatadi; avval barcha lokal qoidalar `WARNING`
  edi va rasmiy paketsiz Semgrep gate'ga hech qachon ta'sir qilmasdi. Sinov ilovasida
  topilmalar 1 → 9, loyihaning o'z kodida noto'g'ri signal 0.
- **Nuclei `.env` va SQL dump shablonlari (v2):** faqat sirdan iborat `.env` va
  mysqldump sarlavhasisiz SQL eksporti endi topiladi. Nazorat sinovi (`validate_web.py`,
  jumladan soft-404 rejimi) o'zgarishsiz o'tadi.
- **`yarn.lock` (v1 va Berry) va `pnpm-lock.yaml` (v5/v6/v9) o'qiladi** — avval "qo'llanmaydi"
  bo'shlig'i edi, ya'ni Yarn/pnpm loyihalarining npm paketlari umuman tekshirilmasdi.
  git/fayl/workspace manbalari taxmin qilinmaydi, nomli bo'shliq bo'ladi.
- **Korporativ tarmoq:** `SSL_CERT_FILE`/`SSL_CERT_DIR` endi certifi'dan ustun
  (`zanjir/nettrust.py`); proxy `THREATCHAIN_USE_PROXY=1` bilan ixtiyoriy yoqiladi
  (standart holatda avvalgidek chetlab o'tiladi). TLS tekshiruvi hech qachon o'chirilmaydi.
- **O'z qoidasini tekshirish internetsiz ishlaydi:** `semgrep --validate` semgrep.dev'dan
  qoida yuklardi va tarmoq yopiq bo'lsa ~100 s qotib qolardi; endi xuddi shu parser bo'sh
  papka skani orqali ~2 s da ishlaydi.
- **Kichikroq:** web skan rad etilgan nishonda aniq sababni yozadi (masalan metadata
  manzili); `crapi-full` manbasi yo'q bo'lsa CLI mavjud nishonlarni taklif qiladi;
  EOL OS'li image'da aniq ogohlantirish; portfel jadvali ekranga sig'adi; chap paneldagi
  "So'nggi tekshiruvlar" endi to'ladi; telefon kengligida loyiha kartasi chiqib ketmaydi;
  3 ta test mashinaga bog'liq edi — endi germetik.

## 0.7 ga yo'l — bajarilgan bosqichlar

- **B0 — regressiya to'ri:** hisobot formatlari `tests/fixtures/legacy/` da muzlatilgan
  (har bosqichdan eng eski, eng yangi va topilmasi eng ko'p hisobot), shakl va API shartnomasi
  testlar bilan qo'riqlanadi. `tests/make_legacy_fixtures.py` va `tests/freeze_report_shape.py`
  ularni qayta yaratadi.
- **B1 — barqaror topilma identifikatori:** har bir topilma endi `fingerprint` maydoniga ega
  (`zanjir/findings.py`). Model DefectDojo'ning `HASHCODE_FIELDS_PER_SCANNER` yondashuvidan
  olingan: har bir skaner uchun identitetni tashkil etadigan maydonlar ro'yxati. Ikkita qoida
  farq qiladi — **qator raqami hech qachon identitetga kirmaydi** (fayl boshiga qator
  qo'shilganda topilma "yangi" bo'lib ko'rinmasligi uchun; o'rniga qatorning
  bo'shliqlari normallashtirilgan matni ishlatiladi), va **yetmagan maydon xato**, boshqa
  xesh emas. SARIF eksportida `partialFingerprints` endi barcha bosqichlarda bor, ya'ni
  GitHub/GitLab o'zgarmagan topilmani har skanda yangi deb ko'rsatmaydi.
  Mavjud `id` maydonlari o'z nomi va qiymati bilan qoladi.
- **B2 — topilma hayotiy sikli:** qarorlar endi hisobotga emas, **loyiha + topilma
  identifikatoriga** bog'lanadi (`zanjir/triage.py`), shuning uchun qayta skandan keyin ham
  qoladi. Holatlar: `investigating`, `confirmed`, `fix_planned`, `false_positive`,
  `accepted_risk`, `fixed`. Har bir o'zgarish alohida audit yozuvi yaratadi.
  Ochiq topilmaga og'irligiga qarab muddat beriladi (Critical 7 / High 30 / Medium 90 /
  Low 120 kun — DefectDojo standarti); baholanmagan og'irlikka muddat berilmaydi va
  muddatlar hech qachon bitta ballga aylantirilmaydi.
  API: `POST /api/triage`, `POST /api/triage/bulk`, `GET /api/triage/<loyiha>`.
  Eski review'lar `python3 migrate_triage.py` bilan ko'chiriladi — manba fayllar
  o'chirilmaydi va o'zgartirilmaydi.
- **B3 — baseline va ishlatib bo'ladigan CI gate:** `zanjir/baseline.py` ikkita skanni
  topilma identifikatori bo'yicha solishtiradi (`new` / `gone` / `unchanged`).
  `ci_gate.py` ga uchta yangi bayroq qo'shildi — **standart xulq o'zgarmagan**:
  `--baseline <ID|last-green>`, `--fail-on any|new|new-high|new-critical`,
  `--respect-triage`. Shu bilan mavjud loyihada gate birinchi kundanoq qizil bo'lmaydi,
  lekin eski topilmalar yashirilmaydi (`total` maydonida ko'rinadi).
  Uchta halollik qoidasi: asos faqat **tugagan** skan bo'la oladi; identifikatorsiz
  topilma doim sanaladi (uni eski deb isbotlab bo'lmaydi); **yo'qolgan topilma hech qachon
  "tuzatilgan" deb atalmaydi**. Asos topilmasa gate 2 kod bilan to'xtaydi.
  Har bir hisobot ko'rinishida "oldingi tugagan skanga nisbatan" qatori bor.
  Bir fayl-bir qatorda ikki skaner topgan narsa `duplicate_of` bilan **bog'lanadi**,
  birlashtirilmaydi — dalil yo'qolmaydi.
- **B4 — aktivlar grafi va yangi zanjirlar:** `zanjir/chain_secrets.py` → `zanjir/chains.py`.
  Image nishonlari Compose xizmatlariga bog'lanadi (avval loyiha ta'rifidagi `service`,
  bo'lmasa image nomi bo'yicha; moslik topilmasa **taxmin qilinmaydi**, "bog'lanmagan"
  yoki "noaniq" deb yoziladi). Ikki yangi zanjir:
  **SX-002** — tashqariga ochiq xizmat + uning image'ida CISA KEV ro'yxatidagi yoki
  CRITICAL CVE; **SX-003** — o'sha, ustiga debug rejimi (RP-006) va tuzatilgan versiya
  allaqachon mavjud. Teglar: CWE-1395 + CWE-668 → A03 + A01.
  Image hisobotlari endi CISA KEV va FIRST EPSS bilan boyitiladi
  (`known_exploited: null` — tekshirilmagan, "xavfsiz" emas).
  Tekshirib bo'lmagan narsa `chain_gaps` da yoziladi — bog'lanmagan image, olinmagan KEV
  ro'yxati, tanlanmagan bosqich. **"Tekshirilmadi" va "topilmadi" hech qachon bir xil
  ko'rinmaydi.**
- **B5 — IaC, SBOM va uchta nginx qoidasi:** yangi **`iac`** bosqichi (`zanjir/iac.py`) Trivy
  `config` rejimida Dockerfile, Kubernetes, Terraform, CloudFormation, Helm va ARM fayllarini
  tekshiradi — yangi bog'liqliksiz, kod skaneri bilan bir xil faqat-o'qish nusxasi ustida.
  **Standart holatda tanlanmagan:** `iac_target` ixtiyoriy maydon, shuning uchun mavjud
  chaqiruvlar o'zgarmaydi. CWE xaritada bo'lmagan tekshiruv o'z ID si bilan ko'rsatiladi va
  hech qanday OWASP toifasiga taxmin qilinmaydi.
  **CycloneDX 1.6 SBOM** (`zanjir/sbom.py`): `GET /api/images/reports/<id>/sbom` va loyiha
  bo'yicha `GET /api/images/sbom?project=<id>`. SBOM image'ni qayta skanerlamaydi — u
  topilmalar bilan bir xil Trivy dalilidan quriladi. Paket ro'yxati yo'q eski hisobot uchun
  bo'sh SBOM emas, **sababi bilan xato** qaytadi.
  **Yangi nginx qoidalari:** RP-009 (`location` + `alias` yo'l chegarasidan chiqishi, CWE-22),
  RP-010 (`proxy_pass` so'rovchi boshqaradigan o'zgaruvchidan — SSRF, CWE-918),
  RP-011 (ichki `add_header` yuqoridagi xavfsizlik sarlavhalarini bekor qiladi, CWE-693).
- **B7 — SIEM darajasidagi ish markazi:** yangi **Topilmalar** ekrani barcha skanerlarning
  barcha topilmasini bitta jadvalda ko'rsatadi (`zanjir/findings_index.py`): og'irlik,
  skaner, loyiha, OWASP/CWE, CISA KEV, EPSS, triage holati, SLA muddati, birinchi/oxirgi
  ko'rilgan. Filtrlar manzilda saqlanadi, ko'p topilmani birdan triage qilish mumkin,
  yon panelda dalil, zanjir bog'lanishi, qaror formasi va qaror tarixi bor.
  Yangi **Loyiha sahifasi** bitta loyihaning barcha qatlamlarini, trendini va
  tekshirilmagan joylarini bir ekranda beradi.
  Chap menyu guruhlandi, yuqorida buyruq paneli va global qidiruv, klaviatura yorliqlari
  (`/`, `g t`, `g l`, `?`), qorong'u rejim va telefon kengligida ishlash qo'shildi.
  Oynalar: nishon qo'shish, sozlamalar (NVD kaliti), eksport markazi.
  **Chegara saqlandi:** manba papkasini brauzerdan ro'yxatga olish standart holatda
  o'chirilgan (`--allow-registration` bilan yoqiladi) — brauzerga ixtiyoriy fayl yo'lini
  berish serverga butun diskni o'qishga yo'l ochadi.
  React yoki qurish bosqichi kiritilmadi; CSP `script-src 'self'; style-src 'self'`
  o'zgarmadi va buni test qo'riqlaydi.
- **B6 — haqiqiy serverlar:** image endi **teg** bilan ham, **shaxsiy registry** bilan ham
  ro'yxatga olinadi (`registry.example.com:5000/jamoa/app:1.0`); teg pinned hisoblanmaydi va
  har bir skan aynan qaysi digest tekshirilganini yozadi. **Masofaviy git repozitoriysi**
  (`zanjir/remote_source.py`) har skan uchun vaqtinchalik sayoz nusxaga olinadi, commit
  qayd etiladi va nusxa skandan keyin o'chiriladi; hook'lar o'chirilgan, hech qanday kod
  bajarilmaydi. Web nishonida **TLS holati** (protokol, shifr, subject/issuer, muddat va
  qolgan kun) qayd etiladi, **autentifikatsiyali nishon** qo'llanadi va so'rovlar orasidagi
  kechikishni sekinlashtirish mumkin.
  **Hech qanday parol yoki token loyihada saqlanmaydi.** Registry uchun
  `THREATCHAIN_REGISTRY_<HOST>_USERNAME/…_PASSWORD`, web uchun `THREATCHAIN_WEB_AUTH_<ID>` —
  qiymat faqat jarayon muhitidan o'qiladi, hisobotda esa faqat **o'zgaruvchi nomi** ko'rinadi.
  Login tashigan git URL'i (`https://user:token@host/...`) rad etiladi, `ext::` va `file://`
  transportlari ham.
  Chegarada qoladi: masofaviy Docker daemon, SSH orqali host skani va agent.

## 0.6 dagi o'zgarishlar

- **Faqat online rejim:** kutubxonalar (SCA) tekshiruvida "faqat inventar" (offline) rejimi olib tashlandi — har bir skan doim OSV, CISA KEV, NVD va EPSS orqali internetga ulanadi. Sun'iy "Lokal demo" (TB-001) ssenariysi butunlay o'chirildi; qolgan barcha bo'limlar (Repository, Kod va sirlar, CVE va kutubxonalar, Sayt va API, Docker image) haqiqiy loyiha/nishonlar ustida ishlaydi.
- **CWE va OWASP Top 10:2025 teglash:** har bir topilma (Semgrep, Gitleaks, OSV/NVD, Trivy, Nuclei, HTTP sarlavha tekshiruvi, Compose/Nginx qoidalari) endi mumkin bo'lgan joyda aniq `CWE-XXX` identifikatori va unga mos OWASP Top 10:2025 kategoriyasi (`A01`–`A10`, 2026-yil yanvarda chiqqan — 2021'dan keyingi birinchi rasmiy yangilanish) bilan belgilanadi. Xarita `zanjir/taxonomy.py` da, to'g'ridan-to'g'ri MITRE CWE kategoriya sahifalaridan (cwe.mitre.org, CWE-1436–1445) olingan va **o'sha o'nta toifaning barcha 249 a'zosini to'liq qamrab oladi** (2026-09-25 da sahifalarga qayta solishtirildi; CWE-1450 — "Weaknesses in OWASP Top Ten RC1 (2025)" ota-ko'rinishi, a'zo emas, shuning uchun xaritaga kirmaydi). Jadvalda yo'q CWE hech qachon kategoriyaga "taxmin" qilinmaydi (masalan CWE-400 va CWE-1333 tekshirilib, hech qaysi 2025 toifasiga a'zo emasligi aniqlandi).
- **Kengaytirilgan tahdid bazalari:** OSV.dev + CISA KEV'dan tashqari endi [NVD](https://nvd.nist.gov/) (CWE bo'shliqlarini to'ldirish uchun, so'rov cheklovi hisobga olingan holda) va [FIRST.org EPSS](https://www.first.org/epss/) (ekspluatatsiya ehtimoli foizi va persentili) ulandi — `zanjir/threatfeeds.py`.
- **"Tasdiqlangan / qo'lda tekshirish kerak" klassifikatsiyasi:** har bir topilmada aniq `verified` (yoki eski nomi bilan `runtime_verified`) bayrog'i bor. `true` — nishon bilan haqiqiy tarmoq muloqoti orqali bevosita kuzatilgan (masalan real HTTP javobi); `false` — statik/baza mosligi, mutaxassis tomonidan qo'lda tasdiqlanishi shart. Har bir hisobotda va "Umumiy tekshiruv" pipeline'ida jamlangan `verification_summary` (`confirmed_by_evidence` / `manual_review_required`) mavjud — mantiq `zanjir/verification.py` da.
- Web/image tekshiruvlari uchun oldingi "online" ruxsat katakchasi (haqiqiy tarmoq so'roviga ochiq rozilik) o'zgarishsiz qoldi — bu offline rejim emas, balki har bir faol tarmoq harakati uchun ongli tasdiq.
- **ThreatChain yadrosi — RP-004 (yangi):** Compose/Nginx tahlilchisi endi "gateway ishonch sarlavhasi (masalan `X-User`) to'g'ri uzatilgan + backend porti ham to'g'ridan-to'g'ri ochiq" kombinatsiyasini aniqlaydi — bu ikkala tomon alohida "to'g'ri" bo'lgan holatda paydo bo'ladigan autentifikatsiya-chetlab-o'tish zanjiri (`CWE-290` → `A07:2025`). Bu o'chirilgan sun'iy demo (TB-001)ning g'oyasini haqiqiy konfiguratsiya ustida qayta tiklaydi.
- **Faol DAST kengaytmasi (yangi):** "Sayt va API" bo'limi endi 6 ta Nuclei shabloni bilan bir qatorda: (1) bir manbadagi sahifalar bo'ylab cheklangan chuqurlikdagi (`GET`, ~16 sahifa, chuqurlik 2) xavfsiz bosib chiqish; (2) CORS — sinov `Origin` sarlavhasi ko'r-ko'rona aks ettirilib, `Access-Control-Allow-Credentials: true` bilan kelayotganini aniqlash (`CWE-942` → `A02`); (3) cookie `Secure`/`HttpOnly` bayroqlari yo'qligi (`CWE-614`/`CWE-1004` → `A02`); (4) server/texnologiya versiyasi sarlavhada oshkor qilinishi (`CWE-200` → `A01`); (5) server xatosi (5xx) javobida stek-iz/texnik tafsilot naqshi borligi, qiymatning o'zi hisobotga kiritilmaydi (`CWE-209` → `A10`). Barchasi GET-only, mavjud ruxsat/tezlik chegaralari (2 so'rov/soniya, 48 so'rov, 64 KiB/javob, 180 s) doirasida; in'ektsiya (SQLi/XSS), autentifikatsiya va biznes-mantiq sinovlari hali yo'q.
- **ThreatChain yadrosi — RP-005 (yangi):** Compose tahlilchisi endi tarmoq segmentatsiyasi yo'qligidan kelib chiqadigan zanjirni aniqlaydi — host portidan ochiq xizmat (masalan web frontend) va ma'lumotlar bazasi/keshga o'xshash ichki xizmat (image nomi bo'yicha aniqlanadi: Postgres, MySQL, MongoDB, Redis va h.k.) bitta Docker tarmog'ida (odatda Compose'ning standart tarmog'i) turganda. Ikkala tomon alohida to'g'ri: xizmatni ochish ham, standart tarmoqdan foydalanish ham odatiy holat; birgalikda esa — ochiq xizmat buzilsa, gateway autentifikatsiyasisiz ichki bazaga to'g'ridan-to'g'ri Docker DNS orqali yetish mumkin (`CWE-668` → `A01:2025`). Faqat host porti loopback bo'lmagan holatlarda ishga tushadi — shuning uchun barcha portlari `127.0.0.1`ga bog'langan haqiqiy crAPI namunasida (yuqoridagi "5 tasi loopback" holati) bu qoida chiqmaydi; sun'iy `0.0.0.0` portli demo loyihada esa to'g'ri ishlab tasdiqlandi.
- **ThreatChain yadrosi — RP-006 (yangi):** Compose tahlilchisi endi debug/dev muhiti (`DEBUG`, `FLASK_DEBUG`, `DJANGO_DEBUG`, `NODE_ENV=development`, `ASPNETCORE_ENVIRONMENT=Development`, `SPRING_PROFILES_ACTIVE=dev` va h.k.) yoqilgan xizmat host portidan ham to'g'ridan-to'g'ri ochiq bo'lgan holatni aniqlaydi. Ikkalasi alohida to'g'ri: debug rejimi lokal ishlab chiqish uchun odatiy, portni ochish alohida qaror; birgalikda esa — debug rejimi ko'pincha batafsil xato sahifasi, interaktiv konsol yoki qo'shimcha ichki yo'llarni yoqadi, ular endi tashqi tarmoqdan ham yetkaziladi (`CWE-489` → `A02:2025`). `NODE_ENV=production` kabi ishlab chiqarish qiymatlari qasddan chetlab o'tiladi — faqat "development/dev/true/1/yes/on" kabi aniq debug qiymatlarida ishga tushadi.
- **ThreatChain yadrosi — RP-007 va RP-008 (yangi, konteyner imtiyozi zanjiri):** Ikkalasi ham "kengaytirilgan konteyner imtiyozi + host portidan ochiqlik" naqshini qamraydi — CI runner yoki monitoring vositasiga shunday imtiyoz kerak bo'lishi, portni ochish esa alohida ops qarori bo'lishi mumkin, lekin birgalikda xizmat buzilganda butun xostga chiqish yo'li ochiladi: **RP-007** — Docker socket (`/var/run/docker.sock`) konteyner ichiga ulangan va shu xizmat host portidan ham ochiq (daemon/root darajasidagi Docker API nazorati qo'lga kiritiladi); **RP-008** — `privileged: true` yoki xavfli `cap_add` (`SYS_ADMIN`, `SYS_PTRACE`, `NET_ADMIN` va h.k., `NET_BIND_SERVICE` kabi oddiy capability'lar chetlab o'tiladi) bilan bir qatorda host portidan ochiqlik. Ikkalasi ham `CWE-269` (Improper Privilege Management) → `A06:2025`, `error` darajasida — bu ikki qoida boshqalarga qaraganda jiddiyroq, chunki natija konteyner chegarasidan chiqib xost darajasiga yetish.
- **Cross-skaner zanjiri — SX-001 (yangi):** "Umumiy tekshiruv" bo'limiga 5-chi mustaqil bosqich — **Repository (Compose)** — qo'shildi. Ikkala bosqich (Kod/Gitleaks va Repository) tanlanib tugagach, `zanjir/chain_secrets.py` ularni birlashtiradi: agar bir xizmatning manba katalogida (Compose `build.context`) Gitleaks haqiqiy sir mosligini topsa VA aynan shu xizmat host portidan to'g'ridan-to'g'ri ochiq bo'lsa (`RP-001` sharti) — bu ikki mustaqil skaner natijasi bitta `SX-001` topilmaga birlashtiriladi. Ikkalasi alohida to'g'ri: kodda test/dev qiymati qolishi va portni ochish alohida hodisalar; birgalikda — bu xizmat boshqa yo'l bilan (masalan RP-004/006/007/008 zanjirlaridan biri) buzilsa, sir darhol qo'lga tushadi. Ikki qatlamli CWE (`CWE-798` + `CWE-668` → `A07:2025` + `A01:2025`) bilan teglanadi, `secret_value` hech qachon ko'chirilmaydi. **crAPI'da chiqmaydi** — bundle qilingan namuna barcha xizmatlar uchun tayyor `image:` ishlatadi, `build:` yo'q; sun'iy `build:`li demo loyihada **real Gitleaks** bilan uchidan-uchigacha tasdiqlandi (soxta Stripe kaliti + ochiq port → SX-001 to'g'ri chiqdi).
- **Barcha 4 ta skaner vositasi endi macOS/Linux'da ham ishlaydi (muhit tuzatishi):** `.tools/` to'liq Windows uchun ta'minlangan edi (`gitleaks.exe`, `semgrep/Scripts` venv, `trivy.exe`, `nuclei.exe`) — boshqa platformada barchasi `OSError` bilan tugallanmasdi. Endi `zanjir/scanners.py`, `zanjir/images.py` va `zanjir/webscan.py` platformani aniqlaydi va mos vositani tanlaydi: Windows'da o'zgarishsiz eski yo'llar, POSIX'da `.tools/<vosita>/posix/...` ostida alohida vendorlangan (rasmiy relizdan SHA-256 tekshirilgan) macOS/Linux binari — hech biri tashqi tizim PATH'iga yoki Homebrew Cellar'iga tayanmaydi. `setup_tools.py` (Trivy) va `setup_nuclei.py` ham platformaga qarab to'g'ri arxiv nomini tanlab, xuddi shu rasmiy checksum-tekshiruv orqali o'rnatadi. `zanjir/readiness.py`dagi "O'rnatilganmi?" tekshiruvi ham eski qattiq yozilgan Windows yo'lidan haqiqiy joriy platforma binariga o'tkazildi (avval bu tekshiruv ishlamaydigan eski faylni "O'rnatilgan" deb noto'g'ri ko'rsatardi). Qo'shimcha: Semgrep uchun Unix socket yo'l uzunligi tekshiruvi (`sun_path` limiti) endi faqat Windows emas, barcha platformada (macOS uchun 104 bayt, boshqalarda 108) ishlaydi. `pilot_tls.py`dagi sinov TLS sertifikatlariga `SubjectKeyIdentifier`/`AuthorityKeyIdentifier` kengaytmalari qo'shildi — ularsiz zamonaviy OpenSSL (3.2+, macOS'da standart) "Missing Authority Key Identifier" xatosi bilan zanjirni rad etardi.
- **Docker aniqlash tuzatildi (`pilot.py`):** `docker_prefix()` ilgari joriy Docker context nomini OS bo'yicha taxmin qilar edi (`'default'` yoki `'desktop-linux'`) — bu Docker Desktop uchun ishlaydi, lekin colima, OrbStack va boshqa sozlamalarda context boshqa nomda bo'lib, aslida yashab turgan daemon'ga emas, ishlamaydigan bo'sh `'default'` context'ga ulanishga urinib xato berardi. Endi `docker context show` orqali CLI'ning haqiqiy joriy context'i so'raladi, so'ng xuddi avvalgidek faqat lokal (`unix://`/`npipe://`) endpoint qabul qilinadi. `colima` bilan real docker o'rnatib, butun Docker-bog'liq zanjirni (crAPI lab: `pilot.py prepare/pull/start`, TLS nazorat tajribasi: `pilot_tls.py run`, jonli crAPI'ga qarshi Nuclei skani) uchidan-uchigacha tasdiqladim — jonli crAPI'da haqiqiy **HIGH** darajali `.env` fayli ochiqligi topildi (`verified: true`, HTTP 206).
- **CI/CD Quality Gate (yangi):** butun "Umumiy tekshiruv" quvuri endi interfeyssiz, bitta buyruq bilan ishga tushadi va CI'ni to'xtatadigan chiqish kodi qaytaradi — `python ci_gate.py --target <manba> --repository-target <compose> [--web-target ...] [--image-target ...] --allow N`. Chiqish kodi: `0` — gate o'tdi, `1` — gate to'xtatdi, `2` — skan umuman bajarilmadi (noto'g'ri nishon yoki vosita xatosi; bu "toza natija" deb hisoblanmaydi). **Hech qanday aralash "xavfsizlik foizi" hisoblanmaydi** — loyihaning boshqa joylaridagi tamoyil bilan bir xil: gate faqat aniq nomlangan shartlarni sanaydi (`zanjir/ci_gate.py`): repository topilmasi `level == 'error'` (ya'ni RP-004/007/008 — natijasi autentifikatsiyani chetlab o'tish yoki xost darajasiga chiqish bo'lgan zanjirlar), `dependencies`/`images` topilmasi `CRITICAL`/`HIGH`, `web` topilmasi `HIGH`, va har qanday cross-skaner zanjir topilmasi (SX-00X — bular allaqachon ikki mustaqil faktning kamdan-kam uchraydigan birikmasi, shuning uchun bittasi ham e'tiborga loyiq). `--allow N` mavjud texnik qarzni bosqichma-bosqich kamaytirish uchun: birinchi ishga tushirishda joriy sonni o'lchab shuni qo'ying, keyin asta 0 ga tushiring. Amalda tekshirildi: crAPI repository profilida SARIF'da 6 topilma chiqdi, lekin barchasi `warning` darajasida (loopback portlar) — gate to'g'ri o'tkazdi; to'liq crAPI quvurida esa 135 gate-relevant topilma sanalib, `--allow 100` bilan chiqish kodi 1 qaytdi.
- **SARIF 2.1.0 eksporti (yangi):** `zanjir/sarif_export.py` butun quvur hisobotini — beshala bosqich (`code`, `repository`, `dependencies`, `images`, `web`) va cross-skaner `chain_findings` — standart SARIF 2.1.0 formatiga o'giradi, har bir bosqich alohida `run` sifatida, CWE teglari va (kod bosqichida) fayl/satr joylashuvi bilan. Bu GitHub Code scanning, GitLab va boshqa SARIF tushunadigan tizimlarga to'g'ridan-to'g'ri yuklanadi, ya'ni topilmalar PR'da aynan o'sha satrda ko'rinadi. Ikki yo'l bilan olinadi: CLI'da `ci_gate.py --sarif-out`, interfeysda esa "Umumiy tekshiruv" natijasi yonidagi **SARIF (CI/CD) ↓** havolasi (`GET /api/assessments/reports/<id>/sarif`). Tayyor CI namunalari: [`ci-examples/github-actions.yml`](ci-examples/github-actions.yml) (SARIF'ni `github/codeql-action/upload-sarif` orqali yuklaydi) va [`ci-examples/gitlab-ci.yml`](ci-examples/gitlab-ci.yml). DAST (`--web-target`) namunalarga qasddan kiritilmagan — u haqiqiy tarmoq so'rovi yuboradi va faqat yozma ruxsat berilgan nishonga qarshi qo'shilishi kerak.
- **SAST chuqurligi va til qamrovi — rasmiy Semgrep qoida bazasi (yangi):** loyihaning lokal qoidalari ustiga endi `semgrep/semgrep-rules` omboridan **pinlangan commit'dagi** rasmiy `security` toifasidagi qoidalar qo'shiladi — `python3 setup_semgrep_rules.py` bitta arxivni yuklab, har bir faylni YAML sifatida tekshiradi, SHA-256 bilan manifestga yozadi va `scanner-rules/semgrep-registry/` ga o'rnatadi. Natija: **7 qoida / 5 til → 1350 qoida / 22 til** (bash, C, C#, Clojure, Dockerfile, Go, HTML, Java, JavaScript, JSON, Kotlin, OCaml, PHP, Python, Ruby, Rust, Scala, Solidity, Terraform, TypeScript, YAML, generic). Terraform/Kubernetes/Dockerfile qoidalari orqali **IaC qamrovi** ham qo'shildi. Paket **ixtiyoriy** — o'rnatilmagan bo'lsa skan avvalgidek faqat lokal qoidalar bilan ishlaydi. Har bir skandan oldin manifest qayta tekshiriladi: qoida fayli o'zgargan yoki o'chirilgan bo'lsa skan to'xtaydi (qoida fayli skan nimani topa olishini belgilaydi, shuning uchun jimgina o'zgarishi qamrovni jimgina qisqartirardi). Amalda tasdiqlandi: crAPI'da Semgrep topilmalari **6 → 134** ga chiqdi, **134/134** da CWE bor, 117 tasi OWASP 2025 toifasiga bog'landi (qolgan 17 tasining CWE'si MITRE jadvalida hech bir 2025 toifasiga a'zo emas — taxmin qilinmaydi), skan vaqti ~39 s.
  - **Topilma matni skaner chiqishidan emas, qoida faylidan olinadi.** Semgrep o'z `extra.message` maydoniga mos kelgan kod parchasini (masalan funksiya nomi yoki literal qiymat) qo'shib yuboradi — bu tekshirilayotgan loyihadan hisobotga, jumladan haqiqiy sir qiymatini olib chiqishi mumkin edi. Shuning uchun matn SHA-256 bilan tasdiqlangan qoida faylining o'z yozuvidan o'qiladi; hisobotda `$CONTAINER` kabi o'rin egallovchi ko'rinib turishi aynan shu himoyaning dalili.
  - **OWASP toifasi har doim loyihaning o'z MITRE'dan olingan jadvali orqali chiqariladi**, rasmiy qoidaning o'z `owasp` maydonidan emas — barcha skanerlarda bitta manba saqlanadi.
  - **Qoida darajasi (`ERROR`/`WARNING`/`INFO`)** endi topilmada saqlanadi, interfeysda rangli belgi sifatida ko'rinadi va ro'yxat eng jiddiylari yuqorida turadigan qilib tartiblanadi; SARIF'ga ham `error`/`warning`/`note` sifatida o'tadi.
  - **CI gate'ga `code` bosqichi qo'shildi:** har bir Gitleaks mosligi (manbadagi ochiq sir merge qilinmaydi) va Semgrep `ERROR` darajasidagi topilmalar gate'ni to'xtatadi; `WARNING`/`INFO` qasddan kiritilmagan — haqiqiy loyihada ular yuzlab bo'ladi va doim to'xtaydigan gate'ni hech kim o'qimaydi. crAPI'da: 135 → **163** gate-relevant topilma (18 Semgrep `ERROR` + 10 Gitleaks), ular orasida omborga kiritilgan **private key'lar**, root bilan ishlaydigan **Dockerfile'lar** va Postman to'plamidagi **JWT token'lar**.
  - **Yaxlitlik cheklovi ochiq aytiladi:** commit SHA qattiq pinlanadi va har bir fayl uchun SHA-256 hamda mustaqil qayta tekshirish uchun `raw.githubusercontent` havolasi manifestda saqlanadi, lekin arxiv baytlari oldindan ma'lum xesh bilan solishtirilmaydi va reliz imzosi tekshirilmaydi — bu loyihadagi Trivy/Nuclei o'rnatuvchilari bilan bir xil daraja, undan yuqori kafolat da'vo qilinmaydi. Apex qoidalari qasddan chiqarib tashlangan: OSS Semgrep Apex'ni umuman parse qila olmaydi, ular faqat o'zgarmas xato shovqini berardi.
  - **Tahlil xatolari endi turi bo'yicha taqsimlanadi** (`error_kinds`) — yalang'och son o'rniga "qaysi turdagi qamrov bo'shlig'i" ko'rinadi. crAPI'da 36 ta `Other syntax error` — bular Helm shablon fayllari (`deploy/helm/templates/...`), ular sof YAML emas; bu haqiqiy qamrov bo'shlig'i, shuning uchun bosqich halol ravishda `partial` holatida qoladi.
- **O'z qoidalaringiz:** loyihangizga xos naqshni qo'shsangiz, keyingi har bir kod tekshiruvida u 29 ta lokal va ~1343 ta rasmiy qoida bilan birga ishlaydi. Saqlash joyi `scanner-rules/local/`, mantiq `zanjir/custom_rules.py`, API `GET /api/rules` va `POST /api/rules/{validate,save,delete}`. **Web sahifadagi qoida muharriri 0.7 da olib tashlandi** (kundalik ishda ishlatilmasdi va sahifani og'irlashtirardi) — qoidalar endi faylga yozib yoki shu API orqali qo'shiladi; tekshirish mantig'i va cheklovlari o'zgarmadi.
  - **Faqat deklarativ Semgrep YAML qabul qilinadi — bu chegara qasddan qo'yilgan.** Python mantiqidagi zanjir qoidalari (RP-00X, SX-00X) **hech qachon** web orqali qo'shilmaydi: ular dastur kodi, va ularni HTTP orqali qabul qilish xavfsizlik vositasining o'ziga ixtiyoriy kod bajarish yo'lini ochardi. **Nuclei shablonlari ham qabul qilinmaydi:** shablon real tarmoq so'rovi yuboradi, ya'ni oddiy matn maydoni interfeysga ixtiyoriy hostga trafik yo'naltirish imkonini berardi — bu "Sayt va API" bo'limidagi yozma ruxsat modelini talab qiladi, matn maydonini emas.
  - **Ishonch chegarasi ochiq aytiladi:** server faqat localhost'ga bog'langan va cross-site so'rovlarni rad etadi, shuning uchun bu endpoint'ga yeta oladigan kishi allaqachon skanerlash uchun loyiha papkasini ro'yxatdan o'tkaza oladi. Quyidagi tekshiruvlar masofaviy hujumchidan himoya emas — ular noto'g'ri qoidaning skan natijasini jimgina buzishining oldini oladi.
  - **Har bir qoida ikki marta tekshiriladi:** (1) strukturaviy — `id` noyobligi va xavfsiz belgilar, `message`, `languages` (faqat OSS engine parse qila oladigan tillar), `severity`, kamida bitta naqsh kaliti, YAML alias/anchor va chuqurlik/hajm chegaralari; manba faylini o'zgartiradigan (`fix`, `fix-regex`) va engine sozlamasiga tegadigan (`options`, `join`, `r2c-internal-*`) kalitlar rad etiladi, noma'lum kalit jimgina e'tiborsiz qoldirilmaydi; (2) **Semgrep'ning o'z qoida parseri** (bo'sh papka skani, internetsiz) — naqsh haqiqatan parse bo'lishini faqat u biladi.
  - **`metadata.cwe` majburiy.** CWE'siz topilma hisobotga CWE'siz va OWASP toifasisiz tushadi, bu loyiha esa keyinchalik toifani hech qachon taxmin qilmaydi — shuning uchun qoida yozishning o'zida talab qilinadi.
  - Topilma matni bu yerda ham qoida faylidan olinadi, Semgrep chiqishidan emas — rasmiy paketdagi bilan bir xil sir sizishidan himoya sababi.
  - Uchidan-uchigacha tasdiqlandi: brauzerdan yozilgan `pattern-regex` qoidasi sun'iy loyihada to'g'ri ishladi — `severity: ERROR`, `CWE-798` → `A07:2025`, xabar qoida faylidan; `fix` kalitli, CWE'siz, noto'g'ri `severity`/til va parse bo'lmaydigan naqshli variantlar esa aniq sabab bilan rad etildi.
- **Ko'p loyihali portfel ko'rinishi (yangi) — "Loyihalar" bo'limi:** barcha loyihalar va beshala qatlam bitta matritsada; har bir loyiha uchun vaqt bo'yicha o'zgarish. Mantiq `zanjir/portfolio.py`, API `GET /api/portfolio`, `GET /api/portfolio/trend`, `POST /api/portfolio/{register,remove}`.
  - **"Tekshirilmagan" — "toza" emas, va bu matritsaning asosiy qiymati.** Katak uch xil holatni **ajratib** ko'rsatadi, chunki faqat topilmalarni sanaydigan panelda tekshirilmagan loyiha eng yaxshi ko'rinadi: (1) tekshirilgan va topilma yo'q, (2) tekshirilgan, lekin tugamagan (`partial`/`failed` — qamrov bo'shlig'i bor), (3) **hech qachon tekshirilmagan**. Uchinchisida son `null` bo'lib qoladi, `0` emas — hech narsa o'lchanmagan. Ko'p nishonli bosqichda (masalan 9 ta image) tekshirilmagan nishonlar nomma-nom ko'rsatiladi: crAPI namunasida 9 ta image'dan faqat 3 tasi tekshirilgan ekan — buni oldin hech bir ko'rinish ko'rsatmasdi.
  - **Bu yerda ham umumiy ball yo'q.** Har bir bosqich o'z soni, o'z holati va o'z vaqti bilan alohida turadi; Trivy soni bilan Nuclei soni turli narsalarni o'lchaydi va ularni qo'shish mavjud bo'lmagan kattalikni ixtiro qilardi. Bitta test aynan shuni qo'riqlaydi — natija maydonlari orasida `score`/`ball`/`total` kabi kalit bo'lmasligini tekshiradi.
  - **Sonning kamayishi tuzatish dalili sifatida ko'rsatilmaydi.** Trend har bir nuqtada sonni **holati bilan birga** beradi va o'zgarish yo'nalishi haqida hech qanday xulosa chiqarmaydi — son tushishi tuzatishdan emas, qamrov qisqarganidan ham bo'lishi mumkin. Bu loyihaning "joriy hisobotda yo'qlik o'z-o'zidan tuzatish tasdig'i emas" tamoyilining davomi.
  - **Guruhlash aniq, taxminiy emas.** Loyihaning ID'si bosqichlar bo'yicha farq qilishi mumkin (crAPI: kod uchun `crapi-full`, Compose uchun `crapi`, web uchun `pilot-crapi`, har bir image uchun alohida ID). Guruh uch yo'l bilan hosil bo'ladi: bundled namuna, operator qo'lda bog'lagan guruh, yoki **aniq ID mosligi** — `app.py --register-project` bitta ID'ni kod, CVE va Repository ro'yxatlariga birdan yozgani uchun shunday qo'shilgan loyiha hech qanday qo'shimcha sozlashsiz paydo bo'ladi. O'xshash ko'ringan ID'lar (`shop` va `shop-web`) **hech qachon** o'z-o'zidan birlashtirilmaydi.
  - Diagramma kengligi CSS sinfi orqali beriladi, inline `style` orqali emas — `app.py` yuboradigan `style-src 'self'` CSP'si diagramma uchun bo'shatilmadi.
- **Zanjir qoidalari endi standart o'rnatmada ko'rinadi — `samples/chain-demo`:** bundle qilingan crAPI barcha xizmatlar uchun tayyor `image:` ishlatgani (`build:` yo'q) sababli cross-skaner zanjiri **SX-001 hech qachon chiqmasdi** — loyihaning asosiy farqini ko'rsatish uchun har safar qo'lda sun'iy loyiha yaratish kerak edi. Endi kichik sun'iy namuna bundled profil sifatida ham Repository, ham Manba kodi ro'yxatida turadi: `chain-demo` ni tanlash bilanoq **RP-001, RP-005, RP-006, RP-007, RP-008** va (ikkala bosqich birga tanlansa) **SX-001** chiqadi. Namunadagi kalit **soxta** — hech qachon amal qilmagan va bu uning `README.md`, fayl izohi hamda provenance yozuvida ochiq aytilgan; tekshirildi: kalit hisobot, SARIF va Markdown eksportlarining hech biriga tushmaydi, faqat `secret_value: "hidden"` saqlanadi. `tests/test_chain_demo_sample.py` namunaning o'zini qo'riqlaydi — `build:` olib tashlansa yoki port loopback'ga o'tkazilsa testlar yiqiladi, ya'ni farq jimgina ko'rsatilmaydigan bo'lib qolmaydi.
- **Kod topilmalari jadvali sahifalandi:** rasmiy qoida paketi crAPI skanini 6 dan 144 topilmaga olib chiqqani uchun jadvalga CVE bo'limidagi naqsh ko'chirildi — sahifada 25 qator, qidiruv maydoni va daraja filtri (`ERROR`/`WARNING`/`INFO`/darajasiz). Hisobot almashtirilganda sahifa nolga qaytadi.
- **Server eski kod bilan ishlayotgani endi ko'rinadi:** `/api/health` jarayon **yuklagan** kod xeshini, `/api/readiness` esa **diskdagi** joriy xeshni qaytaradi; ular farq qilsa boshqaruv panelida "serverni qayta ishga tushiring" ogohlantirishi chiqadi. Bu haqiqiy muammodan keyin qo'shildi — diskda allaqachon tuzatilgan SARIF marshruti eski jarayon sababli 404 qaytarib turgan va buni tashqaridan bilishning yo'li yo'q edi.
- **CLI shartnomalari mustahkamlandi:** `tests/test_cli_scripts.py` (13 test) ildizdagi 18 ta skriptni qo'riqlaydi — import bo'lishi, `zanjir.*` importlari mavjud modulga ishora qilishi, `--help` ishlashi va **ish bajarmasligi**, pipeline payload'i `pipeline.SELECTION_FIELDS` bilan aynan mos kelishi, eskirgan versiya/rejim satri qattiq yozilmaganligi. Shu jarayonda beshta jimgina buzilgan skript tuzatildi (`check_all.py`, `validate_pipeline.py`, `verify_pilot_api.py` — eskirgan import, yo'qolgan maydon, eskirgan konstanta) va beshta skriptga `argparse` qo'shildi: ularda u umuman yo'q edi, shuning uchun `validate_web.py --help` yordam o'rniga to'liq haqiqiy skanni ishga tushirardi. Bundan tashqari `check_dependencies.py`, `check_image.py`, `check_web.py`, `scan_code.py`, `ci_gate.py` da odamga mo'ljallangan satrlar `stderr` ga ko'chirildi — endi `script > out.json` to'g'ridan-to'g'ri parse qilinadi.
- **Yagona o'rnatish buyrug'i — `setup_all.py`:** yangi mashinada uchta alohida o'rnatuvchi ishga tushirish kerak edi va qaysi biri majburiy ekani aytilmagandi. Endi `python3 setup_all.py` uchalasini ketma-ket bajaradi va **har birining natijasini alohida** ko'rsatadi: bittasi yiqilsa qolganlari baribir o'rnatiladi va qaysi bosqich ishlamasligi aytiladi — yarim o'rnatilgan holat ham ishlaydigan holat (Trivy'siz ham kod va CVE tekshiruvlari to'liq ishlaydi). `--only` bilan tanlab, `--force` bilan qayta yuklash mumkin.
- **Tahlil qilinmagan fayllar endi nomma-nom va harakat bilan ko'rsatiladi:** ilgari kod bosqichida faqat "36 ta tahlil xatosi" degan raqam bor edi. Endi ular toifalarga ajratiladi va crAPI'dagi 36 tasining **hammasi** bitta ma'lum sabab ekani aniqlandi — `deploy/helm/templates/` ostidagi fayllar Helm (Go) shabloni, YAML emas, shuning uchun hech bir YAML tahlilchisi ularni o'qiy olmaydi. Interfeysda fayllar ro'yxati va bajariladigan harakat chiqadi: "`helm template` bilan render qilib, natijani alohida loyiha sifatida tekshiring". Toifa `/templates/` yo'li **va** fayl ichidagi `{{` bo'yicha aniqlanadi — papka nomi yolg'iz yetarli emas. Bosqich baribir `partial` holatida qoladi: o'qilmagan fayl haqiqiy qamrov bo'shlig'i va u hech qachon toza natija sifatida ko'rsatilmaydi.
- **Platforma tarmoqlanishi ikkala yo'nalishda test qilinadi:** `.tools/` bir vaqtda Windows va POSIX qurilmalarini saqlaydi, va oltita joy (to'rtta iste'molchi, ikkita o'rnatuvchi) binar qayerda turishi haqida kelishishi kerak. `tests/test_platform_paths.py` `sys.platform` ni almashtirib har bir tarmoqni qayta baholaydi va **o'rnatuvchi qayerga yozishi bilan skaner qayerdan izlashi bir xil fayl ekanini** tasdiqlaydi — bu jimgina ajralib ketadigan qism. Windows binarini macOS'da ishga tushirib bo'lmaydi va bu test bunday da'vo qilmaydi; u faqat yo'l mantiqini tekshiradi.
- **Image tekshiruvi yiqilganda sabab hisobotda ko'rinadi:** Trivy jurnali lokal qoladi (unda registr metadatasi bo'lishi mumkin), shuning uchun ilgari hisobotda faqat "tool.log ni tekshiring" degan yozuv bor edi — web interfeys bu faylni hech qachon ko'rsatmaydi, ya'ni bu bajariladigan maslahat emas edi. Endi jurnaldan aniq sabab ajratib olinadi: Trivy'ning o'z 10 daqiqalik chegarasidan oshishi, 1 GB hajm chegarasi, registrda digest topilmasligi, kirish rad etilishi yoki DNS xatosi. Har bir xabar "bu toza natija emas" deb aniq aytadi. Haqiqiy holatda topildi: crAPI'ning `crapi-chatbot` image'i aynan 10 daqiqalik chegaradan oshib yiqilgan.
- **Kutubxona qamrovi 3 ekotizimdan 8 taga kengaydi:** npm/PyPI/Go ustiga **Maven** (`gradle.lockfile`), **RubyGems** (`Gemfile.lock`), **Packagist** (`composer.lock`), **crates.io** (`Cargo.lock`) va Python'ning lock formatlari (`Pipfile.lock`, `poetry.lock`, `uv.lock`) qo'shildi. Sinovda 14 paketli namunadan **124 haqiqiy OSV topilmasi** chiqdi. **Faqat aniq versiya yozadigan formatlar o'qiladi** — `pom.xml`, `build.gradle`, `pyproject.toml` qasddan qamralmaydi, chunki ularda versiya diapazon yoki xossa bo'lishi mumkin va uni hal qilish uchun build vositasini ishga tushirish kerak bo'lardi; bu modul esa repository kodini hech qachon bajarmaydi. Taxmin qilingan versiya dalilga o'xshagan, lekin dalil bo'lmagan CVE mosligini berardi. Bunday fayllar endi aniq sabab bilan rad etiladi (`gradle_lockfile_missing`) va operator nima qilishni biladi: `./gradlew dependencies --write-locks`.
- **Trivy bazalari o'rnatish vaqtida oldindan yuklanadi:** ilgari Trivy zaiflik va Java bazalarini **skan byudjeti ichida** yuklardi, va katta Java image'da byudjet aynan shunga ketardi. Eng yomoni — skan o'sha payt to'xtatilsa baza keshga ham tushmasdi, ya'ni qayta urinish ham yordam bermasdi. `setup_tools.py` endi ikkalasini oldindan yuklaydi (~2 daqiqa, bir martalik). Natija: crAPI `identity` image'i **11 daqiqadan oshib yiqilish o'rniga 31 soniyada tugadi** — 711 topilma, 13 CRITICAL.
- **Qamralmaydigan tillar jimgina chetlab o'tilmaydi:** Apex qoidalari o'rnatishda chiqarib tashlanadi (OSS Semgrep uni parse qila olmaydi), lekin bu ilgari faqat kod izohida qolgan edi — Apex loyihasi interfeysda "tekshirilgan" bo'lib ko'rinardi. Endi boshqaruv panelida aniq yozuv bor. NVD kaliti yo'qligi ham shunday: chegara nima ekani va kalitni qayerdan olish yoziladi.
- **Apex (Salesforce) qamrovi — PMD:** OSS Semgrep Apex'ni parse qila olmaydi (pullik kengaytma kerak). Endi ochiq manbali **PMD 7.27.0** ning `category/apex/security.xml` to'plami ishlatiladi (`python3 setup_pmd.py`, Java kerak). PMD faqat loyihada `.cls`/`.trigger` fayl bo'lsa ishga tushadi. 10 ta qoida CWE → OWASP bilan bog'langan: SOQL injection (CWE-89), XSS (CWE-79), open redirect (CWE-601), CRUD/sharing buzilishi, shifrlanmagan endpoint, qattiq yozilgan kalit/credential. Hisobot matni qoidaga xos qat'iy yozuv — PMD o'z xabariga koddagi nomlarni qo'yishi mumkin, ular hisobotga tushmaydi.
- **Image hajm chegarasini operator ongli ravishda oshira oladi:** `python3 check_image.py --target X --max-size 2GB` (eng ko'pi 4 GB). Standart 1 GB o'zgarmaydi; oshirilgan chegara hisobotning o'zida yoziladi (`size_limit_raised`), vaqt byudjeti ham mutanosib o'sadi (10 daqiqa/GB). Yuqoriroq chegarada tasdiqlangan digest standart 1 GB skanida qayta tekshiriladi — chegarani aylanib o'tib bo'lmaydi. Diskda image + 1 GB joy bo'lmasa skan boshlanmaydi va sababini aytadi.
- **Toza nusxada barcha vositalar o'rnatiladi:** `setup_scanners.py` Semgrep (pinlangan, loyiha ichidagi venv) va Gitleaks'ni (rasmiy reliz, SHA-256) o'rnatadi — ilgari bu ikkisi uchun o'rnatuvchi yo'q edi. `setup_all.py` endi beshta o'rnatuvchini bajaradi.
- **Platforma tekshiruvi:** `python3 verify_platform.py` joriy OS da barcha vositalarni va haqiqiy skanlarni ishga tushirib, `validation-runs/platform-<os>.json` ga yozadi. Windows'da `VERIFY-WINDOWS.cmd`; GitHub'da `ci-examples/threatchain-self-test.yml` (Windows/Ubuntu/macOS).
- **Frontend/UX tuzatishlari:** (1) Repository dalil bloklari (masalan RP-002dagi fayl yo'li/port ma'lumoti) yonida endi aniq izoh bor — bu joylashuv dalili, parol/token kabi maxfiy qiymat emas; (2) CWE/OWASP teglashdan oldin olingan eski Docker image/CVE hisobotlarida "Tasdiqlash: 0/0" degan chalg'ituvchi ko'rsatkich o'rniga "N ta (eski format)" va tushuntirish chiqadi.

## 0.5 dagi yangi ish jarayoni

- **Umumiy tekshiruv:** Semgrep/Gitleaks → OSV/CISA KEV → ruxsatli web → Trivy. Manba, web va image mustaqil tanlanadi. Har bosqich holati, o‘z hisoboti va xeshi umumiy JSON/Markdown hisobotda saqlanadi. Turli skaner sonlari qo‘shilib “xavfsizlik foizi” chiqarilmaydi.
- **Sayt va API:** Nuclei 3.11.1, 2 ta rasmiy va 4 ta mahalliy qoida. `.git/config`, `.env`, ikki SQL backup nomi, ikki Compose nomi, API sxemasi va directory listing; qo‘shimcha HTTP himoya sarlavhalari. Bu butun Nuclei bazasi yoki barcha CVE uchun faol ekspluatatsiya emas.
- **Ruxsat doirasi:** `CHECK-WEB.cmd` aniq URL va mas’ulni qayd qiladi. Faqat GET, aniq origin/base path, soniyasiga 2 so‘rov, jami 32 so‘rov, javobdan 64 KiB. DNS tekshirilib IP ulanishlarga mahkamlanadi; HTTPS sertifikati va hostname tekshiriladi. Redirect kuzatilmaydi. Raw javob va sir qiymati eksport qilinmaydi.
- **Qayta tekshirish dalili:** haqiqiy Nuclei engine sun’iy zaif holatda 6 moslik, tuzatilgan holatda 0 moslik topdi. Bir xil 200 OK fallback javobida aniq fayl topilmalari chiqarilmadi; javobdagi sezgir mazmun alohida ogohlantirish va `partial` holat bilan saqlandi. Bu real kompaniya pentesti emas; interfeysda alohida “Nazorat dalili” deb belgilangan.

**2026-09-15 holati:** 14-sentabrda saqlangan natijalarda Semgrep, Gitleaks, OSV/KEV, Nuclei va Trivy ishlagan. Umumiy hisobot `partial`: kutubxona inventarida 6 qamrov bo‘shlig‘i, eski web hisobotida esa 2 javob cheklangan deb qayd etilgan. Bugun `206` javobini baholash tuzatildi va haqiqiy Nuclei bilan nazoratdan o‘tdi; eski dalillar o‘zgartirilmadi. Docker’ni agentdan boshqarish `Access denied` bilan cheklangan, crAPI porti hozir yopiq; real crAPI web qayta skani hali olinmagan. Tafsilot: **[DAVOM-2026-09-15.md](DAVOM-2026-09-15.md)**. Yakuniy sinov: **[PILOT-ACCEPTANCE.md](PILOT-ACCEPTANCE.md)**.

## Ertangi loyiha sinovi

1. Windows’da **START-PILOT.cmd** ni oching. Brauzer: **http://127.0.0.1:8766/**. Bitta Windows pilot serverini ishlating; uning terminalini yopmang. 8765 portdagi agent preview bilan adashmaydi.
2. **CHECK-PROJECT.cmd** ni ochib ruxsat berilgan loyiha papkasini kiriting. crAPI uchun Enter. Online rejim OSV ga faqat paket nomi, ecosystem va versiya yuboradi.
3. Sahifani yangilang. **CVE va kutubxonalar** va **Kod va sirlar** bo‘limlarida shu loyihani tanlang. Compose shart emas.
   Web uchun **CHECK-WEB.cmd** orqali ruxsatli URL kiriting. crAPI uchun Docker Desktop va **PILOT-START.cmd** orqali xizmatlarni yoqing. **Umumiy tekshiruv** bo‘limida barcha kerakli bosqichlarni birga boshlang. **PILOT-VERIFY.cmd** crAPI uchun shu jarayonni Windows terminalida boshlaydi; bir vaqtda ikki skan boshlamang.
4. Qamrov va baza sanasini ko‘ring; P1/P2 topilmalarini mutaxassis tekshirsin. CVE bo‘limida mas’ul, qaror va asos yoziladi. JSON, inventar va o‘qiladigan Markdown hisobotni saqlang.
5. Alohida branchda tuzatish kiriting, funksional test va qayta skan bajaring. Oldingi online hisobot bilan solishtiring. Joriy hisobotda yo‘qlik o‘z-o‘zidan tuzatish tasdig‘i emas.

Python 3.10+ kerak. Interfeys uchun Docker shart emas, lekin internet **doim** kerak: kutubxonalar (OSV/KEV/NVD/EPSS) va Trivy tekshiruvlari internetdan foydalanadi; offline/faqat-lokal rejim mavjud emas. START.cmd ushbu kompyuterdagi Python runtime’ni taniydi (macOS/Linux’da `python3 app.py` ishlatiladi).

NVD so‘rov cheklovi sekin (5/30s, kalitsiz). Tezroq CWE boyitish uchun ixtiyoriy `NVD_API_KEY` muhit o‘zgaruvchisini o‘rnating (https://nvd.nist.gov/developers/request-an-api-key). Ba’zi Python o‘rnatishlarida (masalan macOS’dagi python.org paketi) standart TLS sertifikat do‘koni to‘liq bo‘lmasligi mumkin — `pip install certifi` shuni avtomatik tuzatadi.

**Semgrep holati:** 2026-09-14 kungi Windows skanida Semgrep 1.176.1 va Gitleaks 8.30.1 muvaffaqiyatli tugagan: 6 + 10 kuzatuv. Agentning oldingi certificate-store xatosi boshqa bajarish muhitiga tegishli. Yangi loyiha uchun Windows’dan START-PILOT.cmd yoki SCAN-CODE.cmd orqali yangi skan oling. SCAN-CODE.cmd standart holatda crAPI uchun; boshqa loyiha interfeysdan tanlanadi. Defender yoki sertifikat tekshiruvi o‘chirilmaydi.

**crAPI nusxasi:** avval dastur ichidagi `work/repositories/crapi-stable`, keyin tarixiy tashqi nusxa tanlanadi. `ZANJIR_CRAPI_ROOT` berilsa aynan shu manba ishlatiladi; u topilmasa boshqa loyiha yashirin tanlanmaydi. `BUNDLE-CRAPI.cmd` yetishmagan fayllarni nusxalaydi, mavjud fayllarni o‘chirmaydi. O‘zgartirilgan faylga duch kelsa nusxa olishdan oldin to‘xtaydi; link/junction orqali nusxa olmaydi. Dastur papkasini ko‘chirish Python, skanerlar va Docker boshqa kompyuterda tayyor degani emas.

## Qamrov

| Vosita | Qamrov | Chegara |
|---|---|---|
| Semgrep | 29 ta mahalliy qoida (taint: buyruq/SQL injeksiyasi, deserializatsiya, SSTI, XSS, XXE; Python/JS/Java/Go/PHP) + rasmiy `semgrep-rules` security paketi (~1343 qoida, 22 til; `setup_semgrep_rules.py`, ixtiyoriy) + `scanner-rules/local/` dagi o‘z qoidalaringiz | Universal SAST emas; paket o‘rnatilmasa faqat 29 ta lokal qoida ishlaydi; Apex qamralmaydi; web orqali faqat deklarativ Semgrep YAML qabul qilinadi (Python zanjir qoidalari va Nuclei shablonlari emas) |
| Gitleaks | Joriy matn fayllaridagi sirlar | Git tarixi yo‘q; API hisobotida sir qiymati yashiriladi |
| OSV + CISA KEV | npm lock v1–v3, Python `==`, Go `require`; ustuvorlik | Java/Gradle va boshqa lock formatlari qamrov bo‘shlig‘i; tranzitiv/runtime to‘liqligi kafolatlanmaydi |
| Trivy 0.74.0 | Public Docker Hub image; digest; linux/amd64; 1 GB gacha | Private registry va faol hujum sinovi yo‘q; image bajarilmaydi |
| Nuclei 3.11.1 + HTTP | 6 qoida, cheklangan chuqurlikdagi bir manba crawler (~16 sahifa), CORS aks ettirish, cookie bayroqlari, fingerprint, xato oshkorligi | Login, autentifikatsiya, in’ektsiya (SQLi/XSS), barcha CVE, fuzzing, POST va tashqi callback yo‘q; IPv4 nishonlar |
| Repository | Compose + bog‘langan Nginx; fayl/satr dalillari | Cheklangan statik qoidalar |
| Lokal demo / TLS dalili | 6 sun’iy localhost ssenariysi; oldingi 4 TLS nazorat tajribasi | Real kompaniyaning pentesti yoki deploy tuzatilgani tasdig‘i emas |

Kod snapshotida Git tarixi, vendor/node_modules, binar va 1 MB dan katta fayllar yo‘q. Kutubxona adapteri 16 MB gacha manifest, jami 64 MB/500 manifest va 12 000 paket nusxasi bilan cheklangan. Xatolar va qo‘llanmaydigan formatlar toza natija deb ko‘rsatilmaydi.

P1 — KEV bog‘lanishi yoki kritik manba bahosi; biznesga ta’sirni alohida tekshiring. `matched_advisory_ids` aynan versiyaga mos kelgan OSV yozuvlarini saqlaydi; aliaslar qo‘shimcha bog‘lanishdir. Birinchi fixed versiyani ko‘r-ko‘rona o‘rnatmang: turli versiya shoxlari bo‘lishi mumkin.

## CLI

```text
python app.py
python check_dependencies.py --register my-app --repo C:\repos\my-app --name "My App"
python check_dependencies.py --target my-app
python scan_code.py --target my-app
python check_image.py --target pilot-crapi-web
python check_web.py --register my-staging --url https://staging.example.com --owner "Team" --authorized
python check_web.py --target my-staging
python check_all.py --target my-app --web-target my-staging --online
python ci_gate.py --target my-app --repository-target my-deploy --allow 0 --sarif-out threatchain.sarif
python setup_semgrep_rules.py
python setup_all.py          # barcha o‘rnatuvchilarni birdan
python verify_platform.py    # shu OS da hamma narsa haqiqatan ishlashini tekshirish
```

URL misoli o‘rniga haqiqiy ruxsatli manzilingizni kiriting. Lokal/intranet ro‘yxati uchun `--allow-private` kerak; link-local metadata manzillari har doim rad etiladi. Profilni almashtirish uchun yangi ID ishlating. Nuclei lokal o‘rnatilishi: `python setup_nuclei.py`; rasmiy release SHA-256 tekshiriladi. Reliz imzosini mustaqil tekshirish bajarilmagan. Template manbasi va xeshlari `scanner-rules/nuclei/manifest.json` da; rasmiy ikki template litsenziyasi shu papkada.

O‘z public image’ingiz: `python check_image.py --register my-image --image IMAGE@sha256:DIGEST`, so‘ng `python check_image.py --target my-image`. IMAGE/DIGEST haqiqiy Docker Hub nomi va 64 belgili digest bilan almashtiriladi. Tag (`latest`) va private registry qabul qilinmaydi. Trivy kerak bo‘lsa `python setup_tools.py` rasmiy relizni SHA-256 bilan tekshirib lokal o‘rnatadi; Sigstore imzosi tekshirilmaydi.

Compose/Nginx ro‘yxatga olish: `python app.py --register-project my-deploy --repo C:\repos\my-app --compose deploy/compose.yml`. Nginx mapping va oldingi versiya tafsilotlari README-0.3-ARCHIVE.md da; undagi offline cheklovlar tarixiy holatni bildiradi.

## Saqlangan haqiqiy natijalar

Test manbasining asosi: OWASP crAPI, commit `700f03d12a392d9e408260b4beae72ed02a4a1a4`. Ichki nusxadan olingan aniq kod snapshoti hisobot xeshi bilan ajratiladi; `.git`/`.github` ko‘chirilmagani sabab uni tarixiy to‘liq checkout bilan bir xil deb hisoblamang.

- Semgrep/Gitleaks: **485 matn fayli, 6 + 10 kuzatuv, ikkisi ham completed**. Hisobot: `scanner-runs/20260914T074638-5be33141/report.json`.
- OSV/KEV: **1 649 noyob paket versiyasi, 263 moslik, 6 qamrov bo‘shlig‘i, so‘rov xatosi yo‘q**. Hisobot: `dependency-runs/20260914T075335-54325181/report.json`; holat `partial`.
- Lokal crAPI web: **5 kuzatuv**, shundan `.env` mazmuni naqshiga 1 Nuclei mosligi va 4 HTTP kuzatuvi. Hisobot: `web-runs/20260914T074545-ee753f16/report.json`; eski `206` hisobi sababli 2 javob cheklangan deb qayd etilgan. Hozirgi tuzatishdan keyingi real qayta skan kutilmoqda.
- Trivy crAPI gateway-service image: **397 moslik — 9 kritik, 99 yuqori, 167 o‘rta, 120 past, 2 noma’lum**. Hisobot: `image-runs/20260914T074109-8f170c8d/report.json`. Bu `pilot-crapi-web` image’i emas; uning oldingi 169 mosligi boshqa nishonga tegishli.
- To‘rtta bosqichni bog‘lagan sinov: `assessment-runs/20260914T074035-a9563237/report.json`; kod 16, kutubxonalar 263, web 5, image 397; umumiy holat `partial`. Bu bosqichlar o‘z alohida dalil IDlariga ega.
- 2026-09-15 online nazorat: lodash 4.17.20 da **GHSA-35jh-r3h4-6jhm** mos; 4.17.21 da aynan shu yozuv mos emas. Ikkala so‘rov tugagan; boshqa zaifliklar qoladi. Dalil: `validation-runs/osv-control/result.json`.
- 2026-09-15 Nuclei nazorati: zaif misol 6, tuzatilgan misol 0, to‘liq `206` misol 6 Nuclei mosligi. Bir xil fallback uchun 0 aniq fayl mosligi va alohida ogohlantirish. Dalil: `validation-runs/web-control/result.json`.

Bu kuzatuv/mosliklar soni, tasdiqlangan hujumlar soni emas. Turli qamrov sonlarini qo‘shib xavfsizlik foizi chiqarilmaydi. Source commit va image bir-biriga tegishli ekanini alohida tasdiqlash kerak.

## Tekshirish va ma’lumotlar

```text
python -m unittest discover -s tests -q
python validate_pilot.py
python validate_web.py
python verify_pilot_api.py --port 8765
```

Nazorat sinovi paketlarni o‘rnatmaydi yoki bajarmaydi. U ikki lock versiyasini haqiqiy OSV bilan solishtirib dalil saqlaydi. Frontend o‘zgarsa sahifani, Python backend o‘zgarsa serverni qayta oching. Skan davomida terminalni yopmang; uzilgan job toza natija emas.

Hisobotlar `dependency-runs/`, `image-runs/`, `scanner-runs/`, `web-runs/`, `assessment-runs/` ichida. OSV/KEV kesh 24 soat. API xatosi topilma yo‘q deb yashirilmaydi. Review qarorlari aynan hisobot va inventarga bog‘langan; alohida hodisalar ham saqlanadi, ammo raqamli imzolangan audit emas. Umumiy jarayon bekor qilinganda joriy kod bosqichi o‘z timeoutigacha tugashi kutilishi mumkin; keyingi bosqichlar boshlanmaydi.

Manba kodi OSV ga yuborilmaydi; lokal scanner ish papkasida manba nusxasi bo‘lishi mumkin. Trivy raw ImageConfig/Env API eksportiga kiritilmaydi; normal tugashda raw JSON o‘chadi, majburan to‘xtashda lokal qoldiq qolishi mumkin. Mahalliy profillar, kesh va natijalar `.gitignore`ga kiritilgan; bu shifrlash emas. Tashqi tomonga to‘liq ish papkasini emas, ko‘rib chiqilgan kerakli hisobotni bering.

Server faqat 127.0.0.1 da, Host/Origin tekshiruvi va CSP bilan ishlaydi. RBAC, ko‘p foydalanuvchi, internetga ochiq xizmat, VS Code kengaytmasi, ZAP, EPSS, barcha CVE bazalarining to‘liq qamrovi va umumiy hujum yo‘li aniqlash bu versiyada mavjud emas. Keyingi bosqich kompaniya stack’i, ruxsatli nishon doirasi, to‘liq inventar, autentifikatsiyalangan DAST va real pilotdagi aniqlik/vaqt yutug‘ini o‘lchashga bog‘liq. ZAP’ni hali o‘rnatilgan yoki sinalgan integratsiya deb ko‘rsatmaymiz; tanlangan Nuclei profilining qamrovi ham ochiq yozilgan.

Manbalar: [OSV API](https://google.github.io/osv.dev/api/), [CISA KEV](https://github.com/cisagov/kev-data), [Trivy](https://trivy.dev/docs/latest/scanner/vulnerability/), [Nuclei](https://docs.projectdiscovery.io/opensource/nuclei/running), [Semgrep Windows xatosi](https://github.com/semgrep/semgrep/issues/11829), [nazorat yozuvi](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm).
