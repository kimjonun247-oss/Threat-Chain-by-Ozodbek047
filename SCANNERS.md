# Semgrep va Gitleaks integratsiyasi

## Joriy holat — 2026-09-17: rasmiy qoida bazasi ulandi

Qoida bazasi 7 ta lokal qoidadan **7 + 1343 ta rasmiy `semgrep-rules` security qoidasiga** (22 til) kengaytirildi — `python3 setup_semgrep_rules.py`, pinlangan commit `40b8c63f75dc7c22c8a77482d73bfb864b146f7e`. macOS arm64, Semgrep **1.177.0**, Gitleaks **8.30.1**.

crAPI (`crapi-full`, 485 matn fayli) ustidagi haqiqiy skan: Semgrep **134 ta kuzatuv** (avval 6 ta), Gitleaks **10 ta**, jami **144**. Skan vaqti ~39 s. Barcha 134 topilmada CWE bor; 117 tasi OWASP Top 10:2025 toifasiga bog'landi, qolgan 17 tasining CWE'si MITRE jadvalida hech bir 2025 toifasiga a'zo emas va **taxmin qilinmaydi**. Daraja taqsimoti: 18 `ERROR`, 106 `WARNING`, 10 `INFO`.

Holat `partial`, xato soni 36 — barchasi `Other syntax error` turida va `deploy/helm/templates/...` ostidagi Helm shablon fayllariga tegishli (ular sof YAML emas). Bu haqiqiy qamrov bo'shlig'i, shuning uchun bosqich `completed` deb ko'rsatilmaydi. Apex qoidalari o'rnatishda qasddan chiqarib tashlangan: OSS Semgrep Apex'ni parse qila olmaydi va ular faqat o'zgarmas "Missing plugin" shovqinini berardi.

**Sir sizishidan himoya:** topilma matni Semgrep chiqishidagi `extra.message` dan emas, SHA-256 bilan tasdiqlangan qoida faylining o'z yozuvidan olinadi — Semgrep o'z xabariga mos kelgan kod parchasini qo'shib yuboradi va bu haqiqiy sir qiymatini hisobotga olib chiqishi mumkin edi. Hisobotda `$CONTAINER` kabi o'rin egallovchi ko'rinishi shu himoyaning bevosita dalili. Har bir skandan oldin manifest qayta tekshiriladi; qoida fayli o'zgargan yoki o'chirilgan bo'lsa skan to'xtaydi.

Dasturiy testlar: **203 ta o'tgan** (avval 178).

## Oldingi holat — 2026-09-10

**Muvaffaqiyatli haqiqiy skan:** `20260910T165840-c28e8380`, 16:58:40–16:59:00 UTC. Holat `completed`. Semgrep **1.176.1** 7 ta mahalliy qoida bilan **6 ta TLS kuzatuvi**, Gitleaks **8.30.1** **10 ta kuzatuv** (6 private-key, 4 JWT) qaytardi. Ikkala vosita hisobotida xatolar soni 0. 493 matn fayli / 1 654 192 bayt. Bular hali `unverified_static`; amaliy hujum yoki real sir sizishi tasdiqlanmagan.

493 ta manba faylining manifest xeshlari, umumiy manifest xeshi, qoidalar xeshlari, topilma satrlari, sonlar, vaqtinchalik nusxa tozalanishi va jonli API JSON eksport mosligi tekshirildi. Dalillar shu hisobot papkasidagi `review.json`, o‘qishga qulay natija `report.md` da. Avvalgi nosozliklar quyida tarix sifatida saqlangan; oxirgi muvaffaqiyatli skan ularni joriy holat sifatida almashtiradi. Dasturiy testlar: 91 ta o‘tgan.

### Nosozliklarni tuzatish tarixi

- Semgrep Python paketi 1.176.1 va Gitleaks 8.30.1 loyiha ichidagi `.tools` papkasiga o‘rnatildi. Oldingi foydalanuvchi skanlarida `1.174.0` qaytishi diagnostikada global Python311 Semgrep nusxasiga o‘tib ketish bilan bog‘landi. Global Python va Windows himoya sozlamalari o‘zgartirilmadi.
- Gitleaks rasmiy Windows arxivi SHA-256 bilan tekshirildi: `d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e`. Yuklash manbasi va exe xeshi `.tools/gitleaks/provenance.json` ichida.
- To‘liq crAPI nusxasidan 493 ta matn fayli (1 654 192 bayt) tekshiruv nusxasiga olindi. Gitleaks 10 ta statik kuzatuv qaytardi. Bular demo qiymat yoki amaldagi sir ekanligi hali qo‘lda baholanmagan.
- Semgrep ushbu agent sessiyasida `CertOpenSystemStore returned NULL` xatosi bilan boshlanmayapti. Qoidalar real Semgrep skani bilan hali tekshirilmagan. Natija `partial`; muvaffaqiyatli yoki toza skan deb ko‘rsatilmaydi.
- Foydalanuvchi Windows’da `SCAN-CODE.cmd` ni ochdi: `20260910T153610-d162bd7b` hisobotida Gitleaks 10 kuzatuv bilan tugadi, Semgrep boshqa `ValueError` bilan tugallanmadi. Eski hisobot bu xatoning aniq bosqichini saqlamagani uchun sabab hali aniqlanmagan. Qoida ID’larini Windows konfiguratsiya yo‘liga bog‘lamaslik uchun `--no-rewrite-rule-ids` qo‘shildi; bu o‘zgarish asl xatoni bartaraf etgani hali tasdiqlanmagan.
- `20260910T162356-31bb655d` diagnostikasi aniq sababni ko‘rsatdi: Semgrep versiya tekshiruvidan o‘tdi, ammo skan buyrug‘idagi qo‘llanmaydigan `--oss` parametrida exit 2 bilan to‘xtadi. Parametr olib tashlandi; mahalliy qoidalar bilan oddiy `scan` ishlatiladi, Pro rejimi yoqilmaydi. Tuzatilgan buyruqning foydalanuvchi muhitidagi haqiqiy skani hali kutilmoqda.
- Xato bosqichi va exit kodi saqlanadi. `SCAN-CODE.cmd` Semgrep xatosida faqat sun’iy `demo.py` fayli bilan diagnostika bajaradi va `scanner-runs/<id>/semgrep-diagnostic.json` ga yozadi. Diagnostika haqiqiy repository kodi yoki sirlarini o‘qimaydi, JSON eksportga kiritilmaydi.
- Keyingi haqiqiy urinish `20260910T164414-11480f22`: Gitleaks 10 kuzatuv bilan tugadi (6 private-key, 4 JWT); Semgrep exit 2 bilan tugallanmadi. Sun’iy diagnostikada `<ERROR: missing output>` chiqdi, stderr bo‘sh. Bu xabarning o‘zi asosiy sababni aniqlamaydi. `DIAGNOSE-CODE.cmd` endi repositoryni qayta skan qilmasdan debug rejimida to‘liq qoidalar, bitta sodda Python qoidasining JSON va matn chiqishini taqqoslaydi. Natija `semgrep-diagnostic-debug.json` ga yoziladi; eski diagnostika saqlanadi. Diagnostika yangilangach 9 ta integratsiya testi o‘tdi; foydalanuvchi muhitidagi yangi diagnostika kutilmoqda.
- Batafsil diagnostika olindi: uchala sun’iy skan `socketpair: The data area passed to a system call is too small` xatosida to‘xtagan. RPC jurnali loyiha tashqarisidagi `Python311/Lib/site-packages/semgrep/bin/semgrep-core.exe` 1.174.0 ni ko‘rsatdi. Loyiha Semgrep wrapper’i Scripts papkasini PATH oxiriga qo‘shadi; shuning uchun endi jarayon PATH boshiga loyiha Scripts papkasi qo‘yiladi. Ikkinchi tuzatish: chuqur hisobot papkasidagi TEMP o‘rniga OS vaqtinchalik papkasida alohida qisqa `zsg-*` papka ishlatiladi va tugaganda tozalanadi. HOME va sozlamalar alohida ish papkasida qoladi. OCaml Windows socketpair manbasida GetTempPath natijasi va socket nomi cheklangan UTF-8 sun_path buferiga yozilishi ushbu yo‘l uzunligi tashxisini qo‘llab-quvvatlaydi: https://github.com/ocaml/ocaml/blob/trunk/otherlibs/unix/socketpair_win32.c. Haqiqiy Semgrep skanining ushbu tuzatishlardan keyingi natijasi hali kutilmoqda.
- Ushbu tuzatishlardan keyin 91 ta test o‘tdi. Qo‘shimcha sinovlar global Semgrep o‘rniga loyiha nusxasi tanlanishini, qisqa vaqtinchalik papka chegarasini va xato bo‘lganda ham tozalanishini tekshiradi. Bu testlar haqiqiy skan tugaganini anglatmaydi.
- Parametr tuzatilgach 89 ta dasturiy test o‘tdi; bu haqiqiy Semgrep skani o‘rnini bosmaydi. Lokal API orqali ish boshlash, natijani olish va JSON eksport avval tekshirildi. JSON eksport olingan hisobotga teng. JavaScript sintaksisi tekshirildi; vizual brauzer tekshiruvi bajarilmagan.

## Foydalanish

`START.cmd` Zanjir interfeysini ochishga xizmat qiladi. Brauzerda http://127.0.0.1:8765/ manziliga kiring va **Kod va sirlar** bo‘limini tanlang. To‘liq crAPI manbasi yoki oldindan ro‘yxatdan o‘tkazilgan mahalliy loyiha tanlanadi. Tugma tekshiruvni fonda boshlaydi; natija va qisman xatolar ekranda ko‘rinadi. JSON hisobot yuklab olinadi.

`SCAN-CODE.cmd` aynan to‘liq crAPI nusxasini Windows foydalanuvchisi muhitida tekshiradi va shu hisobot tarixiga yozadi. Keyin sahifani yangilang. Buyruq satri uchun: `python scan_code.py --target crapi-full`. Boshqa loyiha uchun README’dagi ro‘yxatdan o‘tkazish usulidan foydalaning va o‘sha ID’ni `--target` bilan bering.

## Masofaviy nishonlar (0.7)

- **Image:** teg (`nginx:1.27`), digest va shaxsiy registry (`registry.example.com:5000/jamoa/app:1.0`).
  Teg pinned hisoblanmaydi — har skan `resolved_digest` ni yozadi. Registry uchun kirish
  ma'lumoti `THREATCHAIN_REGISTRY_<HOST>_USERNAME/…_PASSWORD` muhit o'zgaruvchilaridan
  olinadi yoki mavjud `docker login` seansidan; **hech qayerda saqlanmaydi**.
- **Manba:** `https://` yoki `ssh://` git repozitoriysi. Har skan uchun `--depth 1` sayoz
  nusxa, hook'lar o'chirilgan, commit qayd etiladi, nusxa skandan keyin o'chiriladi.
  URL ichida login qabul qilinmaydi; `ext::` va `file://` rad etiladi.
- **Sayt/API:** TLS holati (protokol, shifr, subject/issuer, muddat) qayd etiladi;
  autentifikatsiya `THREATCHAIN_WEB_AUTH_<ID>` dan; so'rov tezligini sekinlashtirish mumkin.

Chegarada qoladi: masofaviy Docker daemon, SSH orqali host skani, agent.

## Konfiguratsiya (IaC) — Trivy config

Alohida `iac` bosqichi. Trivy `config` rejimi Dockerfile, Kubernetes, Terraform,
CloudFormation, Helm va ARM fayllarini statik tekshiradi. Compose va Nginx bu bosqichga
kirmaydi — ular uchun Repository bosqichi (RP-001…RP-011) ishlaydi.

- Kod skaneri bilan bir xil faqat-o'qish nusxasi: symlink kuzatilmaydi, binar va 1 MB dan
  katta fayllar tashlab ketiladi, hech nima bajarilmaydi.
- Trivy tekshiruvlarida CWE yo'q. `zanjir/iac.py` dagi `CHECK_CWE` xaritasi faqat zaifligi
  aniq bo'lganlarini bog'laydi; qolganlari o'z ID si bilan ko'rsatiladi va hisobotda
  `untagged_checks` ro'yxatida sanaladi.
- Standart holatda tanlanmagan (`iac_target` — ixtiyoriy maydon).

## SBOM — CycloneDX 1.6

Image hisoboti Trivy'ning `--list-all-pkgs` natijasidan paket ro'yxatini saqlaydi, va SBOM
o'sha ro'yxatdan quriladi — image ikkinchi marta yuklab olinmaydi va SBOM topilmalar bilan
bir xil dalilga asoslanadi.

    GET /api/images/reports/<id>/sbom        # bitta image
    GET /api/images/sbom?project=<loyiha>    # loyihadagi barcha image

Paket ro'yxati yo'q (eski) hisobot uchun bo'sh SBOM emas, `409` va sabab qaytadi.

## Qamrov

Semgrep CE uchun ThreatChain yozgan 29 ta lokal qoida ishlatiladi (rasmiy paket o'rnatilmagan bo'lsa ham ishlaydi):

- **Taint (ERROR, CI gate'ni to'xtatadi):** HTTP so'rovidan (Flask/Django `request`, Express `req.query/body/params`, Java servlet, Go `http.Request`, PHP `$_GET/$_POST/$_REQUEST`) kelgan qiymat buyruq bajarishga (CWE-78), SQL matniga (CWE-89), deserializatsiyaga (CWE-502), shablon matniga (SSTI, CWE-1336) yoki PHP'da HTML chiqishiga (XSS, CWE-79) yetib borsa; shuningdek `yaml.load` xavfsiz Loader'siz va lxml XXE (CWE-611).
- **Naqsh (WARNING):** shell/dinamik kod/TLS o'chirilishi (Python, JS/TS, Go, Java), SQL matnini satr birlashtirish yoki formatlash bilan qurish (Python, Java, Go), `pickle.load(s)`, Flask `debug=True` (CWE-489), MD5/SHA1 (CWE-328, `usedforsecurity=False` bundan mustasno), JS prototype pollution (CWE-1321).

**Benchmark (2026-09-25, 5 til, 30 ta ma'lum zaiflik + xavfsiz fayllar):** rasmiy paket bilan 30/30 topiladi, CI gate 24 tasida to'xtaydi (qolgan 6 tasi TLS, zaif shifr, debug, prototype pollution — o'rta toifa, ataylab to'xtatmaydi), xavfsiz fayllarda gate noto'g'ri signali 0. Gitleaks 10/10 (ulanish URL'idagi parol va git tarixidagi sir bilan).

ERROR faqat manba va xavfli amal bitta oqimda ko'ringanda beriladi. Bu to'liq Semgrep Registry to'plami yoki barcha zaifliklar qamrovi emas; to'liqroq qamrov uchun `setup_semgrep_rules.py`. Ko'rsatilgan amaldan foydalanishning o'zi zaiflik isboti emas.

Gitleaks ichki qoidalari `dir` rejimida joriy fayllarga qo‘llanadi. Git tarixi tekshirilmaydi. `.git`, `.tools`, virtual muhitlar, `node_modules`, `vendor`, natijalar va pilot papkalari; binar fayllar va 1 MB dan katta fayllar chiqarib tashlanadi. Nusxa chegarasi: 10000 fayl va 50 MB. Cheklovga yetish xato holatini beradi. O‘tkazilgan fayl/papka sonlari hisobotda saqlanadi. `snapshot-manifest.json` aynan nusxalangan fayllarning yo‘llari va xeshlarini saqlaydi; bu butun repositoryning bitta atomik vaqt holati degani emas.

## Ma’lumotlar va bajarish chegaralari

Repository kodi import qilinmaydi, build va setup amallari bajarilmaydi. Skanerlar vaqtinchalik nusxani o‘qiydi; reparse point/symlink va loyiha chegarasidan tashqaridagi yo‘llar kiritilmaydi. Ular mahalliy native dasturlar: ushbu vosita o‘z-o‘zidan alohida OS sandbox bermaydi.

Mahalliy qoidalar majburiy beriladi; loyiha `.semgrepignore`, `.gitleaksignore`, `.gitleaks.toml` fayllari qamrovni yashira olmaydi. `nosem` va `gitleaks:allow` izohlari e’tiborga olinmaydi. Jarayon muhitiga tokenlar, bulut credential’lari va proxy konfiguratsiyasi uzatilmaydi. Semgrep metrics, versiya tekshiruvi va OpenTelemetry o‘chirilgan; platformaga login yoki natijani upload qilish chaqirilmaydi. Tarmoq blokirovkasi OS darajasida bu integratsiya tomonidan o‘rnatilmagan.

Gitleaks `--redact=100` bilan bajariladi. Bundan tashqari, ikkala vosita javobidan faqat qoida ID’si, mavjud nusxadagi fayl yo‘li, satr va Zanjir’ning qat’iy izoh matni olinadi. `Secret`, `Match`, kod parchasi, metavariable, stderr va ixtiyoriy vosita xabarlarini hisobotga yozmaymiz. Vaqtinchalik nusxa tekshiruv tugaganda tozalanadi. Hisobotdagi loyiha/fayl nomlari ichki ma’lumot bo‘lishi mumkin; ularni ommaga tarqatishdan oldin ko‘rib chiqing.

## Natija holatlari

- `completed`: ikkala vosita ushbu qamrovda tugadi; topilma yo‘qligi xavfsizlik kafolati emas.
- `partial`: kamida bitta vosita bajarildi, lekin boshqa vosita yoki ayrim fayllar tahlili tugallanmadi.
- `failed`: tekshiruv bajarilmadi.
- `unverified_static`: kod/sir kuzatuvi; amaliy hujum tasdig‘i emas.
- `controlled_test_confirmed`: alohida crAPI TLS tajribasi uchun ishlatiladi. Kod skanerlari topilmalari bilan avtomatik tenglashtirilmaydi.

TLS paneli asl jurnal va konfiguratsiya xeshlarini tekshiradi, to‘rtta nazoratni javoblar hamda jurnal bilan qayta hisoblaydi. Asl crAPI tarmog‘idagi hujum yo‘li yoki qo‘llangan tuzatish deb belgilamaydi.

## O‘rnatish manbalari va keyingi ish

Semgrep Windows beta o‘rnatish tartibi: https://docs.semgrep.dev/getting-started/quickstart. CLI va flaglar: https://docs.semgrep.dev/cli-reference. Gitleaks rasmiy relizi: https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1. Gitleaks CLI: https://github.com/gitleaks/gitleaks.

Mahalliy Semgrep Python paketlarining aniq versiyalari `scanner-rules/semgrep-windows-lock.txt` ichida qayd etilgan. Semgrep haqiqiy crAPI skani tugadi. Ikkinchi kompyuterga takrorlanadigan o‘rnatish, barcha qoidalar uchun positive/negative engine sinovlari, topilmalarni qo‘lda baholash va vizual tekshiruv hali tugallanmagan. `.tools`, pilotdagi demo private key’lar va mahalliy skan hisobotlarini umumiy tarqatish ZIP’iga avtomatik qo‘shmang.
