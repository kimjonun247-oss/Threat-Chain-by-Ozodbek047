# Arxiv: Zanjir 0.3 — 2026-09-10 holati

Bu tarixiy tavsif. Joriy imkoniyatlar va online rejim README.md da.

**2026-09-10 yangilanish:** **Kod va sirlar** bo‘limidagi mahalliy Semgrep/Gitleaks skani crAPI nusxasida muvaffaqiyatli tugadi: 493 ta matn faylida Semgrep 1.176.1 bilan 6 ta, Gitleaks 8.30.1 bilan 10 ta statik kuzatuv. Hisobot `20260910T165840-c28e8380`; manba va qoida xeshlari, satrlar, sonlar hamda API JSON eksport mosligi qayta tekshirildi. Alohida crAPI TLS tajribasi natijasi ham mavjud. Qamrov va qolgan ishlar: **SCANNERS.md**. Bu 16 ta tasdiqlangan hujum yoki ochiq beta tayyorligi tasdig‘i emas.

Kod, joylashtirish va tarmoq orasidagi himoya talablarini dalillar bilan tekshirish. **Repository** bo‘limi real crAPI konfiguratsiyasini faqat o‘qiydi; **Lokal demo** bo‘limi sun’iy HTTP laboratoriyasidir. Natijalar alohida saqlanadi.

## 0.3: loyiha ulash va birinchi pilot

Amaliy crAPI muhitini tayyorlash vositasi: `pilot.py`; tushuntirish **pilot/README.md** ichida. Muhitni tekshirish uchun `python pilot.py check`. Docker/WSL hali o‘rnatilmagan kompyuterda bu amal ochiq ravishda “muhit kerak” natijasini beradi; xavfsizlik tasdig‘i chiqarmaydi.

O‘z repositoryingiz bo‘lishi shart emas. Paketdagi **crAPI** boshlang‘ich pilot sifatida tanlanadi. Interfeysda loyiha tanlash, shu loyihaning oxirgi hisoboti va avvalgi tahlil bilan solishtirish mavjud. Keyingi amaliy bosqichlar: **PILOT_PLAN.md**.

Keyinchalik lokal loyiha tayyor bo‘lganda, uning manba papkasini bir marta ro‘yxatdan o‘tkazing. Quyidagi yo‘llar misol; haqiqiy papka va fayllarga almashtiriladi:

```text
python app.py --register-project my-app --repo C:\repos\my-app --compose deploy/compose.yml --name "My App" --owner "AX jamoasi"
python app.py --repository-profile my-app
```

Zarur bo‘lsa ro‘yxatdan o‘tkazishda quyida ko‘rsatilgan `--env-file` va `--bindings` parametrlarini qo‘shing. Sahifani yangilagach, loyiha ro‘yxatda ko‘rinadi. Mahalliy profil `profiles/local/` ichida saqlanadi. Bir xil ID ustiga yozilmaydi. Hisobot va review kalitlari loyiha hamda o‘qilgan fayllar nusxasiga bog‘langan; boshqa loyihaga qaror ko‘chirilmaydi. 0.2 hisobotlaridagi review qarorlari yangi kalitga avtomatik ko‘chmaydi.

Bu lokal bir foydalanuvchili MVP: profil ajratilishi korporativ foydalanuvchi/rol izolyatsiyasi emas. Hisobotlarda ichki konfiguratsiya dalillari bo‘lishi mumkin; avtomatik to‘liq maxfiy ma’lumot tozalash mavjud emas. Tarqatiladigan paketga mahalliy profillar va shaxsiy loyiha hisobotlarini qo‘shmang.

## 0.2: real repository tahlili

- Compose YAML va literal `.env` qiymatlarini tahlil qilish; host/container portlari va IPv4/IPv6 loopbackni ajratish.
- Qo‘lda berilgan mapping orqali Nginx fayllarini xizmatlarga bog‘lash, proxy yo‘llarini ajratish.
- HTTPS upstream sertifikat tekshiruvi, host interfeyslari va parallel host yo‘llari bo‘yicha uchta cheklangan qoida.
- Fayl/satr dalillari, commit kelib chiqishi, input hash, JSON va SARIF 2.1.0 eksport.
- Mas’ul va sabab bilan review qarorlari; qaror aniq input hash’ga tegishli, yangi nusxaga avtomatik ko‘chmaydi.
- Oldingi hisobot bilan fingerprint bo‘yicha solishtirish. “Joriy tahlilda yo‘q” avtomatik “tuzatildi” degani emas.

Tavsiya etilgan repositorylar, tanlangan commit va amaliy natijalar: **REPOSITORIES.md**.

```text
python app.py --repository-profile crapi
```

Boshqa lokal repository uchun faqat o‘qish rejimi:

```text
python app.py --scan-repo C:\repos\my-app --compose deploy/compose.yml --env-file deploy/.env --bindings my-bindings.json
```

`--env-file` va `--bindings` ixtiyoriy. `my-bindings.json` — quyidagi shakldagi massiv:

```json
[{"service_id":"web", "path":"nginx.conf", "template_variables":{"BACKEND":"api:8080"}}]
```

Compose/env/proxy yo‘llari repository ichida bo‘lishi kerak. Tahlilchi repository kodini, setup.py, Dockerfile yoki shell skriptni bajarmaydi. Browser API ixtiyoriy disk yo‘lini qabul qilmaydi; crAPI va oldindan ro‘yxatdan o‘tkazilgan lokal profillarni tahlil qiladi. `--scan-repo` bir martalik hisobot yaratadi; loyiha tanlash ro‘yxatiga kiritish uchun `--register-project` ishlating.

Hozirgi cheklovlar: bitta Compose fayli; YAML alias/merge, port diapazonlari, murakkab `.env` interpolatsiyasi, tashqi include, Docker runtime, ko‘p faylli Compose merge va nginx Lua bajarilishi qo‘llanmaydi. Shell env avtomatik o‘qilmaydi. Generic Python/JS auth skaneri va universal hujum yo‘li qidiruvi mavjud emas. Source → image mapping deklaratsiya bo‘lib qoladi. Aniq qamrov va cheklovlar har bir hisobotda bor.

## Ishga tushirish

Windows’da `START.cmd` faylini oching. Terminalda ko‘rsatilgan `http://127.0.0.1:8765` manziliga brauzer orqali kiring. Server allaqachon ishlayotgan bo‘lsa, ikkinchi nusxani ishga tushirmang.

Istalgan Python 3.10+ o‘rnatilgan kompyuterda:

```text
python app.py
```

Qo‘shimcha paket, internet, API kaliti yoki Docker kerak emas. Barcha so‘rovlar 127.0.0.1 manzilida qoladi. Serverni to‘xtatish: terminalda Ctrl+C.

## 3 daqiqalik demo

1. **01 · Himoyani chetlab o‘tish** ssenariysini ishga tushiring. Ruxsatsiz bevosita so‘rov `HTTP 200` va sun’iy `DEMO-001` hujjatini oladi. Gateway shu ruxsatsiz rolga `403` qaytaradi; vakolatli foydalanuvchi `200` oladi.
2. **Dalillar** bo‘limida aynan bir `service_id`ga tegishli port, tarmoq qoidasi va kod deklaratsiyasini ko‘rsating. Ma’lumotlar tasodifiy skaner topilmalarining yig‘indisi emas.
3. **02 · Bevosita yo‘l yopilgan** variantini tekshiring. Lokal tarmoq modeli bevosita so‘rovni to‘xtatadi. Vakolatli gateway so‘rovi ishlashda davom etadi.
4. **03 · Xizmat ruxsatni tekshiradi** variantida tarmoq yo‘li ochiq qoladi, lekin xizmatning o‘zi `documents.read` ruxsatini tekshiradi.
5. **05 · Tarmoq dalili yo‘q** variantida “noma’lum” natija va sinov o‘tkazilmaganini ko‘rsating.
6. **Sinovlar → Barcha sinovlarni bajarish** orqali oltita ssenariyni tekshiring. Jadvaldagi natijalar haqiqiy ishga tushirishdan olinadi.

## Nima ishlaydi

- Python AST yordamida ikki namunaviy ilovadan aniq xavfsizlik deklaratsiyalarini o‘qish.
- Xizmat identifikatori bo‘yicha kod, joylashtirish va tarmoq faktlarini bog‘lash.
- TB-001 v1.0.0 qoidasi: gateway himoyasini chetlab o‘tadigan yo‘l + xizmatda tegishli ruxsat tekshiruvi yo‘qligi.
- `detected`, `not_detected`, `unknown` holatlarini alohida chiqarish.
- Uchta haqiqiy localhost HTTP so‘rovi bilan kod xatti-harakatini tekshirish; statik deklaratsiya va xatti-harakat mos kelmasa `inconsistent` chiqarish.
- Ssenariy nusxasi, manba kodi, HTTP javoblari, qoida versiyasi, vaqt va SHA-256 bilan JSON hisobotlar.
- Ikki tuzatish variantini qayta sinash, lokal tarix, yuklab olinadigan hisobot.

## Muhim chegaralar

Bu **sun’iy namunadagi ishlaydigan PoC**, korporativ tizimlar uchun tayyor skaner emas.

- Tarmoq aloqasi loopback HTTP relay orqali **modellashtiriladi**. `403` tarmoq modeli tomonidan qaytishi mumkin; bu OS firewall paket tashlagani yoki real Docker segmentatsiyasi sinalganini anglatmaydi.
- `demo/scenarios.json` ichidagi tarmoq, gateway va joylashtirish tavsiflari qo‘lda belgilangan deklaratsiyalardir. Real qurilmadan avtomatik yig‘ilmaydi.
- Kod adapteri faqat ikki namunaviy ilovadagi deklaratsiyalarni o‘qiydi. U umumiy Python/JS autentifikatsiya skaneri emas. Deklaratsiya amaliy HTTP sinovi bilan solishtiriladi.
- Faqat belgilangan rollar, `/documents` endpointi va `documents.read` huquqi sinaladi. Demo credential haqiqiy identifikatsiya tizimi emas.
- `not_detected` — faqat TB-001 shartlari bajarilmadi degani. Umumiy xavfsizlik yoki audit sertifikati emas.
- Kichik oldindan belgilangan 6 ta ssenariyning o‘tishi umumiy detection rate yoki xavfsizlik foizi emas. Qo‘lda tekshirish vaqtiga nisbatan yutuq hozircha o‘lchanmagan.
- Xesh nusxalarni solishtirish uchun. Hisobotlar raqamli imzolangan yoki o‘zgartirib bo‘lmaydigan audit jurnali emas.
- Loyihaga real maxfiy ma’lumot qo‘shilmagan. Internet, bulut, LLM yoki tashqi skaner ish vaqtida ishlatilmaydi.

## Tekshirish va hisobotlar

```text
python -m unittest discover -s tests -v
python app.py --suite
python app.py --run bypass
```

Hisobotlar `runs/` ichida saqlanadi. `suite.json` oxirgi to‘plam natijasi, boshqa JSON fayllar alohida ishga tushirishlar hisoboti. Testlar vaqtinchalik papkadan foydalanadi. `report_sha256` butun hisobotdan shu maydon chiqarib tashlanib, UTF-8 JSON `sort_keys=True`, `ensure_ascii=False`, `separators=(',', ':')` bilan hisoblanadi.

## Arxitektura

```text
demo/scenarios.json + demo/apps/*.py
                  ↓
          zanjir/engine.py
   Faktlar → service_id bog‘lash → TB-001
                  ↓
           zanjir/lab.py
    Gateway + ilova + tarmoq relay
       3 ta real lokal HTTP so‘rovi
                  ↓
          zanjir/runner.py
       Snapshot + dalil + JSON hisobot
                  ↓
       app.py API → dist/ interfeys
```

Backend: Python standard library va paketga qo‘shilgan PyYAML 6.0.2. Frontend: HTML/CSS/JavaScript; tashqi shrift yoki CDN yo‘q. PyYAML kodi o‘zgartirilmagan, kelib chiqishi va litsenziyasi vendor/ ichida. Server localhost’ga bog‘langan; Host, Origin va cross-site so‘rovlar tekshiriladi. API tashqi target URL, disk yo‘li yoki buyruq qabul qilmaydi. Laboratoriya faqat paketdagi ikki demo ilovasini bajaradi. Repository adapteri esa faqat fayllarni o‘qiydi, ilova kodini import qilmaydi.

## Keyingi muhandislik bosqichi

1. Bitta real pilot tizim, uning egasi va yozma tekshiruv chegarasini tanlash.
2. Real stack’ka mos kod adapteri, joylashtirish eksporti va tarmoq qoidasi formatini qo‘shish.
3. Deklaratsiya, konfiguratsiyadan aniqlangan fakt va amalda kuzatilgan faktni ajratish; snapshot vaqtlarini moslashtirish.
4. Ruxsat etilgan test muhitida yo‘lni mustaqil tasdiqlash. Production’ga avtomatik faol so‘rov yubormaslik.
5. AX mutaxassisi topilmalarni tasdiqlashi; noto‘g‘ri ogohlantirish, qamrov, tuzatish va qayta tekshirishni o‘lchash.
6. Natija foydali bo‘lsa, versiyalanadigan qoidalar, RBAC, himoyalangan dalil saqlash va CI integratsiyasini qo‘shish.

Namunaning maqsadi universal tahlilchi borligini da’vo qilish emas: chegaralangan qoidani qanday ishonarli tekshirish, tushuntirish va qayta sinashni ko‘rsatish.
