# Zanjir: o‘z repositoryingiz bo‘lmasa ham boshlash rejasi

Hozirgi pilot — paket ichidagi OWASP crAPI manba nusxasi. Alohida shaxsiy loyiha yaratish yoki tashkilot tizimiga ulanish talab qilinmaydi. Mahalliy interfeys: http://127.0.0.1:8765/.

## Hozir tayyor

- crAPI konfiguratsiyasining kelib chiqishi qayd qilingan nusxasi: commit `700f03d12a392d9e408260b4beae72ed02a4a1a4`. Tanlangan fayllar nusxasi to‘liq ishga tushiriladigan crAPI emas.
- 10 xizmat, 5 localhost host porti, 12 proxy yo‘l deklaratsiyasi va 6 ta ko‘rib chiqiladigan kuzatuv. Amalda tasdiqlangan crAPI hujumi: 0.
- Kuzatuvlar uchun fayl/satr dalillari, JSON/SARIF eksport, mas’ul va asos bilan qaror saqlash, ikki hisobotni taqqoslash.
- Alohida sun’iy lokal demoda ruxsatsiz kirish, tuzatish va ma’lumot yetishmasligi nazoratlari.
- Kelajakdagi Compose/Nginx loyihasini lokal profil sifatida ulash va interfeysdan tanlash.

## Birinchi amaliy mashg‘ulot

1. **Repository** bo‘limida crAPI’ni tanlab, tahlilni boshlang. Bu boshlang‘ich hisobot bo‘ladi.
2. RP-002 kuzatuvini oching. `proxy_ssl_verify off` qaysi HTTPS yo‘liga taalluqli ekanini fayl/satr dalili bilan tekshiring. Bitta sozlama bir necha yo‘lga ta’sir qilishi mumkin: beshta kuzatuvni beshta mustaqil buzib kirish deb hisoblamang.
3. Tekshiruvchi natijani o‘qib, mas’ul va sabab bilan “Tekshirilmoqda” holatini kiritsin. Bu hali runtime tasdiq emas.
4. Manbani o‘zgartirmasdan yana tahlil qiling. “Oldingi tahlil bilan solishtirish” bir xil qamrovda yangi 0, yo‘qolgan 0, saqlangan 6 ko‘rsatishi kerak.
5. **Lokal demo** bo‘limidagi zaif va tuzatilgan ssenariylarni ko‘ring. Bu tuzatishni qayta tekshirish usulini ko‘rsatadi; crAPI xatti-harakatini tasdiqlamaydi.

## Keyingi qurish bosqichlari

| Bosqich | Ish | Tugallangan deb hisoblash mezoni |
|---|---|---|
| 1. Dalilni tekshirish | crAPI kuzatuvlarini qo‘lda baholash, birinchi tekshiriladigan yo‘lni tanlash | Manba, qamrov, mas’ul va tekshiruv gipotezasi yozilgan |
| 2. Ajratilgan runtime | To‘liq crAPI nusxasi uchun takrorlanadigan lokal muhit, image versiyalari va boshlang‘ich ishlash tekshiruvi | Muhit qayta yaratiladi; haqiqiy so‘rov natijalari saqlanadi |
| 3. Tuzatish tajribasi | Alohida nusxada TLS ishonch zanjiri, CA, nom va SNI sozlamalarini moslash | Noto‘g‘ri sertifikat rad etiladi; to‘g‘ri sertifikat bilan kerakli xizmat ishlaydi |
| 4. Qayta tahlil | Bir xil qamrovdagi oldin/keyin statik hisobot va amaliy sinovni bog‘lash | Kuzatuvdagi o‘zgarish hamda ishlash saqlangani alohida dalillangan |
| 5. Ichki pilot | Kelajakdagi haqiqiy loyiha nusxasini ulash, mutaxassis bahosi bilan solishtirish | Aniqlash foydasi, noto‘g‘ri signallar va sarflangan vaqt o‘lchangan |

2026-09-10: runtime muhiti ishga tushdi; crAPI va MailHog sahifalari HTTP 200 qaytargani mustaqil tekshirildi. `PILOT-CHECK.cmd` konteyner konfiguratsiyasidan `/identity/` uchun sertifikat tekshiruvi off ekanini qayd etdi. `PILOT-TLS-TEST.cmd` aynan shu web image’da ajratilgan nazorat tajribasini bajardi: to‘rtta nazorat o‘tdi (ishonchsiz sertifikat off bilan qabul qilindi, on bilan rad etildi; ishonchli sertifikat/to‘g‘ri nom ishladi, noto‘g‘ri nom rad etildi). Dalil: `pilot/tls-runs/20260910T091714-055ace44/report.md`. Bu asl crAPI uchun hujumchi trafikni ushlay olishi yoki tuzatish qo‘llanganini bildirmaydi. Keyingi ish — natijani interfeysga ulash va asl identity xizmatiga mos CA/nom bilan alohida nusxada tuzatish hamda qayta sinov. RP-003 bo‘yicha ham host porti mavjudligi autentifikatsiya chetlab o‘tilganini o‘z-o‘zidan isbotlamaydi.

## Keyin haqiqiy loyiha qanday ulanadi?

Hozir qo‘llanadigan kirish ma’lumotlari: lokal repository papkasi, bitta Compose fayli, zarur bo‘lsa literal `.env` va Nginx fayllarining xizmatlarga mappingi. Ro‘yxatdan o‘tkazish misoli README.md ichida. Dastur manbani faqat o‘qiydi; avtomatik deploy, tarmoqqa hujum yoki repository kodini bajarish yo‘q.

Kubernetes, oddiy server konfiguratsiyasi, ko‘p Compose faylini birlashtirish hamda umumiy Python/JavaScript avtorizatsiya tahlili uchun alohida adapterlar kerak. Hozirgi tahlilchini istalgan texnologiyani to‘liq qamrab oluvchi skaner sifatida taqdim etmaymiz.

## Mablag‘ ajratish uchun nimani o‘lchaymiz?

- Topilmadan foydalanish mumkin bo‘lgan dalilgacha ketgan vaqt: qo‘lda va Zanjir yordamida.
- Mutaxassis tekshirgan topilmalar ichida tasdiqlangan, noto‘g‘ri signal va hal bo‘lmagan holatlar soni.
- Tuzatishdan keyingi qayta sinov va odatiy foydalanishning saqlanishi.
- Qo‘llanmagan konfiguratsiyalar va dalil yetishmaydigan holatlar.

Hozir vaqt tejalishi yoki umumiy aniqlash foizi o‘lchanmagan. 54 ta dasturiy testning o‘tishi mahsulotning ichki xatti-harakatini tekshiradi; real tashkilotdagi xavfsizlik samaradorligi o‘rnini bosmaydi. Birinchi pilot shu amaliy foydani o‘lchash uchun xizmat qiladi.
