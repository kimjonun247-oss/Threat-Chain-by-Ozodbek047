# Zanjir MVP — tekshirish natijalari

Sana: 2026-09-09. Muhit: Windows, Python 3.12.14, Node.js v24.16.0.

## Bajarilgan tekshiruvlar

- 61 ta Python avtomatik testi o‘tdi. Testlar klassifikatsiya, noto‘g‘ri format, xizmatlarni adashtirib bog‘lash, noto‘g‘ri kod deklaratsiyasi, haqiqiy localhost HTTP javoblari, vakolatli kirishni saqlash, hisobot xeshlari va lokal API kirish chegaralarini qamraydi.
- JavaScript sintaksisi tekshirildi; HTML’dagi barcha skript, stil va favicon manbalari lokal va mavjud.
- Asosiy sahifa va lokal API ishlashi HTTP orqali tekshirildi.
- Barcha oltita ssenariy brauzerdagi tuzilgan boshqaruv amali orqali bajarildi: 6/6 kutilgan natija.
- `run_security_demo` bilan xizmatdagi ruxsat tekshiruvi varianti bajarildi, natija `not_detected / blocked`; `read_security_result` aynan shu natijani qaytardi.
- Barcha uchta tuzilgan boshqaruv amali noto‘g‘ri parametrni rad etdi; avvalgi natija o‘zgarmadi.
- Alohida vizual screenshot tekshiruvi bajarilmadi. Funksional backend va tuzilgan interfeys amallari tekshirildi.

## To‘plam natijalari

| Ssenariy | Statik tahlil | Lokal tasdiq | Ruxsatsiz bevosita HTTP | Vakolatli gateway HTTP |
|---|---|---|---|---|
| 01 · Himoyani chetlab o‘tish | detected | confirmed | 200 | 200 |
| 02 · Bevosita yo‘l yopilgan | not_detected | blocked | 403 | 200 |
| 03 · Xizmat ruxsatni tekshiradi | not_detected | blocked | 403 | 200 |
| 04 · Bog‘lanmagan topilmalar | not_detected | blocked | 403 | 200 |
| 05 · Tarmoq dalili yo‘q | unknown | skipped | — | — |
| 06 · Kod modeli noma’lum | unknown | skipped | — | — |

`403` javobi tarmoq modelidan yoki ilovadagi ruxsat tekshiruvidan keladi. Tarmoq modelining javobi real firewall testi emas. `—` dalil yetishmagani sababli faol tekshiruv bajarilmaganini anglatadi.

Bu oltita nazorat namunasi umumiy aniqlash samaradorligi yoki kompaniya xavfsizligi foizini o‘lchamaydi. Haqiqiy tashkilot tizimi tekshirilmagan. Demo fayllari ichidagi sun’iy credential va hujjatlar namuna ma’lumotlardir.

Takrorlash: `python -m unittest discover -s tests -v` va `python app.py --suite`.


## 0.2 repository tahlili

- Parser, read-only repository adapteri va review qatlami bo‘yicha 22 ta yangi test; jami 45 ta test muvaffaqiyatli.
- Pinned crAPI source: 10 xizmat, 5 loopback host porti, 12 proxy route, 5 TLS kuzatuvi va 1 parallel host yo‘li kuzatuvi. Runtime tasdiq: 0.
- Testlar YAML duplicate/alias/unsafe tag/depth, IPv4/IPv6 port mapping, dotenv, nginx meros olinadigan directive, source kodini bajarmaslik, yo‘l chegarasi, SARIF lokatsiyalari, snapshotga bog‘langan review va before/after statik taqqoslashni qamraydi.
- Repositoryni tahlil qilish va natijani o‘qish tuzilgan brauzer amallari orqali bajarildi. Noto‘g‘ri parametrlar rad etildi; joriy natija o‘zgarmadi.
- Lokal API’dan JSON hisobot va SARIF eksport olindi; JSON nusxa asl hisobotga teng, SARIF’da 6 ta natija bor.
- Ikki o‘zgarmagan nusxa API orqali solishtirildi: yangi 0, yo‘qolgan 0, saqlangan 6.
- Vizual screenshot tekshiruvi bajarilmagan. Real crAPI runtime, Docker, firewall va umumiy Python/JS auth qamrovi sinalmagan.


## 0.3 loyiha ulash — 2026-09-09

- Jami 54 ta avtomatik test muvaffaqiyatli; 9 ta yangi onboarding testi qo‘shildi.
- Vaqtinchalik loyihalarda ro‘yxatdan o‘tkazish, CLI, disk yo‘li chegarasi, band/takroriy ID, noto‘g‘ri mapping, manbani o‘zgartirmaslik va kodini bajarmaslik tekshirildi.
- Bir xil fayllarga ega ikki loyiha hisobotlari va review qarorlari ajratilishi, boshqa loyiha hisobotini solishtirish rad etilishi tekshirildi.
- Lokal API profil ro‘yxati, loyiha bo‘yicha hisobot filtri, noma’lum profil va ixtiyoriy disk yo‘li yuborishni rad etish tekshirildi.
- Interfeys JavaScript sintaksisi tekshirildi. Brauzerdagi WebMCP orqali crAPI aniq tanlanib tahlil qilindi; natija qayta o‘qildi. Noma’lum profil rad etilganda oldingi natija o‘zgarmadi.
- Ishlayotgan 0.3.0 serverda JSON/SARIF eksport va ikki crAPI hisobotini taqqoslash tekshirildi: yangi 0, yo‘qolgan 0, saqlangan 6.
- crAPI natijasi: 10 xizmat, 5 loopback port, 12 proxy yo‘l deklaratsiyasi, 6 statik kuzatuv, runtime tasdiq 0.
- Vizual screenshot tekshiruvi bajarilmagan. crAPI runtime va ishlab turgan tashkilot tizimlari tekshirilmagan.


## crAPI runtime pilotini tayyorlash — 2026-09-09

- `pilot.py check` bajarildi: Docker topilmadi, `environment_required`, `security_test: not_run`, `runtime_verified: false`.
- Windows `wsl --status` va `wsl --list --quiet` WSL o‘rnatilmaganini qaytardi. Docker PATH va standart Program Files joyida topilmadi.
- Asl deployment fayllaridan 10 xizmatli pilot konfiguratsiyasi yaratildi. Qayd qilingan farqlar: alohida loyiha, ichki tarmoq, uchta loopback port, demo kalitini faqat o‘qish.
- Yetti yangi test, jami 61 test o‘tdi: pilot tarmoq/port qamrovi, caller environment ta’sirini rad etish, image digestni qayd qilish, digest yetishmasligini rad etish, Docker yo‘qligida muvaffaqiyat chiqarmaslik, masofaviy Docker contextni rad etish, lock orqali port qamrovini o‘zgartirishni rad etish.
- Image digest va Docker context testlari test obyektlari bilan bajarildi; Docker CLI integratsiyasi hisoblanmaydi.
- Docker Compose schema validatsiyasi, image yuklash, konteyner ishga tushirish, xizmatlar mosligi va RP-002 TLS amaliy testi hali bajarilmagan. Ular Docker/WSL o‘rnatilgandan keyin bajarilishi kerak.
