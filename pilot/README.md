# crAPI amaliy pilot — tayyorlash bosqichi

**2026-09-10 holati:** Docker/WSL o‘rnatildi, 10 ta image digest qayd qilindi. Mahalliy kirish tuzatishi qo‘llangach, 12:57 (Asia/Tashkent) natijasida barcha 10 ta konteyner ishlayotgan, crAPI va MailHog sahifalari HTTP 200 qaytargan. Soat 13:02 da agent ikkala sahifani mustaqil qayta tekshirdi: ikkalasi ham HTTP 200. Foydalanuvchi ham crAPI sahifasi ochilganini tasdiqladi. Dalillar: `runtime/status.json`, `runtime/http-readiness.json`, `runtime/independent-http-check.json`. Bu xizmatlarning ochilishini tasdiqlaydi; xavfsizlik sinovi hali bajarilmagan.

## Konteynerlar ishlaydi, lekin sahifa ochilmaydi

Asosiy konfiguratsiyada barcha xizmatlar faqat `internal` tarmoqqa ulangan. Docker’da bunday xizmatlar uchun so‘ralgan host portlari ochilmasligi qayd etilgan: https://github.com/moby/moby/issues/36174.

Asosiy papkadagi **PILOT-FIX.cmd** ni oching. U `python pilot.py repair-access` amalini bajaradi: aniq saqlangan imagelar bilan faqat `crapi-web` va `mailhog` xizmatlarini yangilaydi, image yuklamaydi va bazaning volume’larini o‘chirmaydi. `compose.access.json` qo‘shimchasi bu ikkita xizmatga `local_access` bridge tarmog‘ini beradi; ular ichki tarmoqqa ham ulangan qoladi. Host portlari 127.0.0.1 bilan cheklangan. Qolgan sakkiz xizmat faqat ichki tarmoqda qoladi. Ikki kirish xizmati uchun tashqariga chiqish imkoniyati bor: bu to‘liq outbound izolyatsiya emas.

Tuzatish Docker’da qo‘llanib, ikkala HTTP sahifa ham javob berganidan keyingina muvaffaqiyat qayd qilinadi. `runtime/http-readiness.json` tekshiruv vaqtini va natijasini saqlaydi; `runtime/status.json` endi vaqt hamda HTTP holatini ko‘rsatadi. HTTP javobi xavfsizlik zaifligini tasdiqlamaydi. Tuzatish ushbu kompyuterdagi amaldagi konteynerlarda qo‘llanib, yuqoridagi HTTP tekshiruvlaridan o‘tdi.

## Sizdan yangi repository kerak emas

Rasmiy crAPI loyihasining saqlangan deployment fayllari bilan ishlaymiz. `upstream/` ichida asl Compose, `.env`, sun’iy demo kaliti va litsenziya bor. `provenance.json` commit va fayl xeshlarini saqlaydi. Ishga tushirish rasmiy loyiha hujjatlaridagi prebuilt image usuliga asoslanadi: https://owasp.org/crAPI/docs/setup.html.

## Avval Windows muhitini tayyorlash kerak

1. WSL 2 o‘rnatish: https://learn.microsoft.com/en-us/windows/wsl/install. Windows administrator tasdig‘i va qayta ishga tushirish talab qilishi mumkin.
2. Docker Desktop o‘rnatish: https://docs.docker.com/desktop/setup/install/windows-install/. O‘rnatish va litsenziya oynalarini foydalanuvchi ko‘rib chiqadi.
3. Docker Desktop’ni oching va Linux engine tayyor bo‘lishini kuting. Muhit tayyorligini quyidagi `check` amali tekshiradi.

## Tayyor vosita

Windows uchun qulay boshlash: asosiy papkadagi **PILOT-START.cmd** faylini oching. U avval Docker tayyorligini tekshiradi, keyin crAPI imagelarini yuklaydi va xizmatlarni ishga tushiradi. Har bir bosqich muvaffaqiyatli tugagandagina keyingisiga o‘tadi. Yuklash jarayoni oynada ko‘rinadi. Docker Desktop oldindan ochilgan va `Engine running` holatida bo‘lishi kerak. Administrator sifatida ishga tushirish shart emas; mahalliy foydalanuvchi muhiti ishlatiladi.

Buyruqlar Zanjir asosiy papkasidan bajariladi. `python` kompyuterdagi Python 3.10+ dasturini bildiradi.

```text
python pilot.py check
python pilot.py pull
python pilot.py start
python pilot.py status
```

- `check` — Docker borligi, lokal Linux engine va Compose’ni tekshiradi. O‘zi hech narsa o‘rnatmaydi.
- `pull` — image fayllarini yuklaydi va ularning aniq SHA-256 digestlarini saqlaydi. Dastlab internet va disk joyi kerak. Bu hali ilovani ishga tushirmaydi.
- `start` — faqat qayd qilingan imagelarni ishga tushiradi. Yangisini avtomatik yuklamaydi yoki build qilmaydi. Xizmatlarning tayyor bo‘lishini kutadi.
- `status` — konteynerlar holatini ko‘rsatadi. Ishlayotgan konteyner zaiflik tasdiqlandi degani emas.
- `stop` — faqat `zanjir-crapi-pilot` sinov loyihasini to‘xtatib, konteynerlarini olib tashlaydi. Sinov ma’lumotlari saqlangan volume’lar qoladi.

```text
python pilot.py stop
```

Tekshirilgan mahalliy kirish: crAPI http://127.0.0.1:18888/, sinov xatlari http://127.0.0.1:18025/. Oxirgi mavjudlik dalili yuqorida qayd etilgan.

## Ajratilgan konfiguratsiya

Pilot faqat localhost’ga uchta port chiqaradi: 18888, 18443 va 18025. Xizmatlar alohida ichki Compose tarmog‘iga biriktiriladi. Tashqi API kalitlari berilmaydi. Chatbotning internet talab qiladigan funksiyalari ushbu pilot qamroviga kirmaydi. Docker tarmog‘i virtual mashina darajasidagi to‘liq izolyatsiya degani emas; amaliy tarmoq chegaralari ishga tushirgandan so‘ng tekshiriladi.

Asl konfiguratsiyadan farqlar: alohida loyiha nomi, global container nomlarini olib tashlash, ichki tarmoq, uchta lokal port, demo kalit papkasini faqat o‘qish. Shu sabab bu pilotdagi natijani asl konfiguratsiyaga avtomatik ko‘chirmaymiz.

`runtime/compose.lock.json` va `images.json` yuklangan imagelarni aniq qayd qiladi. Upstream `latest` taglari vaqt o‘tishi bilan o‘zgaradi. Digest ularni keyingi ishga tushirish uchun qotiradi, lekin image aynan saqlangan manba commitidan qurilganini isbotlamaydi. Dastlabki ishga tushirishda xizmatlar mosligi ham tekshirilishi kerak.

## Birinchi xavfsizlik sinovi: RP-002

**Dalil yig‘ish tayyor:** asosiy papkadagi `PILOT-CHECK.cmd` ni ochish `pilot_evidence.py` vositasini bajaradi. U faqat lokal pilotdagi bitta `crapi-web` konteynerini tanlaydi, loyiha/service belgilarini va image ID’sini locked image bilan tekshiradi. `openresty -T` orqali konfiguratsiya tekshiriladi va dump olinadi; `/etc/nginx/conf.d/default.conf` nusxasi dump bilan solishtiriladi. Konteyner qayta ishga tushirilmaydi, konfiguratsiyasi tahrirlanmaydi, image yuklanmaydi. Natijalar `pilot/evidence/<vaqt-id>/` ichida JSON, o‘qiladigan Markdown va SHA-256 bilan saqlanadi. Joriy source-only hisobot ID’si ham bog‘lanadi. Nginx `-T` diskdagi fayllarni o‘qiydi, ishlayotgan worker xotirasidagi konfiguratsiya bilan tengligini isbotlamaydi: https://nginx.org/en/docs/switches.html.

Kuzatuv `explicit_tls_verification_disabled_observed` bo‘lsa ham bu konfiguratsiya dalili, amaliy TLS hujumi tasdig‘i emas. Yo‘l yoki sozlama mos kelmasa `needs_review` yoki `analysis_unknown` chiqadi. **2026-09-10 13:41:** `20260910T084123-c563a4a0` dalili olindi: `default.conf` 41-satrda `/identity/` upstream `https://crapi-identity:8080`, 45-satrda `proxy_ssl_verify off`. SHA-256 qayta tekshirildi. Source-only hisobot: `20260910T084123-88116f14`. Image va konteyner identifikatorlari dalil hisobotida saqlangan.

### Ajratilgan TLS tajribasi

`PILOT-TLS-TEST.cmd` vositasi tayyor. U aynan dalildagi crAPI web image nusxasidan vaqtinchalik bitta konteyner yaratadi (`--pull never`). `--network none`, host portsiz, root bo‘lmagan foydalanuvchi, faqat o‘qiladigan fayl tizimi va vaqtinchalik `/tmp` bilan ishlaydi. Asl crAPI konteynerlari, sozlamalari va bazasi o‘zgarmaydi. Test tugagach faqat yangi yaratilgan konteyner ID’si bo‘yicha o‘chiriladi; o‘chirish xatosi alohida qayd qilinadi.

Sinov sertifikatlari mavjud bundled Python’dagi `cryptography` yordamida yaratiladi; Windows ishonch omboriga o‘rnatilmaydi. Sinov ishonchli va ishonchsiz ikki CA, bir xil xizmat nomi hamda ikki sun’iy HTTPS javobidan foydalanadi. OpenResty konfiguratsiyasi har bir nazorat uchun CA, SNI va nomni aniq belgilaydi:

| Nazorat | Kutilgan javob |
|---|---|
| Tekshiruv off + ishonchsiz sertifikat | HTTP 200 va aynan ishonchsiz test xizmatining belgisi |
| Tekshiruv on + ishonchsiz sertifikat | HTTP 502 va aynan shu so‘rovga oid certificate verify error |
| Tekshiruv on + ishonchli sertifikat va to‘g‘ri nom | HTTP 200 va aynan ishonchli test xizmatining belgisi |
| Tekshiruv on + ishonchli sertifikat, noto‘g‘ri nom | HTTP 502 va aynan shu so‘rovga oid nom mos emas xatosi |

Faqat HTTP 502 yoki xizmat ishlamay qolishi muvaffaqiyat hisoblanmaydi. Har bir javobga noyob test belgisi bog‘lanadi; xato sababi Nginx jurnali bilan solishtiriladi. Natijalar `pilot/tls-runs/<id>/report.json`, `manifest.json` va jurnallarga yoziladi. `runtime/latest-tls-test.json` oxirgi natijaga ko‘rsatadi.

Bu tajriba bir xil web image’da sozlamaning xatti-harakatini tekshiradi. U asl crAPI tarmog‘ida hujumchi trafik yo‘liga kira olishini isbotlamaydi va crAPI’ga tayyor tuzatish qo‘llamaydi. **2026-09-10 14:17: Docker’dagi to‘rt nazorat ham o‘tdi.** `tls-runs/20260910T091714-055ace44/report.md` o‘qiladigan xulosani beradi. HTTP natijalar ketma-ketligi: 200, 502, 200, 502; ikkala rad etish sababi tegishli so‘rovning Nginx xato jurnali bilan tasdiqlangan. Agent 12 ta fayl/image moslik tekshiruvini va to‘rtta nazorat hisobini qayta bajardi (`review.json`). Hisobotda vaqtinchalik konteyner olib tashlangani qayd etilgan. Asl crAPI uchun amaliy hujum yo‘li va qo‘llangan tuzatish hali tasdiqlanmagan.

Tanlangan kuzatuv: `/identity/` yo‘lidagi upstream TLS sertifikati tekshirilmayotgani. Bu hali hujumchi trafikni o‘zgartira olishini isbotlamaydi.

1. Ishlayotgan `crapi-web` ichidagi haqiqiy Nginx konfiguratsiyasini saqlangan manba bilan solishtirish. Yo‘l va `proxy_ssl_verify off` mos kelmasa, tajriba shu kuzatuvning tasdig‘i hisoblanmaydi.
2. Alohida sinov nusxasida boshqariladigan HTTPS xizmat va ikki sinov sertifikati tayyorlash: ishonchli va ishonchsiz. Asl crAPI ma’lumotlari yoki sertifikatlari ustiga yozmaslik.
3. Tekshirish o‘chirilgan holatda ishonchsiz sertifikat orqali kelgan javob qabul qilinadimi — haqiqiy proxy javobi bilan qayd qilish.
4. Ishonchli CA, xizmat nomi va SNI sozlamalari bilan tekshirishni yoqish. Ishonchsiz sertifikat rad etilishi, ishonchli sertifikat bilan odatiy javob ishlashi kerak.
5. Boshlang‘ich va tuzatilgan konfiguratsiyalarni Zanjir bilan qayta tahlil qilish; statik farq va HTTP/TLS dalillarini alohida saqlash.

Konfiguratsiyadan dalil olish va aynan bir xil web image’da ajratilgan TLS nazorat tajribasi bajarildi. `pilot.py` muhit hayot siklini, `pilot_evidence.py` konfiguratsiya dalilini, `pilot_tls.py` nazorat tajribasini bajaradi. Asl crAPI uchun CA/nomga mos tuzatishni qo‘llash, undan oldin/keyin statik tahlil hamda haqiqiy identity xizmatining odatiy ishlashini qayta tekshirish hali bajarilmagan.
