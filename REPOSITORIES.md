# Qaysi repositoryda sinash kerak?

## Birinchi tanlov: OWASP crAPI

Rasmiy repository: https://github.com/OWASP/crAPI

crAPI ataylab zaif qilingan mikroservisli o‘quv ilovasi. Compose xizmatlar va portlarni, Nginx esa xizmatlararo proxy yo‘llarini ko‘rsatadi. Shuning uchun bizning qatlamlar orasidagi bog‘lanishlarni tekshirish maqsadimizga mos. Bu tashkilotning haqiqiy production tizimi emas.

Zanjir 0.2 amalda shu repositoryning quyidagi nusxasida sinaldi:

- Branch: main.
- Commit: `700f03d12a392d9e408260b4beae72ed02a4a1a4`.
- Commit sanasi: 2025-09-22; yuklab olish sanasi: 2026-09-09.
- samples/crapi/ — o‘zgartirilmagan tanlangan source fayllar; butun repository yoki ishlaydigan crAPI deployment emas.
- Asl Apache-2.0 litsenziyasi va arxiv kelib chiqishi saqlangan.

Paketdagi nusxada takrorlash uchun internet va Docker kerak emas:

```text
python app.py --repository-profile crapi
```

Natija: 10 ta xizmat, 5 ta host porti (barchasi loopback), 12 ta proxy route deklaratsiyasi, 6 ta ko‘rib chiqiladigan statik kuzatuv. Ulardan 5 tasi HTTPS upstream uchun proxy_ssl_verify off bilan bog‘liq; bittasi proxy ortidagi MailHog xizmatiga parallel localhost porti mavjudligi. Ikki listen blokida takrorlangan bir xil mantiqiy yo‘l bitta topilma sifatida birlashtiriladi.

Bu **6 ta tasdiqlangan ekspluatatsiya degani emas**. Xizmat ruxsatlari, ishlayotgan image va real tarmoq tekshirilmagan. crAPI ataylab zaif o‘quv loyihasi; natijani yangi zero-day yoki mualliflar bilmagan xato deb taqdim etmang.

Dalil manbalari:

- [Compose](https://github.com/OWASP/crAPI/blob/700f03d12a392d9e408260b4beae72ed02a4a1a4/deploy/docker/docker-compose.yml)
- [.env](https://github.com/OWASP/crAPI/blob/700f03d12a392d9e408260b4beae72ed02a4a1a4/deploy/docker/.env)
- [Nginx TLS template](https://github.com/OWASP/crAPI/blob/700f03d12a392d9e408260b4beae72ed02a4a1a4/services/web/nginx.ssl.conf.template)
- [Template tanlash skripti](https://github.com/OWASP/crAPI/blob/700f03d12a392d9e408260b4beae72ed02a4a1a4/services/web/nginx-wrapper.sh)

## Keyingi nomzodlar

| Repository | Nima uchun | Zanjir uchun hozirgi holat |
|---|---|---|
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | JavaScript/Node.js ilovasida kod tahlili va tuzatishlarni o‘rganish | Tavsiya sifatida ko‘rib chiqildi; maxsus adapter yoki amaliy skan natijasi yo‘q |
| [PyGoat](https://github.com/adeyosemanputra/pygoat) | Python/Django muhitiga yaqin, ataylab zaif o‘quv ilovasi | Django adapteri uchun keyingi nomzod; hozir umumiy auth tahlili qilinmaydi |

[PyGoat rasmiy loyiha sahifasi](https://owasp.org/www-project-pygoat/)

## Kompaniya uchun foydani isbotlash

Keyingi bosqichda egasi va tekshiruv chegarasi aniq bo‘lgan bitta ichki test tizimini tanlang. Ilova, DevOps va tarmoq mas’ullari mapping hamda himoya talabini tasdiqlaydi. Bir xil commit/konfiguratsiya nusxalarini tahlil qiling, topilmalarni qo‘lda tekshiring, tuzatishdan keyin vakolatli kirish saqlanganini tasdiqlang. Shundagina kompaniya uchun real foyda o‘lchanadi.

Ataylab zaif ilovani keyinchalik ishga tushirish kerak bo‘lsa, alohida lokal test muhitidan foydalaning va haqiqiy hujjat/credential qo‘shmang. Joriy Zanjir tahlili bu ilovalarni ishga tushirishni talab qilmaydi.
