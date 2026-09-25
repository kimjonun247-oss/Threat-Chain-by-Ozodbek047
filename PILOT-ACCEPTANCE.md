# Zanjir 0.5 — AI ishlatilmaydigan pilotni qabul qilish

## Maqsad

Bitta ruxsatli loyiha uchun manba kodi, paket versiyalari, public container image va ishlayotgan web/API bo‘yicha dalillar olish. Operator topilmalarni tekshiradi, tuzatish kiritadi va qayta tekshiradi. Bu ko‘p foydalanuvchili server yoki to‘liq pentest o‘rnini bosuvchi mahsulot emas.

## Kompyuteringizda yakuniy sinov

1. Docker Desktop’ni oching. `Engine running` bo‘lsin.
2. `PILOT-START.cmd` ni oching. Mavjud crAPI image’lari qayta ishlatiladi. `http://127.0.0.1:18888/` ochilishini tekshiring.
3. `START-PILOT.cmd` ni oching; `http://127.0.0.1:8766/` ga kiring. Oynani ochiq qoldiring. 8765 — agent preview, 8766 — siz ochgan Windows serveri.
4. **Umumiy tekshiruv**: manba `crapi-full`, web `pilot-crapi`, image `pilot-crapi-web`; online katagini belgilang va boshlang. Shu jarayonni `PILOT-VERIFY.cmd` ham boshlaydi. Ikkalasini bir vaqtda boshlamang.
5. Har bir bosqich yakunlanganini tekshiring. `partial` qamrov cheklovini yoki bajarilmagan skanerni bildiradi. `failed` va `cancelled` natijalari qabuldan o‘tmaydi. `not_selected` — tekshirilmagan.
6. Kod bosqichida **Semgrep completed** va **Gitleaks completed** bo‘lishini tekshiring. Semgrep Windows certificate-store xatosi bersa, kod qamrovi hali tasdiqlanmagan. Sertifikat tekshiruvi yoki Windows himoyasi o‘chirilmaydi.
7. JSON va o‘qiladigan hisobotni saqlang. Bir nechta yuqori ustuvorlikdagi topilmani mutaxassis bilan tekshiring.

## Internetdagi o‘z loyihangiz

`CHECK-PROJECT.cmd` orqali manba papkasini kiriting. `CHECK-WEB.cmd` orqali aniq URL, ruxsat bergan mas’ul va lokal/intranet holatini kiriting. Yangi nishon uchun boshqa ID ishlatiladi; eski ruxsat doirasi yashirincha almashtirilmaydi. Brauzer API’si erkin URL yoki buyruq qabul qilmaydi.

Ruxsat butun origin uchun bo‘lmasa bazaviy yo‘lni ham kiriting, masalan `https://staging.example.com/my-app`. Bu manzil namuna; haqiqiy ruxsatli manzilingiz bilan almashtiring. Redirect bo‘lsa yakuniy manzilni ruxsat doirasi bilan alohida ro‘yxatdan o‘tkazing. Ushbu versiyada login/cookie/token bilan tekshirish yo‘q.

## Qabul mezonlari

| Mezon | Dalil |
|---|---|
| Qo‘llanadigan paketlar OSV bilan solishtirilgan | Tekshirilgan/so‘ralgan paket soni, query xatolari, baza vaqti |
| Skaner xatosi toza natija deb ko‘rsatilmagan | Har bir vosita va umumiy jarayon holati |
| Ochiq fayl uchun 200 OK dan kuchliroq dalil bor | Mazmun naqshi, javob kodi, vaqt va javob xeshi |
| Sir qiymati eksportda yo‘q | Nazoratdagi sun’iy sir report JSON/Markdown da yo‘q |
| Nishon doirasi saqlangan | GET, exact origin/base path, DNS pinning, redirect taqiqi, so‘rov limitlari |
| Tuzatish qayta tekshirilgan | Xuddi shu qamrovdagi oldingi/keyingi natija va funksional test |
| Samaradorlik o‘lchangan | Operatorning sarflagan vaqti, tasdiqlangan/noto‘g‘ri topilmalar, o‘tkazib yuborilgan nazorat xatolari |

## Saqlangan nazorat dalili

`validation-runs/web-control/result.json`: haqiqiy Nuclei 3.11.1 sun’iy localhost serverga ishlatilgan. Zaif holatda 6 Nuclei mosligi, tuzatilgan holatda 0; barcha yo‘llarga bir xil javob qaytarilgan holatda aniq fayl mosligi chiqarilmaydi. Fallback javobning o‘zida sezgir mazmun bo‘lgani uchun alohida ogohlantirish va `partial` holat qoladi. Har holat 12 so‘rov. Tuzatilgan misol HTTP laboratoriyasi bo‘lgani uchun alohida past darajali HTTP kuzatuvi qoladi.

`validation-runs/osv-control/result.json`: lodash versiyasi o‘zgargach aynan belgilangan OSV yozuvi mosligi yo‘qolgan; bu paketning barcha zaifliklari bartaraf etilgan degani emas.

## 2026-09-15 da tekshirilgan holat

14-sentabrda barcha skanerlar ishga tushgan: kod 6 Semgrep + 10 Gitleaks, kutubxonalar 263, lokal crAPI web 5, gateway-service image 397 moslik/kuzatuv. Dalillar va turli image nishonlari farqi [README.md](README.md) da berilgan. Semgrep muvaffaqiyati endi saqlangan hisobot bilan tasdiqlangan.

15-sentabrda 151 avtomatik test hamda haqiqiy Nuclei bilan 4 nazorat holati o‘tdi. Online OSV eski/tuzatilgan versiya nazorati ham o‘tdi. `206` javobidagi to‘liq mazmunni qisman deb ko‘rsatish va rasmiy Git qoidasining uni o‘tkazib yuborishi tuzatildi. Asl HTTP holati hisobotda saqlanadi. Bu tuzatishning real crAPI qayta skani hali olinmagan.

## Hali bajarilmagan

Haqiqiy kompaniya URL skani (URL hali berilmagan), crAPI web xizmatini qayta ishga tushirib tuzatishdan keyingi yangi web natijasini olish va real topilmalarni mutaxassis bilan baholash. Agent Docker’ni ishga tushirganda `Access denied` olmoqda; shu kompyuterda Docker Desktop va PILOT-START.cmd orqali laboratoriyani ochish kerak. Kutubxonadagi 6 inventar bo‘shlig‘i hali qolgan. Keyingi mahsulot bosqichida foydalanuvchi/loyiha izolyatsiyasi, markaziy server, VS Code kengaytmasi va autentifikatsiyalangan DAST kerak bo‘ladi.
