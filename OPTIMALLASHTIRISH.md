# Optimallashtirish rejasi — 2026-09-18

Bu reja **taxminlarga emas, o'lchovlarga** asoslangan. Har bir qadamda: nima o'lchandi,
kutilayotgan foyda qanday olindi, va nima buzilishi mumkin.

Qayerda raqam **o'lchangan** bo'lsa, shunday yozilgan. Qayerda **baholangan** bo'lsa, ham
shunday yozilgan — ikkalasi aralashtirilmagan.

Joriy holat: 336 test, 41 Python fayl / 6 347 satr, 7 JS fayl / 568 satr.

---

## Natijalar — 2026-09-18, bajarildi

Barcha raqamlar **o'lchangan**, crAPI ustida, xuddi shu mashinada.

| Qadam | Oldin | Keyin | Tezlanish | Natija o'zgardimi |
|---|---|---|---|---|
| 1. Qoidalarni birlashtirish (Semgrep) | 36.1 s | 9.0 s | **4.0×** | Yo'q — 138 = 138 (A/B) |
| 1. Kod skani, CLI to'liq | 39 s | 18.8 s | **2.1×** | Yo'q |
| 3. `dependencies.history()` | 84 ms | 0.8 ms | **105×** | Yo'q |
| 3. `portfolio.overview()` | 89 ms | 5.1 ms | **17×** | Yo'q |
| 2. To'liq quvur (kod+repo+CVE+image) | 170 s | 15.8 s | **~11×** | Yo'q — bir xil sonlar |
| Qo'shimcha: image qayta skani | 172 s | 3.3 s | **52×** | Yo'q — 169 = 169 |

Quvurdagi yutuqning katta qismi parallellikdan emas, rejada **ko'zda tutilmagan** ikki topilmadan keldi:

- **Trivy bazani skan ichida yangilardi.** Har ~kunda bir marta, 7.7 daqiqalik skanning 4.3 daqiqasi.
  Endi baza yangilanishi skan oldidan alohida qadam; yangilanmasa skan eski baza bilan davom etadi
  va `partial` deb belgilanadi.
- **`--max-image-size` keshni chetlab o'tardi.** Ochilgan hajmni bilish uchun Trivy har safar barcha
  qatlamlarni qayta yuklardi (143 s vs 3 s). Digest o'zgarmas bo'lgani uchun, bir marta chegaradan
  o'tgan digest qayta tekshirilmaydi; har bir **yangi** digest uchun chegara baribir qo'llanadi.

### Reja bilan farqlar — halol

- **Qadam 2 kutilganidek emas.** Rejada `web` ham parallel bo'lishi mumkin deb yozilgan edi.
  `test_cancel_before_next_stage_never_starts_it` testi buni to'xtatdi: bekor qilish faol web
  skanni (foydalanuvchi tizimiga haqiqiy so'rov) boshlanishidan oldin to'xtatishi shart. Shuning
  uchun faqat **passiv** bosqichlar parallel; web oxirida alohida. Test yangi, muhimroq shartnomaga
  almashtirildi va mutatsiya bilan tekshirildi (ketma-ket rejimda yiqiladi).
- **Qadam 1 ikki marta xato qilindi.** Birinchi urinishda o'rnatuvchi eski paketni **tekshirishdan
  oldin** o'chirdi va yiqilgach qoidalarsiz holat qoldi; ikkinchisida birlashtirilgan fayl registr
  papkasi ichiga yozilib, papka konfiguratsiyasi har bir qoidani ikki marta yuklardi — bu mening
  birinchi A/B solishtiruvimni ham yaroqsiz qildi. Ikkalasi tuzatildi va A/B qayta, toza o'tkazildi.
- **Birinchi marta ko'rilgan katta image hali ham tarmoqqa bog'liq.** Hajm tekshiruvi qatlamlarni
  yuklashni talab qiladi. `crapi-identity` bugun ertalab 31 s da o'tdi, kechqurun 11 daqiqa chegarasida
  yiqildi — Docker Hub tezligi ~20× o'zgaradi. Yiqilish aniq xabar bilan qayd etiladi.

---

## Qadam 1 — Semgrep qoidalarini bitta faylga birlashtirish ⭐ eng katta foyda

**O'lchandi.** Semgrep'ning o'z profil ma'lumoti (`--json` chiqishidagi `profiling_times`)
4 ta fayllik sun'iy loyihada:

```
config_time  33.2 s   ← 1327 ta YAML faylni o'qish va parse qilish
core_time     0.5 s   ← haqiqiy skan
total        33.8 s
```

Ya'ni **vaqtning ~98% i qoida yuklashga ketadi**, skanga emas. Loyiha kattaligi bunga deyarli
ta'sir qilmaydi: crAPI'ning 485 fayli ham ~39 s da tugaydi — farq atigi bir necha soniya.

**Tekshirildi.** 1343 qoidani bitta 2 MB li YAML ga birlashtirib o'lchadim:

```
config_time  33.2 s → 6.5 s
total        33.8 s → 7.1 s      (4.7×)
```

Natijalar bir xil chiqdi (o'sha 2 topilma).

**Qanday qilinadi.** `setup_semgrep_rules.py` o'rnatish vaqtida, SHA-256 tekshiruvidan **keyin**,
qoidalarni bitta `merged.yml` ga yozadi. Alohida fayllar o'z joyida qoladi — manifest yaxlitligi
tekshiruvi ular ustida ishlashda davom etadi. `scanners.py` esa `--config` ga birlashtirilgan
faylni beradi.

**Nima buzilishi mumkin.** Birlashtirish qoida ID'larini o'zgartirmasligi kerak (`--no-rewrite-rule-ids`
allaqachon berilgan), va `registry_messages()` matnni alohida fayllardan o'qiydi — u o'zgarmaydi.
Test: birlashgan va birlashmagan konfiguratsiya **bir xil topilmalar to'plamini** berishini
tasdiqlovchi tekshiruv qo'shilsin.

---

## Qadam 2 — Quvur bosqichlarini parallel bajarish

**O'lchandi.** `pipeline.execute()` bosqichlarni oddiy `for` siklida ketma-ket bajaradi
(`zanjir/pipeline.py`, `requested` ro'yxati). Jonli crAPI bilan to'liq quvur **67 soniya**
oldi: kod ~40 s + CVE ~15 s + web ~8 s + image ~5 s.

**Kutilayotgan foyda — baholangan, o'lchanmagan.** Kod, CVE, web va image bosqichlari bir-biriga
bog'liq emas (faqat SX-001 korrelyatsiyasi kod **va** repository tugashini kutadi). Ularni
parallel bajarish vaqtni yig'indidan eng uzun bosqichga tushiradi: 67 s → ~40 s. Qadam 1 dan
keyin kod bosqichi qisqargach, bu yanada seziladi (~15 s atrofida).

**Nima buzilishi mumkin — bu qadam eng xavflisi.** Hozir bekor qilish (`cancel`) ketma-ketlikka
tayanadi: "joriy bosqich tugaydi, keyingilari boshlanmaydi". Parallel holatda bu mantiq qayta
yozilishi kerak. Bundan tashqari Semgrep ham, Trivy ham xotira talab qiladi — bir vaqtda
ishlatish kam xotirali mashinada ikkalasini ham sekinlashtirishi mumkin. Shuning uchun:

- avval **faqat ikkita** bosqichni birlashtirish (web + image — ikkalasi ham I/O ga bog'liq),
- xotira o'lchovini olish,
- keyin kod/CVE ni qo'shish.

---

## Qadam 3 — Hisobot ro'yxatini indekslash

**O'lchandi.** Har bir `history()` 30 qator qaytaradi, lekin buning uchun **barcha** hisobot
fayllarini o'qiydi:

| Modul | Vaqt | Fayllar |
|---|---|---|
| `dependencies` | 84 ms | 86 |
| `pipeline` | 58 ms | 28 |
| `images` | 24 ms | 24 |
| `scanners` | 15 ms | 47 |
| `repo_store` | 10 ms | 31 |
| **`portfolio.overview()`** | **89 ms** | oltalasini chaqiradi |

Bu **fayl soniga chiziqli o'sadi**. Bir yil ishlatilgan o'rnatmada minglab hisobot bo'ladi va
boshqaruv paneli har ochilganda hammasini o'qiydi.

**Qanday qilinadi.** Har bir papkada kichik `index.json`: `{id, target, created_at, state, count}`.
Skan tugaganda bitta qator qo'shiladi. `history()` faqat indeksni o'qiydi.

**Nima buzilishi mumkin.** Indeks haqiqatdan ajralib qolishi mumkin. Shuning uchun: indeks
**kesh**, manba emas — yo'q yoki buzilgan bo'lsa, kod avvalgidek papkani skanerlab qayta quradi.
Hisobotning o'zi hech qachon indeksdan o'qilmaydi.

---

## Qadam 4 — Beshta modulda takrorlangan naqshni birlashtirish

**O'lchandi.** `scanners`, `dependencies`, `images`, `webscan`, `pipeline` — beshalasida bir xil
naqsh mustaqil yozilgan: `history()`, `read()`, `CANCEL` lug'ati, ID regex, hisobot yozish.
`webscan.py` 709 satr, `scanners.py` 524 satr.

**Foyda — kod sifati, tezlik emas.** Bu qadam hech narsani tezlashtirmaydi. U **xatolar
takrorlanishini** kamaytiradi: shu sessiyada topilgan A12 (test ishlab chiqarish ma'lumotlariga
yozgan) va A13 (yiqilgan skan "tekshirilgan" deb sanalgan) aynan shu naqshning har bir nusxasida
alohida-alohida tuzatilishi kerak bo'lgan turdagi xatolar.

**Nima buzilishi mumkin.** Refaktoring keng tarqaladi. Faqat 336 test yashil turganda va kichik
qadamlar bilan qilinishi kerak: avval `read()`+ID tekshiruvi, keyin `history()`, keyin bekor
qilish. Har qadamdan keyin to'liq to'plam.

---

## Qadam 5 — Frontend'da umumiy holat

**O'lchandi.** 7 ta JS fayl (568 satr), har biri mustaqil `fetch` qiladi. Sahifa ochilganda
`/api/readiness`, `/api/portfolio`, `/api/rules`, oltita `/reports` va boshqalar — hammasi
alohida so'rov.

**Foyda — baholangan.** Lokal serverga so'rov arzon, shuning uchun tezlik foydasi kichik.
Asosiy foyda — izchillik: hozir bir bo'lim ma'lumotni yangilaganda boshqasi eskirgan holatda
qoladi (shu sessiyada portfel bilan aynan shunday bo'ldi).

**Ustuvorlik: past.** Qadam 1–3 dan keyin qilinadi.

---

## Qilinmasligi kerak bo'lganlar

Bular "optimallashtirish" bo'lib ko'rinadi, lekin loyihaning asosiy tamoyillarini buzadi:

- **Qoida sonini kamaytirib tezlashtirish.** Qadam 1 vaqtni 4.7× qisqartiradi va **birorta
  qoidani ham olib tashlamaydi**. Qamrovni tezlik uchun almashtirish kerak emas.
- **Xatolarni yashirib `partial` ni `completed` qilish.** C1 da aynan buning teskarisi qilindi:
  bo'shliq **ko'rsatiladi** va harakat taklif qilinadi.
- **Trivy'ning 1 GB yoki 11 daqiqa chegarasini shunchaki ko'tarish.** C6 da ildiz sabab (baza
  yuklash) yo'q qilindi — chegara emas. Chegara mahsulot kafolatining bir qismi.
- **Hisobotlarni avtomatik o'chirib joy tejash.** Ular dalil. A12 da test artefaktlari haqiqiy
  crAPI dalillarini ro'yxatdan siqib chiqargani ko'rsatdiki, dalil yo'qolishi jimgina sodir
  bo'ladi.

---

## Tavsiya etilgan tartib

1. **Qadam 1** — o'lchangan 4.7× foyda, xavfi past, bitta fayl o'zgaradi.
2. **Qadam 3** — hozir 89 ms, lekin vaqt o'tishi bilan yomonlashadigan yagona joy.
3. **Qadam 2** — eng katta arxitektura xavfi; Qadam 1 dan keyin foydasi ham kamayadi, shuning
   uchun avval 1 ni bajarib qayta o'lchash kerak.
4. **Qadam 4** — tezlik bermaydi, lekin kelajakdagi xatolarni kamaytiradi.
5. **Qadam 5** — ixtiyoriy.

**Har qadamdan oldin:** to'liq test to'plami yashil bo'lsin. **Har qadamdan keyin:** o'sha
o'lchovni qayta oling va haqiqiy foydani yozib qo'ying — bu hujjatdagi raqamlar taxmin emas,
o'lchov bo'lib qolsin.
