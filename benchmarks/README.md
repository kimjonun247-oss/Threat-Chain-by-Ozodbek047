# ThreatChain benchmarklari

Har bir skaner javobi oldindan ma'lum bo'lgan to'plamda o'lchanadi va natija
`expected.json` bilan solishtiriladi. Topish soni kamaysa, yangi noto'g'ri signal paydo bo'lsa,
CI gate qarori o'zgarsa yoki nishonga yuk ortsa — ishga tushirish **yiqiladi**. Shu bilan qoida
paketi yangilanishi, parser o'zgarishi yoki skaner versiyasini ko'tarish aniqlikni jimgina
pasaytira olmaydi.

```
python3 benchmarks/run.py                     # offline guruh (standart)
python3 benchmarks/run.py --group all         # + lockfile'lar va registry image (tarmoq kerak)
python3 benchmarks/run.py --only sast web     # tanlangan tekshiruvlar
python3 benchmarks/run.py --output natija.json
```

| Tekshiruv | To'plam | Talab |
|---|---|---|
| `sast` | 30 ta ma'lum zaiflik (Python, JS, Java, Go, PHP) + xavfsiz fayllar | Rasmiy paket bilan 30/30 topish, gate ≥ 24; faqat lokal qoidalar bilan ≥ 18 / ≥ 12; xavfsiz fayllarda 0 |
| `secrets` | 11 ta soxta sir (git tarixidagi va DB URL bilan) + 3 ta soxta holat | Hammasi topiladi, soxta holatda 0, qiymat hisobotga tushmaydi |
| `apex` | PMD: SOQL injection, sharing, crypto + xavfsiz klass | Uchala qoida, xavfsiz klass toza |
| `iac` | Dockerfile, Kubernetes, Terraform | ≥ 41 topilma, asosiy tekshiruvlar bor |
| `compose` | RP-001…011 ni ishga tushiradigan Compose/Nginx + xavfsiz Compose | 11/11 qoida, RP-005 bitta, xavfsizda 0 |
| `web` | Zaif va tuzatilgan lokal sayt (`servers/web_target.py`) | Barcha kutilgan topilmalar; tuzatilganda faqat HTTP |
| `impact` | So'rovlarni sanaydigan nishon (`servers/impact_target.py`) | 1 ulanish; band server 6 so'rovdan keyin to'xtatiladi; sekin serverda bitta sekinlashuv |
| `gate` | Yuqoridagilar ustida `ci_gate.py` | Chiqish kodlari 0 / 1 / 1 |
| `lockfiles` *(online)* | 9 ta mashhur loyihaning commit'ga pinlangan lockfile'i | Paket va bo'shliq soni aniq mos |
| `image` *(online)* | `python:3.9.0-alpine` | To'g'ridan-to'g'ri Trivy bilan to'liq mos; SBOM zaifliklari to'liq |

**Izolyatsiya.** Hamma narsa vaqtinchalik `THREATCHAIN_DATA_DIR` ga yoziladi — operatorning
hisobotlari, ro'yxatlari va triage qarorlariga tegilmaydi. O'rnatilmagan vosita `SKIP` bo'ladi,
hech qachon `PASS` emas.

**Sirlar.** Haqiqiy formatdagi soxta tokenlar ishga tushirish vaqtida qat'iy seed bilan yaratiladi;
omborga birorta token shaklidagi satr yozilmaydi (GitHub push protection va sir skanerlari uchun) —
buni `tests/test_benchmark_corpus.py` qo'riqlaydi.

**Kutilgan qiymatni o'zgartirish** faqat ongli qaror bilan: yangi qoida topishni oshirsa, chegarani
ko'taring; kamaytirish kerak bo'lsa, sababini commit xabarida yozing.

Mutatsion tekshiruv (2026-09-26): lokal ERROR qoidalari olib tashlanib, rasmiy paket yashirilganda
`sast` 10/30 va gate 0 bilan yiqildi — benchmark regressiyani ushlaydi.
