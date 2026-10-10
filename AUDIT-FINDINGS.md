# To'liq kod auditi — topilmalar

Butun loyihani qatorma-qator, har tomonlama ko'rib chiqish. Har bir topilma dalil
(fayl:qator) bilan. Severity: 🔴 kritik · 🟠 jiddiy · 🟡 kichik.

Holat: `ochiq` = tuzatilmagan · `tuzatildi` = commit qilindi · `design` = ataylab shunday.

---

## auth.py

### AUTH-1 ✅ Username enumeration (timing side-channel) — tuzatildi
`login()` (auth.py:201-202) noma'lum foydalanuvchi uchun soxta parol hashini
`hash_password('x', b'0'*16, 1000)` bilan — **1000** iteratsiya hisoblaydi, holbuki
haqiqiy foydalanuvchilar **600000** (ITERATIONS). Natijada: mavjud bo'lmagan login
~0.5ms, mavjud login ~300ms javob beradi. Bu kodning o'z izohida ("timing does not
tell which names exist") da'vo qilingan himoyani buzadi — hujumchi javob vaqtiga qarab
qaysi loginlar mavjudligini aniqlay oladi. **Tuzatma:** soxta hash ham ITERATIONS
ishlatsin (doimiy vaqt).

### AUTH-2 ✅ `read_audit` butun jurnalni xotiraga o'qiydi — tuzatildi
`read_audit()` (auth.py:303-306) `handle.readlines()` bilan append-only, abadiy
o'sadigan audit.jsonl ni to'liq xotiraga oladi, keyin oxiridan kesadi. Uzoq ishlagan
jamoa serverida jurnal GB'larga yetib, har `/api/audit` GET da OOM beradi. Yuk-testdagi
"cheksiz kirish" klassi. **Tuzatma:** fayl oxiridan cheklangan bo'lak o'qish
(seek yoki deque).

### AUTH-4 ✅ `/api/reset/results` faqat operator talab qiladi — tuzatildi
`required_role` (auth.py:254) bo'yicha `/api/reset/results` POST uchun 'operator'
yetarli (ADMIN_PATHS da yo'q). Bu endpoint `reset.clear_results()` — BARCHA skan
natijalari + triage tarixini o'chiradi (app.py:602). Hujjatdagi operator roli
"start/cancel scans, triage" — butun tarixni yo'q qilish undan og'irroq, admin bo'lishi
kerakdek. **Tuzatma:** `/api/reset` ni ADMIN_PATHS ga qo'shish.

### AUTH-3 🟡 `_FAILURES` / `_SESSIONS` cheksiz o'sishi — kuzatuv
Ikkalasi ham tozalanmaydi (faqat kirishda/muvaffaqiyatda). Jamoa serverida turli
manzillar/tokenlar vaqt o'tib yig'iladi. Amalda klient soni bilan cheklangan, restart
tozalaydi. Past xavf.

---

## remote_source.py

### REMOTE-1 ✅ git clone'da SSRF/xususiy-IP himoyasi yo'q — tuzatildi
`check_url` (remote_source.py:43) host sintaksisini tekshiradi, lekin ichki/xususiy
manzillarni (192.168.x, 10.x, 169.254.169.254 metadata, localhost) rad etmaydi.
Operator server'ni ichki git serverlariga yoki metadata endpoint'ga ulanishga
majburlashi mumkin (SSRF). Web-skanda `nettrust` xususiy diapazonlarni bloklaydi —
git clone'da bunday himoya yo'q (nomuvofiqlik). Yengillashtiruvchi: git protokoli
cheklangan, amal operator-avtorizatsiyalangan. **Tuzatma:** host'ni hal qilib (resolve)
xususiy/loopback/link-local diapazonlarni rad etish, nettrust bilan bir xil.

---

## triage.py

### TRIAGE-1 ✅ Jarayonlararo yangilanish yo'qolishi (lost update) — tuzatildi
`decide_many`/`observe` (triage.py:196,224) modul-ichi `LOCK` bilan read-modify-write
qiladi — bu faqat BIR jarayonda serializatsiya. CLI skani `observe()` ni server UI
`decide_many()` bilan bir vaqtda bitta scope'ga yozsa, atomik replace oxirgi yozuvchi
g'olib bo'lib birinchisini o'chiradi (lost update). Yengillashtiruvchi: single-user
dizayn, oyna juda kichik. **Tuzatma:** fayl-qulfi (fcntl/msvcrt) yoki scope bo'yicha
jarayonlararo qulf.

### TRIAGE-2 ✅ `decide_many` yarim-paket eventlari — tuzatildi
Fingerprint format validatsiyasi (triage.py:199) halqa ICHIDA, event yozilgandan keyin.
Agar #3 fingerprint noto'g'ri bo'lsa, #1/#2 uchun event fayllari yozilgan, lekin
`write(scope,data)` ga yetmaydi — audit izi holat faylidan oldinga o'tib ketadi (yetim
eventlar). API (`apply`) fingerprintlarni hisobotda borligini oldindan tekshirgani uchun
hozir triggerlanmaydi, lekin `decide_many` to'g'ridan chaqirilsa latent. **Tuzatma:**
barcha fingerprintlarni event yozishdan OLDIN validatsiya qilish (pre-pass).

### TRIAGE-3 ✅ `events()` sanash uchun barcha event fayllarini pars qiladi — ochiq
`overview()` (triage.py:412) `len(events(scope))` — faqat SONI uchun har bir event
JSON faylini ochib pars qiladi. Tarix o'sgani sari sekinlashadi (AUTH-2 klassi, lekin
yengilroq: kichik fayllar). **Tuzatma:** `os.scandir` bilan parslashsiz sanash.


---

## Tuzatish qaydlari (REMOTE-1, TRIAGE-1)

**REMOTE-1 ✅** — `remote_source.guard_destination()` qo'shildi: `clone()` git'ni ishga tushirishdan oldin host'ni resolve qilib loopback/link-local/metadata/multicast/unspecified manzillarni rad etadi. Xususiy intranet (10.x, 192.168.x) ruxsat etiladi (ichki git serveri qonuniy; code-target'da opt-in yo'q). Eng-yaxshi-harakat (git ulanishda qayta resolve qiladi — rebinding'ga kafolat emas, lekin statik metadata/loopback hujumini to'xtatadi). webscan SSRF bilan izchil.

**TRIAGE-1 ✅** — `decisions` va `seen` alohida fayllarga ajratildi (decisions.json / seen.json). observe() faqat seen.json, decide_many() faqat decisions.json yozadi — jarayonlararo bir-birini bosib o'chirmaydi, inson qarori yo'qolmaydi. Legacy birlashgan fayl orqaga-moslik bilan o'qiladi va keyingi yozuvda ajraladi (seen yo'qolmaydi). Inter-process lock qo'shilmadi — loyihaning atomik-replace dizayniga izchil.
