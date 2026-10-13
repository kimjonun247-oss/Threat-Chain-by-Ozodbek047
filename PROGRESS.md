# ThreatChain — beta-tayyorgarlik jurnali

Har yozuv: nima qilindi, buyruq, chiqqan raqam, keyingi qadam. Mashina: Windows 11 Pro, 12 yadro,
7,3 GB RAM, 27 GB bo'sh disk. Vositalar: Semgrep 1.177.0, Gitleaks 8.30.1, Trivy 0.74.0, Nuclei 3.11.1,
rasmiy 1 343 qoidali paket. PMD, CodeQL, Helm, Kustomize o'rnatilmagan. Branch: `beta-readiness`.

## 2026-10-13 — 1-bosqich: baza

| Tekshiruv | Buyruq | Natija |
|---|---|---|
| Unit testlar | `python -m unittest discover -s tests -q` | `Ran 1074 tests in 186.164s` — `OK (skipped=1)` |
| Platforma | `python verify_platform.py` | 9/9 OK, 6 daq 9 s (`validation-runs/platform-windows.json`) |
| Benchmarklar (oflayn) | `python benchmarks/run.py > fayl` | **8 o'tdi, 1 yiqildi, 2 SKIP** (apex — Java yo'q, deep — CodeQL yo'q). Yiqilgani: `fixes` — `UnicodeEncodeError: '→'` |

**Topilgan xato:** natija faylga yo'naltirilganda Windows stdout'i cp1252 bo'ladi; `fixes` natija satridagi
`→` belgisi o'tayotgan tekshiruvni FAIL'ga aylantirardi. Tuzatish: `benchmarks/run.py` da
`stream.reconfigure(errors='replace')`. Tekshiruv: `python benchmarks/run.py --only fixes > fayl` →
`PASS fixes: iac: 5 ... 41 → 36; compose: 13 ... 17 → 3`. Benchmark mezoni o'zgartirilmadi.

Commitlar: `e1f0423` (oldingi raundlar ishi), `93f612a` (benchmark stdout).

**Keyingi qadam:** 2.1 — birinchi skan profili.
