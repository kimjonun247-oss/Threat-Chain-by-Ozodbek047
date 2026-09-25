# Zanjir demo — sun'iy namuna

Bu **sun'iy o'quv namunasi**, haqiqiy loyiha emas va ishga tushirish uchun mo'ljallanmagan.
Uning yagona vazifasi — ThreatChain'ning asosiy farqi bo'lgan **zanjir qoidalarini** standart
o'rnatmada darhol ko'rsatish.

Bundle qilingan crAPI namunasi barcha xizmatlar uchun tayyor `image:` ishlatadi, `build:` yo'q.
Shuning uchun unda `build.context` bo'lmaydi va **kod + tarmoq** zanjiri (SX-001) hech qachon
chiqmaydi. Ushbu namuna aynan shu bo'shliqni yopadi.

## Qanday ishlatiladi

1. **Repository** bo'limida `chain-demo` profilini tanlang → RP-001, RP-005, RP-006, RP-007,
   RP-008 qoidalari chiqadi.
2. **Umumiy tekshiruv** bo'limida Manba kodi va Repository uchun ikkalasiga ham `chain-demo`
   ni tanlang → yuqoridagilarga qo'shimcha **SX-001** cross-skaner zanjiri chiqadi.

## Nima qasddan noto'g'ri qilingan

| Fayl | Nima | Qaysi qoidani uyg'otadi |
|---|---|---|
| `docker-compose.yml` | `0.0.0.0:8080` ga ochilgan port | RP-001 |
| `docker-compose.yml` | ochiq xizmat + `postgres` bitta tarmoqda | RP-005 |
| `docker-compose.yml` | `DEBUG=true` + ochiq port | RP-006 |
| `docker-compose.yml` | `/var/run/docker.sock` ulangan + ochiq port | RP-007 |
| `docker-compose.yml` | `cap_add: SYS_ADMIN` + ochiq port | RP-008 |
| `app/config.py` | soxta Stripe kaliti, `build: ./app` konteksti ichida | Gitleaks → **SX-001** |
| `force-app/.../AccountController.cls` | Apex: open redirect, SOQL injection, sharing yo'q | PMD → ApexOpenRedirect, ApexSOQLInjection, ApexSharingViolations |

## Sirlar haqida

`app/config.py` dagi kalit **soxta** — hech qachon amal qilmagan va hech qanday xizmatga
tegishli emas. U Gitleaks naqshiga mos kelishi uchun yozilgan. ThreatChain uni topganda ham
qiymatni hisobotga **hech qachon** ko'chirmaydi: hisobotda faqat `secret_value: "hidden"`
va fayl/satr joylashuvi saqlanadi.
