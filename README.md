# Cybersecurity Internship — DevelopersHub
**Intern:** Kamran Ahmad  DHC-1264
**Deadline:** May 15, 2026

## Week 1 — Security Assessment
- Scanned app using OWASP ZAP
- Found 11 vulnerabilities (SQL Injection, CSP, Clickjacking etc.)

## Week 2 — Implementing Security Fixes
- bcrypt password hashing
- JWT authentication
- Helmet.js security headers
- Input validation with validator
- Rate limiting with express-rate-limit

## Week 3 — Advanced Security
- Penetration testing (XSS, SQL Injection, Brute Force — all blocked)
- Winston security logging
- Security checklist (22 items)
- Full frontend (Login, Register, Profile)

## ✅ Week 4 — Advanced Threat Detection & API Security
- **Fail2Ban Simulation** — Bans IP after 5 failed login attempts for 10 minutes
- **API Key Authentication** — `/api/data` route protected with API keys
- **CORS** — Restricted to same origin only
- **Tightened CSP** — Removed unsafe-inline, blocked iframes and plugins
- **HSTS** — Strict Transport Security for 1 year
- **Environment Variables** — All secrets moved to .env

 Security Tests — Week 4
| Test | Attack Type | Result |
|------|-------------|--------|
| No API key | Unauthorized access | ✅ 401 Blocked |
| Wrong API key | Invalid credentials | ✅ 401 Blocked |
| Correct API key | Legitimate access | ✅ 200 Accepted |
| 11 login attempts | Brute force | ✅ Rate limited |
| `<script>alert(1)</script>` | XSS attack | ✅ Rejected |
| `admin OR 1=1` | SQL Injection | ✅ Blocked |
| 6 failed logins | Fail2Ban trigger | ✅ IP Banned |

---

## 🔒 Security Packages Used
| Package | Purpose |
|---------|---------|
| `helmet` | HTTP security headers |
| `bcrypt` | Password hashing |
| `jsonwebtoken` | JWT authentication |
| `validator` | Input validation & sanitization |
| `express-rate-limit` | Brute force protection |
| `cors` | Cross-origin restrictions |
| `dotenv` | Environment variable management |
| `winston` | Security event logging |
