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

 Week 5 — Ethical Hacking & Exploiting Vulnerabilities
Attacked SecureApp from Kali Linux using professional penetration testing tools, documented all findings, and implemented CSRF protection.

Task 1 — Reconnaissance
Tool	Command	Key Finding
curl	curl -I http://192.168.0.108:3000	11 Helmet headers active, CORS mismatch
WhatWeb	whatweb http://192.168.0.108:3000	Email exposed in HTML placeholder
NMAP	nmap -sV -p 3000 192.168.0.108	Node.js Express framework identified
DIRB	dirb http://192.168.0.108:3000	Only /index.html found — minimal exposure

Task 2 — SQL Injection (SQLMap)
sqlmap -u "http://192.168.0.108:3000/api/login"
--data='{"email":"test@test.com","password":"test"}'
--headers="Content-Type: application/json"
--level=3 --risk=2 --batch --dbms=mysql --ignore-code=401

Result	Details
Vulnerabilities found	Zero — app is not injectable
Requests blocked by rate limiter	2,854 times with 429 Too Many Requests
IP bans triggered by Fail2Ban	5 times — IP banned automatically

Task 3 — CSRF Protection + Burp Suite
Implemented csurf middleware — every POST request now requires a valid CSRF token.

Test	Token Sent	Result
Legitimate browser login	Yes	200 OK — Login successful
Burp Suite — token removed	No	403 Forbidden — Blocked
curl attack from Kali	No	403 Forbidden — Blocked

Security Packages Used
Package	Purpose
helmet	HTTP security headers
bcrypt	Password hashing
jsonwebtoken	JWT authentication
validator	Input validation & sanitization
express-rate-limit	Brute force protection
cors	Cross-origin restrictions
dotenv	Environment variable management
winston	Security event logging
cookie-parser	Cookie handling for CSRF
csurf	CSRF token generation and validation

Running the App
npm install
node app.js

Visit: http://localhost:3000

