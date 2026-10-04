# Acme Enterprise Multi-Tenant Security Gateway

Node/Express gateway with hybrid auth (local bcrypt + GitHub OAuth 2.0), rotating refresh tokens in httpOnly cookies, RBAC and OWASP hardening, plus a small web GUI.

**Live URL:** _add your Render/Railway HTTPS URL_ · **Repo:** _public GitHub URL_

## Test credentials
| Role | Email | Password |
|---|---|---|
| SuperAdmin | admin@corp.com | Admin@12345 |
| Manager | manager@corp.com | Manager@12345 |
| Employee | employee@corp.com | Employee@12345 |

## Features
- **Local auth:** `POST /api/v1/auth/register`, `/login`. Bcrypt, 12 salt rounds. No plain-text passwords. Register always creates an Employee.
- **Lockout:** 5 failed logins per account per 15 min (express-rate-limit), then HTTP 429. Successful logins don't count.
- **OAuth 2.0:** GitHub login with CSRF `state`. Profile is created or synced, then system tokens are issued.
- **Tokens:** Access JWT 15 min (`Authorization: Bearer`). Refresh JWT 7 days in httpOnly, Secure, SameSite=Strict cookie. `POST /auth/refresh` rotates it; reusing an old refresh token revokes the whole session family. `POST /auth/logout` revokes.
- **RBAC:** `checkRole([...])` middleware.

| Route | Roles |
|---|---|
| GET /api/v1/employee/profile | SuperAdmin, Manager, Employee |
| POST /api/v1/payroll/approve | Manager, SuperAdmin |
| DELETE /api/v1/users/:id | SuperAdmin |
| GET /api/v1/users | SuperAdmin (used by GUI) |

- **OWASP:** Helmet (strict CSP), CORS allow-list, body/query sanitising (strips `$`/`.` keys, XSS-escapes strings), 10kb body limit, global rate limit, generic login errors.

## Run locally
```
npm install
cp .env.example .env   # set secrets
npm start              # http://localhost:3000
```
## GitHub OAuth setup
GitHub > Settings > Developer settings > OAuth Apps > New. Callback URL: `<BASE_URL>/api/v1/auth/github/callback`. Put the Client ID/Secret in env vars.

## Deploy on Render
New Web Service > connect repo > Build `npm install` > Start `npm start`. Env vars: `NODE_ENV=production`, `ACCESS_SECRET`, `REFRESH_SECRET`, `BASE_URL`, `ALLOWED_ORIGINS`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`.

## Viva demo (Postman)
1. Login 6 times with a wrong password: the 6th returns 429.
2. Login as Employee, `POST /payroll/approve` returns 403; as Manager returns 200.
3. `POST /auth/refresh` twice with the same old cookie: the second returns 401 (reuse detected).

## Note
Data is stored in memory (users reset on restart). For persistent production use, replace the `users`/`refreshStore` maps with Postgres or MongoDB.
