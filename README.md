# Auth Server Enterprise (Postgres, Multi-Tenant, MFA, JWT Client Registration, Persisted JWKs)

**Architecture**
- Controller → Service → Repository (SOLID, single-responsibility, thin controllers)
- Packages: api, user, rbac, tenant, client, keys, security, mfa, password
- RBAC via `api_to_roles` checked with `@PreAuthorize("@rbacService.hasAccess('action', authentication)")`

**Features**
- Spring Authorization Server (Auth Code + Refresh + **Custom Password** grant)
- PostgreSQL + Flyway schema (users/tenants/roles/features/mappings + `clients` + `jwk_keys`)
- Multi-tenant by **domain** (Host header) with per-tenant MFA
- **MFA (TOTP)** enrollment + verification endpoints (returns otpauth URI)
- **JWT dynamic client registration** (HMAC HS256 demo)
- **Persisted JWKs** (RSA signing key in DB) powering JWKSource
- Swagger UI at `/swagger`
- WebClient ready

## Run
1) Postgres:
```sql
CREATE DATABASE authdb;
CREATE USER authuser WITH PASSWORD 'authpass';
GRANT ALL PRIVILEGES ON DATABASE authdb TO authuser;
```
2) Start app
```bash
mvn spring-boot:run
```
3) Seed tenants/users as needed via APIs.

## Flows
### Password grant (with MFA if tenant requires)
```bash
curl -u confidential-client:secret -H "Host: domain1.gehilaw.com"   -d "grant_type=password&username=alice&password=pass&scope=openid profile api.read&mfa_code=123456"   http://localhost:9000/oauth2/token
```

### Refresh token
```bash
curl -u confidential-client:secret -H "Host: domain1.gehilaw.com"   -d "grant_type=refresh_token&refresh_token=<rt>"   http://localhost:9000/oauth2/token
```

### Auth code + PKCE
Use `/oauth2/authorize`, then exchange at `/oauth2/token`.

## APIs
- **Users**: `/api/users` (create), `/api/users/{username}/lock`, `/api/users/{username}/unlock`
- **MFA**: `/api/mfa/enroll/{username}` returns `otpauth://...`; `/api/mfa/verify/{username}?code=123456`
- **Client registration**: `POST /api/clients/register` with `{ "registration_jwt": "<HS256 JWS>" }`

**Registration JWT** payload example:
```json
{
  "client_id":"my-app",
  "client_secret":"s3cr3t",
  "scopes":["openid","profile","api.read"],
  "grant_types":["authorization_code","refresh_token"],
  "redirect_uris":["https://my.app/callback"],
  "auth_methods":["client_secret_basic"],
  "require_pkce": true
}
```

Sign header+payload with HS256 using `app.client-registration.hmac-secret` from `application.yml`.

## Notes
- Replace HMAC-based registration with asymmetric (software statements) if desired.
- For production: add key rotation, aud/iss/exp checks on registration JWT, stronger validation, and exception handling.


## Admin APIs (secured by RBAC)
- **Tenants**
  - `POST /api/admin/tenants` (`tenant:create`)
  - `PUT /api/admin/tenants/{id}` (`tenant:update`)
  - `GET /api/admin/tenants` (`tenant:read`)
  - `GET /api/admin/tenants/{id}` (`tenant:read`)
  - `DELETE /api/admin/tenants/{id}` (`tenant:delete`)

- **Clients**
  - `POST /api/admin/clients` (`client:create`)
  - `PUT /api/admin/clients/{clientId}` (`client:update`)
  - `GET /api/admin/clients` (`client:read`)
  - `GET /api/admin/clients/{clientId}` (`client:read`)
  - `DELETE /api/admin/clients/{clientId}` (`client:delete`)

Seed `api_to_roles` with actions like `tenant:create`, `client:read`, etc., mapped to your admin roles.
