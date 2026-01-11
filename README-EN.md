# Synology OpenLDAP Consumer (Ubuntu)

Lightweight OpenLDAP consumer image for Synology LDAP. Configure with environment variables in `docker-compose.yml` and start; no extra scripts required.

## Features
- Ubuntu 22.04 base with slapd/ldap-utils/python3-ldap3.
- Syncrepl consumer: supports SSL/StartTLS/plain to the provider.
- Built-in `/schema/custom` with sample schema; optional auto fetch of provider schema (best-effort).
- Helper CLI `ldap-syncctl.py`: fetch-schema, list-users, list-groups, show-csn, resync-full (reset local DB if needed).
- Local maintenance defaults to ldapi+EXTERNAL (no local admin password exposed).

## Layout
- `Dockerfile`: builds image, includes entrypoint, ldap-syncctl, default schema.
- `scripts/entrypoint.sh`: renders slapd.conf from env, configures syncrepl, starts slapd.
- `scripts/ldap-syncctl.py`: sync utility CLI.
- `schema/custom/`: bundled sample schema (override by mounting your own).
- `docker-compose.yml`: example service definition.

## Required environment
- `LDAP_SERVER_ID`: syncrepl rid for this node.
- `LDAP_BASE_DN`: e.g. `dc=example,dc=com`.
- `LDAP_LOCAL_ADMIN_USERNAME` / `LDAP_LOCAL_ADMIN_PASSWORD`: local admin (rootdn) credentials.
- `LDAP_PROVIDER_URI`: provider host:port; protocol is inferred from security (e.g. `ldap.example.com:636`).
- `LDAP_PROVIDER_BIND_DN` / `LDAP_PROVIDER_BIND_PW`: provider bind account.
- `LDAP_PROVIDER_SEARCHBASE`: search base for sync.
- `LDAP_PROVIDER_SECURITY`: `ssl` / `starttls` / `none`.
- `LDAP_PROVIDER_TLS_REQCERT`: `demand` / `never`.
- `AUTO_FETCH_SCHEMA`: `true`/`false`, best-effort fetch of provider schema.
- `SLAPD_LOG_LEVEL`: slapd log/debug level keyword(s); defaults to `stats` (set to `stats`/`sync`/`none` etc. as needed).
- `CERT_CA` (default `/etc/ssl/certs/ca-certificates.crt`): CA bundle used to validate the provider certificate (and LDAPS on the consumer). Mount your provider CA, e.g. `./certs/ca.cer:/certs/ca.cer:ro`.
- `CERT_CRT` / `CERT_KEY`: server cert/key used to expose LDAPS on the consumer (maps to `/certs/ldap.crt` and `/certs/ldap.key` by default). LDAPS also uses `CERT_CA` as its trust anchor.

## Optional
- Mount `/certs/ldap.crt` and `/certs/ldap.key` to enable LDAPS on the consumer (uses `CERT_CA` as its trust anchor).
- Mount `/schema/custom` to override bundled schema.

## Usage
1. Edit `docker-compose.yml` with your domain, accounts, passwords, and TLS settings.
2. Build & start:
   ```bash
   docker compose up -d
   ```
3. Verify in the container:
   ```bash
   docker compose exec ldap-01 ldap-syncctl.py list-users --tls-reqcert=never
   docker compose exec ldap-01 ldap-syncctl.py show-csn --tls-reqcert=never
   ```
4. Force a full re-sync:
   ```bash
   docker compose exec ldap-01 ldap-syncctl.py resync-full
   docker compose restart ldap-01   # optional to speed up sync
   ```

## Security & privacy
- Repository ships only placeholder values; replace with your own domain/accounts/passwords.
- For production, supply CA/leaf certs and set `LDAP_PROVIDER_TLS_REQCERT=demand`.

## Troubleshooting
- Bind error (rc 13): verify bind DN/password and security/port match provider.
- fetch-schema returns nothing: provider may block subschema reads; place schema at `/schema/custom/provider.schema` manually.
- resync-full fails to modify contextCSN: the tool will fall back to wiping `/var/lib/ldap` to trigger a fresh full sync.

## License
AGPL-3.0 with an additional non-commercial clause (see LICENSE).
