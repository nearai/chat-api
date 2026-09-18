# Connecting chat-api to RDS PostgreSQL

Set `DATABASE_CONNECTION_MODE=direct` to bypass Patroni discovery. The default
is `patroni`. Values must be lowercase without surrounding whitespace. The
existing simple local connection (selected when `DATABASE_PRIMARY_APP_ID` is
empty) and Patroni deployments are unchanged.

Example application environment:

```sh
DATABASE_CONNECTION_MODE=direct
DATABASE_HOST=chatapi-postgres-staging.example.us-east-1.rds.amazonaws.com
DATABASE_PORT=5432
DATABASE_NAME=chat_api
DATABASE_USER=chat_api_app
DATABASE_PASSWORD_FILE=/run/secrets/rds-app-password
DATABASE_TLS_ENABLED=true
DATABASE_TLS_CA_CERT_PATH=/run/certs/us-east-1-bundle.pem
DATABASE_MAX_CONNECTIONS=10
```

Use a dedicated RDS application account with the permissions chat-api and its
startup migrations require. Do not use the source replication login. Preserve
the database field-encryption key and key ID when reading migrated ciphertext.

Direct mode requires TLS and verifies the server certificate chain and hostname.
Mount the official AWS regional CA bundle read-only inside the application
container. Without an explicit bundle, platform trust is used; do not assume it
contains the RDS CA. Missing or invalid CA files fail closed. Use the actual RDS
endpoint rather than an IP address or an alias absent from its certificate. See
[AWS PostgreSQL TLS guidance](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/PostgreSQL.Concepts.General.SSL.html)
and the [AWS regional CA bundles](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html).

This mode uses one pool for reads and writes against the configured writer
endpoint. It trims surrounding whitespace from the host and rejects empty
database or user names, a zero pool size, and disabled TLS. Pool wait, creation,
and recycling have 5, 10, and 5 second timeouts; socket connection has a 10
second timeout. Recycled connections are verified before checkout. These bounds
apply per pool operation, not to an entire request or SQL statement.

RDS read replicas are not discovered. Existing connections can fail during RDS
failover; new connections resolve the configured endpoint again. Rehearse
application retry behavior and do not assume interruption-free failover.

## Deployment and migration gates

- Wire the mode, writer endpoint, password file, and trusted CA file into the
  CVM deployment. Pools are lazy, so pool creation alone does not prove network
  access, authentication, or a successful TLS handshake.
- Verify CVM-to-RDS DNS, routes, security groups, TLS, reads, writes, migrations,
  and access to encrypted fields in staging.
- Prepare compatible schemas and extensions. Changing the endpoint does not copy
  data or synchronize sequences.
- Fence all source writers for the first cutover, finish replication, check data
  and sequence consistency, and then move every application instance to RDS.
  Do not use an ordinary rolling update that leaves Patroni-backed and RDS-backed
  instances writing concurrently.
- Define rollback and reverse-sync procedures before cutover. Rolling back an
  image does not roll back database writes.
