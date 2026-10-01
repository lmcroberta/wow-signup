# WoW self-serve registration page
# Zero dependencies — the app is pure Node stdlib, so there is nothing to npm install.
FROM node:20-alpine

WORKDIR /app

# Only the three files the app actually needs at runtime.
# selftest.js is included on purpose: it is the smoke test you run inside the container.
COPY server.js check-db.js selftest.js ./

# Runs as the unprivileged user that node:20-alpine already ships.
USER node

EXPOSE 8080

# Nothing is baked in — every setting comes from environment variables at run time
# (DB_HOST, DB_USER, DB_PASS, DB_NAME, LISTEN_PORT, REALM_NAME, ACCOUNT_EXPANSION, ...).
CMD ["node", "server.js"]
