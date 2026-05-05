# Checkpoint

IAM support and troubleshooting tool for RoboJackets. Single-file Flask backend (`checkpoint.py`) + Elm SPA frontend (`elm/Main.elm`).

## Cursor Cloud specific instructions

### Tech Stack

- **Backend:** Python 3.12+ / Flask (`checkpoint.py`, single file ~3800 lines)
- **Frontend:** Elm 0.19.1 compiled via Node.js tooling
- **Dependencies:** Poetry (Python), npm (Node/Elm)
- **Database:** SQLite (ephemeral, reset per deployment)
- **Cache/Broker:** Redis (production), SimpleCache (local dev)

### Running Linters

All linting commands from CI (see `.github/workflows/build.yml`):

```sh
poetry run black --check checkpoint.py
poetry run flake8 checkpoint.py
poetry run pylint checkpoint.py
poetry run mypy --strict --scripts-are-modules checkpoint.py
```

Elm linters run as part of the frontend build:

```sh
npm run build   # runs elm-review, elm-format --validate, elm make, terser
```

### Building the Frontend

```sh
npm run build          # production (optimized + minified)
npm run build-debug    # debug mode (no minification, debug overlay)
```

Always use the `build-debug` command during development so you have access to the Elm debugger within the frontend. It is available by clicking the blue Elm logo in the bottom right corner when the Elm app is running.

Output goes to `static/app.js`.

### Running the Flask App Locally

The app requires external service credentials (Keycloak, Apiary, Slack, etc.) configured via `FLASK_`-prefixed environment variables (Flask uses `app.config.from_prefixed_env()`). Create a `.env` file at the repo root with the required values. See `.vscode/launch.json` for the recommended dev configuration.

Key dev overrides:
- `FLASK_CACHE_TYPE=SimpleCache` — avoids the Redis dependency for local dev
- `FLASK_DEBUG=1` — enables Flask debug mode

**Critical:** The app performs OAuth token fetches at **module import time** (Keycloak and Apiary). Without valid credentials to these services, Flask will not start. There is no mock/stub mode.

Required `FLASK_` env vars for startup:
- `FLASK_SECRET_KEY`
- `FLASK_KEYCLOAK_METADATA_URL`, `FLASK_KEYCLOAK_CLIENT_ID`, `FLASK_KEYCLOAK_CLIENT_SECRET`
- `FLASK_KEYCLOAK_ADMIN_CLIENT_ID`, `FLASK_KEYCLOAK_ADMIN_CLIENT_SECRET`, `FLASK_KEYCLOAK_REALM`
- `FLASK_APIARY_CLIENT_ID`, `FLASK_APIARY_CLIENT_SECRET`, `FLASK_APIARY_BASE_URL`
- `FLASK_SLACK_BOT_TOKEN`
- `FLASK_DATABASE_LOCATION`

### Running the Celery Worker

Requires Redis. See `.vscode/launch.json` for args:

```sh
poetry run celery --app checkpoint.celery_app worker --loglevel DEBUG --pool solo
```

### Node.js Version

Node.js 24.x is installed via nvm. Activate with:

```sh
export NVM_DIR="/home/ubuntu/.nvm" && [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh" && nvm use 24
```

### Local Keycloak Setup (Docker)

The app needs a Keycloak instance. For local/cloud dev, run one via Docker (any port works):

```sh
dockerd &>/var/log/dockerd.log &
# Wait for Docker to start, then:
docker run -d --name keycloak -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak start-dev
```

After Keycloak is ready (check `curl -s http://localhost:8080/realms/master/.well-known/openid-configuration`), configure it:

1. Create realm `robojackets`
2. Create OIDC client `checkpoint` (secret: `checkpoint-secret`) in the robojackets realm with redirect URI `http://localhost:5000/*`
3. Create service-account client `checkpoint-admin` (secret: `checkpoint-admin-secret`) in the **master** realm
4. Assign `manage-users`, `view-users`, `manage-realm`, `view-realm`, `manage-clients`, `view-clients` roles from both `master-realm` and `robojackets-realm` clients to the checkpoint-admin service account

Then use these env vars:
```
FLASK_KEYCLOAK_METADATA_URL=http://localhost:8080/realms/robojackets/.well-known/openid-configuration
FLASK_KEYCLOAK_CLIENT_ID=checkpoint
FLASK_KEYCLOAK_CLIENT_SECRET=checkpoint-secret
FLASK_KEYCLOAK_ADMIN_CLIENT_ID=checkpoint-admin
FLASK_KEYCLOAK_ADMIN_CLIENT_SECRET=checkpoint-admin-secret
FLASK_KEYCLOAK_REALM=robojackets
```

### Apiary Dependency

The Apiary service (`https://my.robojackets.org`) is an external production API that performs OAuth token fetch at import time. Without access to Apiary, the Flask app cannot start. There is no mock mode. The required secrets (`FLASK_APIARY_CLIENT_ID`, `FLASK_APIARY_CLIENT_SECRET`, `FLASK_APIARY_BASE_URL`) are injected via the Cursor Cloud secrets mechanism.

### Starting the Flask App (Cloud Dev)

After Docker/Keycloak are running, Apiary is accessible, and the mock services are started:

```sh
FLASK_APP=checkpoint.py \
FLASK_SECRET_KEY="dev-secret-key-12345" \
FLASK_KEYCLOAK_METADATA_URL="http://localhost:8080/realms/robojackets/.well-known/openid-configuration" \
FLASK_KEYCLOAK_CLIENT_ID="checkpoint" \
FLASK_KEYCLOAK_CLIENT_SECRET="checkpoint-secret" \
FLASK_KEYCLOAK_ADMIN_CLIENT_ID="checkpoint-admin" \
FLASK_KEYCLOAK_ADMIN_CLIENT_SECRET="checkpoint-admin-secret" \
FLASK_KEYCLOAK_REALM="robojackets" \
FLASK_CACHE_TYPE="SimpleCache" \
FLASK_DEBUG="1" \
FLASK_DATABASE_LOCATION="/tmp/checkpoint.db" \
FLASK_GROUPER_BASE_URL="http://localhost:9090" \
FLASK_GROUPER_USERNAME="dummy" \
FLASK_GROUPER_PASSWORD="dummy" \
FLASK_WHITEPAGES_HOST="localhost" \
FLASK_WHITEPAGES_PORT="10389" \
FLASK_GTAD_HOST="localhost" \
FLASK_GTAD_PORT="10389" \
FLASK_GTAD_BIND_DN="cn=admin,dc=ad,dc=gatech,dc=edu" \
FLASK_GTAD_BIND_PASSWORD="dummy" \
poetry run flask run --no-debugger --port 5000
```

A test user is pre-created in local Keycloak: `testuser` / `testpass123`.

Always use a fresh incognito or private browsing window when testing the UI to avoid issues with stale cookies, cache, etc.

### Mock Grouper Service

The app depends on Georgia Tech's Grouper (`grouper.gatech.edu`) which is unreachable from the cloud VM. A mock is provided in `grouper_mock.py`. Start it before Flask:

```sh
poetry run flask --app grouper_mock:mock_app run --port 9090
```

Then pass `FLASK_GROUPER_BASE_URL="http://localhost:9090"` (along with any dummy values for `FLASK_GROUPER_USERNAME` and `FLASK_GROUPER_PASSWORD`) when starting the main Flask app.

### Mock LDAP Service (Whitepages + GTAD)

The app depends on two Georgia Tech LDAP services — Whitepages (`whitepages.gatech.edu`) and GTAD (`campusad.ad.gatech.edu`) — both unreachable from the cloud VM. A mock LDAP server is provided in `ldap_mock.py`. Start it before Flask:

```sh
poetry run python ldap_mock.py --port 10389
```

Then pass these env vars when starting the main Flask app:
- `FLASK_WHITEPAGES_HOST="localhost"` and `FLASK_WHITEPAGES_PORT="10389"`
- `FLASK_GTAD_HOST="localhost"` and `FLASK_GTAD_PORT="10389"`
- `FLASK_GTAD_BIND_DN="cn=admin,dc=ad,dc=gatech,dc=edu"` and `FLASK_GTAD_BIND_PASSWORD="dummy"`

The mock returns empty results for all LDAP searches. In the UI, the Whitepages card shows "No entries" and the GTAD card renders without data (empty state). The `WHITEPAGES_HOST`, `WHITEPAGES_PORT`, `GTAD_HOST`, and `GTAD_PORT` config values default to the production hostnames and standard LDAP port when not set.

### SQLite Database Setup

The app expects an existing database at startup, located at `FLASK_DATABASE_LOCATION`. If it is not already present, or if there are database-related errors, run `poetry run flask --app checkpoint migrate` to create the database.

You will also need to delete and recreate the database if there are schema changes made within the `migrate()` function.

### Keycloak Access Role

To get past the "access denied" page, the logged-in user needs a **client role** named `access` on the `checkpoint` client in the `robojackets` realm. A protocol mapper named `checkpoint-roles` (type `oidc-usermodel-client-role-mapper`) must also exist on that client to include the role in the `roles` claim of the ID token. See the Keycloak setup steps above for the full configuration.

### Gotchas

- `uwsgi` requires `python3-dev` and `build-essential` system packages to compile.
- The `static/app.js` file is not committed; it must be built via `npm run build` before the Flask app can serve the frontend.
- `pip install poetry` may fail on Ubuntu 24.04 due to a missing RECORD file for the system `packaging` package. Workaround: `pip3 install --break-system-packages --ignore-installed packaging` first.
- Keycloak can run on any port (e.g. 8080). The code uses `urlparse(...).netloc` to preserve port info in constructed URLs.
- Docker in the cloud VM requires `fuse-overlayfs` storage driver and `iptables-legacy` due to nested container constraints.
