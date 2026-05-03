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

### Gotchas

- `uwsgi` requires `python3-dev` and `build-essential` system packages to compile.
- The `static/app.js` file is not committed; it must be built via `npm run build` before the Flask app can serve the frontend.
- `pip install poetry` may fail on Ubuntu 24.04 due to a missing RECORD file for the system `packaging` package. Workaround: `pip3 install --break-system-packages --ignore-installed packaging` first.
