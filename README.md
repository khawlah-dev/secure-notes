# Secure Notes App

A single-file Flask notes app with user accounts, encrypted note content, private-note PINs, and audit logs.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Generate local secrets before running the app:

```bash
export FLASK_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export SECRET_ENCRYPTION_KEY="$(python3 -c 'import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())')"
python one_file_app.py
```

The SQLite database is created locally under `instance/` and is intentionally not committed.

## Deploy to Railway

Railway can run this app with the included `railway.json` start command:

```bash
gunicorn one_file_app:app
```

Set these Railway variables before deploying:

```bash
FLASK_SECRET_KEY=<random-secret>
SECRET_ENCRYPTION_KEY=<fernet-key>
DATABASE_URL=sqlite:///notes.db
```

For persistent production data, add a Railway PostgreSQL service and point `DATABASE_URL` to the PostgreSQL connection URL, or mount a Railway Volume and use a SQLite path on that volume, for example:

```bash
DATABASE_URL=sqlite:////data/notes.db
```

Keep `SECRET_ENCRYPTION_KEY` unchanged after users create notes, because changing it prevents old notes from being decrypted.
