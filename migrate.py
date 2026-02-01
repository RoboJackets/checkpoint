import os
from sqlite3 import connect

import sentry_sdk
from sentry_sdk.integrations.pure_eval import PureEvalIntegration

sentry_sdk.init(
    debug=True,
    integrations=[
        PureEvalIntegration(),
    ],
    traces_sample_rate=1.0,
    attach_stacktrace=True,
    max_request_body_size="always",
    in_app_include=[
        "checkpoint",
    ],
    profiles_sample_rate=1.0,
)

db = connect(os.environ["FLASK_DATABASE_LOCATION"])
db.execute("PRAGMA foreign_keys = 1")

db.executescript("""
CREATE TABLE IF NOT EXISTS crosswalk (
    gt_person_directory_id TEXT NOT NULL PRIMARY KEY COLLATE NOCASE,
    gtid INTEGER NOT NULL UNIQUE,
    primary_username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    keycloak_user_id TEXT UNIQUE COLLATE NOCASE
) strict;

CREATE TABLE IF NOT EXISTS crosswalk_email_address (
    email_address TEXT NOT NULL PRIMARY KEY COLLATE NOCASE,
    gt_person_directory_id TEXT NOT NULL COLLATE NOCASE,
    FOREIGN KEY(gt_person_directory_id) REFERENCES crosswalk(gt_person_directory_id)
) strict;
""")
