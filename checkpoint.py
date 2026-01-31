"""
IAM support and troubleshooting tools
"""

import logging
import sqlite3
from base64 import b64encode
from email.errors import InvalidHeaderDefect
from email.headerregistry import Address
from hashlib import file_digest
from json import loads
from re import IGNORECASE, fullmatch
from sqlite3 import connect
from typing import Any, Dict, List, Union
from urllib.parse import urlparse, urlunparse

from authlib.integrations.flask_client import OAuth
from authlib.integrations.requests_client import OAuth2Session

from flask import Flask, g, render_template, request, session
from flask.helpers import get_debug_flag, redirect, url_for

from flask_caching import Cache

from ldap3 import (
    Connection,
    DEREF_ALWAYS,
    SUBTREE,
    Server,
)
from ldap3.operation.search import search_operation
from ldap3.utils.log import EXTENDED, set_library_log_detail_level

from requests import post

import sentry_sdk
from sentry_sdk import set_user
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.pure_eval import PureEvalIntegration

from werkzeug.exceptions import Forbidden, InternalServerError, NotFound, Unauthorized

logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
req_log = logging.getLogger("urllib3")
req_log.setLevel(logging.DEBUG)
req_log.propagate = True

GEORGIA_TECH_USERNAME_REGEX = r"[a-zA-Z]+[0-9]+"


def traces_sampler(sampling_context: Dict[str, Dict[str, str]]) -> bool:
    """
    Ignore ping events, sample all other events
    """
    try:
        request_uri = sampling_context["wsgi_environ"]["REQUEST_URI"]
    except KeyError:
        return False

    return request_uri != "/ping"


sentry_sdk.init(
    debug=get_debug_flag(),
    integrations=[
        FlaskIntegration(),
        PureEvalIntegration(),
    ],
    traces_sampler=traces_sampler,
    attach_stacktrace=True,
    max_request_body_size="always",
    in_app_include=[
        "checkpoint",
    ],
    profiles_sample_rate=1.0,
)

app = Flask(__name__)
app.config.from_prefixed_env()

oauth = OAuth(app)  # type: ignore
oauth.register(  # type: ignore
    name="keycloak",
    server_metadata_url=app.config["KEYCLOAK_METADATA_URL"],
    client_kwargs={"scope": "openid email profile"},
)

keycloak = OAuth2Session(
    client_id=app.config["KEYCLOAK_ADMIN_CLIENT_ID"],
    client_secret=app.config["KEYCLOAK_ADMIN_CLIENT_SECRET"],
    token_endpoint=urlunparse(
        (
            urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
            urlparse(app.config["KEYCLOAK_METADATA_URL"]).hostname,
            "/realms/master/protocol/openid-connect/token",
            "",
            "",
            "",
        )
    ),
    leeway=5,
)
keycloak.fetch_token()

apiary = OAuth2Session(
    client_id=app.config["APIARY_CLIENT_ID"],
    client_secret=app.config["APIARY_CLIENT_SECRET"],
    token_endpoint=app.config["APIARY_BASE_URL"] + "/oauth/token",
)
apiary.fetch_token()

cache = Cache(app)
cache.clear()

set_library_log_detail_level(EXTENDED)


def generate_subresource_integrity_hash(file: str) -> str:
    """
    Calculate the subresource integrity hash for a given file
    """
    with open(file[1:], "rb") as f:
        d = file_digest(f, "sha512")

    return "sha512-" + b64encode(d.digest()).decode("utf-8")


app.jinja_env.globals["calculate_integrity"] = generate_subresource_integrity_hash


@cache.cached(key_prefix="majors")
def get_majors() -> Dict[str, str]:
    """
    Fetch majors from Apiary and return as a map of whitepages_ou to display_name
    """
    response = apiary.get(app.config["APIARY_BASE_URL"] + "/api/v1/majors")
    response.raise_for_status()
    data = response.json()
    return {major["whitepages_ou"]: major["display_name"] for major in data["majors"]}


def build_ldap_filter(**kwargs: str) -> str:
    """
    Builds up an LDAP filter from kwargs

    :param kwargs: Dict of attribute name, value pairs
    :return: LDAP search filter representation of the dict
    """
    search_filter = ""
    for name, value in kwargs.items():
        search_filter = f"{search_filter}({name}={value})"
    if len(kwargs) > 1:
        search_filter = f"(&{search_filter})"
    return search_filter


def get_attribute_value(
    attribute_name: str, entry: Dict[str, Dict[str, List[str]]]
) -> Union[str, None]:
    """
    Get a given attribute value from a Whitepages entry, if it exists
    """
    if (
        "attributes" in entry
        and attribute_name in entry["attributes"]
        and entry["attributes"][attribute_name] is not None
        and len(entry["attributes"][attribute_name]) > 0
    ):
        return entry["attributes"][attribute_name][0]

    return None


def get_buzzapi_primary_account(**kwargs: str) -> Union[Dict[str, Any], None]:
    """
    Get the primary account for a user matching the provided kwargs
    """
    accounts = search_gted(**kwargs)

    if len(accounts) == 0:
        return None

    return [
        account for account in accounts if account["uid"] == account["gtPrimaryGTAccountUsername"]
    ][0]


def search_gted(**kwargs: str) -> List[Dict[str, Any]]:
    """
    Search GTED (via BuzzAPI) for accounts matching criteria specified in kwargs
    """
    buzzapi_response = post(
        url="https://api.gatech.edu/apiv3/central.iam.gted.accounts/search",
        json={
            "api_app_id": app.config["BUZZAPI_USERNAME"],
            "api_app_password": app.config["BUZZAPI_PASSWORD"],
            "api_request_mode": "sync",
            "api_log_level": "debug",
            "requested_attributes": [
                "gtGTID",
                "mail",
                "sn",
                "givenName",
                "eduPersonPrimaryAffiliation",
                "gtPrimaryGTAccountUsername",
                "uid",
                "gtEmplId",
                "gtEmployeeHomeDepartmentName",
                "eduPersonScopedAffiliation",
                "gtCurriculum",
                "gtAccessCardNumber",
                "gtAccountEntitlement",
                "gtSecondaryMailAddress",
            ],
        }
        | kwargs,
        timeout=(5, 30),
    )
    buzzapi_response.raise_for_status()

    for account in buzzapi_response.json()["api_result_data"]:
        db().execute(
            (
                "INSERT INTO crosswalk (gt_person_directory_id, gtid, primary_username)"
                " VALUES (:gt_person_directory_id, :gtid, :primary_username) ON CONFLICT DO NOTHING"  # noqa
            ),
            {
                "gt_person_directory_id": account["gtPersonDirectoryId"],
                "gtid": account["gtGTID"],
                "primary_username": account["gtPrimaryGTAccountUsername"],
            },
        )
        db().execute(
            (
                "INSERT INTO crosswalk_email_address (email_address, gt_person_directory_id)"  # noqa
                " VALUES (:email_address, :gt_person_directory_id)"
                " ON CONFLICT DO UPDATE SET gt_person_directory_id = (:gt_person_directory_id) WHERE email_address = (:email_address)"
            # noqa
            ),
            {
                "email_address": account["mail"],
                "gt_person_directory_id": account["gtPersonDirectoryId"],
            },
        )

    return buzzapi_response.json()["api_result_data"]  # type: ignore


@cache.memoize()
def search_whitepages(**kwargs: str) -> List[Dict[str, Dict[str, List[str]]]]:
    """
    Search Whitepages with a given LDAP filter
    """
    with sentry_sdk.start_span(op="whitepages.connect"):
        whitepages = Connection(
            Server("whitepages.gatech.edu", connect_timeout=1),
            auto_bind=True,
            raise_exceptions=True,
            receive_timeout=1,
            return_empty_attributes=False,
        )

    print(build_ldap_filter(**kwargs))

    with sentry_sdk.start_span(op="whitepages.search"):
        # the normal .search function does not allow sending blank attributes in the request,
        # which is the easiest way to get all attributes back from whitepages
        # there is some munging inside the .search function, and then it calls the below two
        # internal functions (among other things)
        ldap_request = search_operation(
            search_base="dc=whitepages,dc=gatech,dc=edu",
            search_filter=build_ldap_filter(**kwargs),
            search_scope=SUBTREE,
            dereference_aliases=DEREF_ALWAYS,
            attributes=[],
            size_limit=0,
            time_limit=0,
            types_only=False,
            auto_escape=False,
            auto_encode=False,
            schema=None,
            validator=None,
            check_names=False,
        )

        whitepages.post_send_search(whitepages.send("searchRequest", ldap_request, []))

    records = []

    for entry in whitepages.entries:
        records.append(loads(entry.entry_to_json()))

    # TODO store results in Crosswalk  # pylint: disable=fixme

    return records


def clean_affiliations(affiliations: List[str]) -> List[str]:
    """
    Remove redundant or confusing affiliations from search results
    """
    cleaned_affiliations = set()

    for affiliation in affiliations:
        parts = affiliation.split("@")

        cleaned_affiliations.add(parts[0])

    if "member" in cleaned_affiliations:
        cleaned_affiliations.remove("member")

    if "active-member" in cleaned_affiliations:
        cleaned_affiliations.remove("active-member")

    return list(cleaned_affiliations)


def format_search_result(
    buzzapi_account: Dict[str, Any], whitepages_entries: List[Dict[str, Dict[str, List[str]]]]
) -> Dict[str, Union[Any, None]]:
    """
    Format a search result for the UI
    """
    title = None
    organizational_unit = None

    if len(whitepages_entries) == 1:
        title = get_attribute_value("title", whitepages_entries[0])

        organizational_unit = get_attribute_value("ou", whitepages_entries[0])

    elif len(whitepages_entries) > 1:
        for entry in whitepages_entries:
            if (
                "attributes" in entry  # pylint: disable=too-many-boolean-expressions
                and "title" in entry["attributes"]
                and entry["attributes"]["title"] is not None
                and len(entry["attributes"]["title"]) > 0
                and entry["attributes"]["title"][0] is not None
                and "student assistant" not in entry["attributes"]["title"][0].lower()
                and "research assistant" not in entry["attributes"]["title"][0].lower()
                and "graduate assistant" not in entry["attributes"]["title"][0].lower()
                and "research technologist" not in entry["attributes"]["title"][0].lower()
                and "instructional associate" not in entry["attributes"]["title"][0].lower()
            ):
                if title is not None:
                    raise InternalServerError(
                        "Selected multiple Whitepages entries to display in results for "
                        + buzzapi_account["gtPrimaryGTAccountUsername"]
                    )

                title = entry["attributes"]["title"][0]

                organizational_unit = get_attribute_value("ou", entry)

    return {
        "givenName": buzzapi_account["givenName"],
        "surname": buzzapi_account["sn"],
        "directoryId": buzzapi_account["gtPersonDirectoryId"],
        "primaryAffiliation": (
            buzzapi_account["eduPersonPrimaryAffiliation"]
            if buzzapi_account["eduPersonPrimaryAffiliation"] != "member"
            else None
        ),
        "affiliations": clean_affiliations(buzzapi_account["eduPersonScopedAffiliation"]),
        "title": title,
        "organizationalUnit": organizational_unit,
    }


def db() -> sqlite3.Connection:
    """
    Get a connection to the database
    """
    connection = getattr(g, "_database", None)
    if connection is None:
        connection = g._database = connect(app.config["DATABASE_LOCATION"])
        connection.autocommit = True
        connection.execute("PRAGMA foreign_keys = 1")
    return connection


@app.teardown_appcontext
def close_connection(exception) -> None:  # type: ignore  # pylint: disable=unused-argument
    """
    Close the connection to the database, if one is open

    Automatically called at the end of a request
    """
    connection = getattr(g, "_database", None)
    if connection is not None:
        connection.close()


@app.get("/")
@app.get("/search")
@app.get("/view/<directory_id>")
def spa(directory_id: Union[str, None] = None) -> Any:  # pylint: disable=unused-argument
    """
    Render the SPA, or an error page, or redirect to login, as applicable
    """
    if "has_access" not in session:
        if request.query_string == b"":
            session["next"] = request.path
        else:
            session["next"] = request.path + "?" + request.query_string.decode("utf-8")

        return oauth.keycloak.authorize_redirect(url_for("login", _external=True))

    set_user(
        {
            "id": session["sub"],
            "username": session["username"],
            "ip_address": request.remote_addr,
        }
    )

    if session["has_access"] is not True:
        sub = str(session["sub"])
        username = str(session["username"])
        session.clear()
        return (
            render_template(
                "access_denied.html",
                username=username,
                keycloak_user_deep_link=urlunparse(
                    (
                        urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
                        urlparse(app.config["KEYCLOAK_METADATA_URL"]).hostname,
                        "/admin/master/console/",
                        "",
                        "",
                        "/" + app.config["KEYCLOAK_REALM"] + "/users/" + sub + "/role-mapping",
                    )
                ),
            ),
            403,
        )

    return render_template(
        "app.html",
        elm_model={
            "username": session["username"],
            "majors": get_majors(),
            # TODO check if user has IAT access and (likely) network connectivity to IAT  # pylint: disable=fixme  # noqa
        },
    )


@app.get("/login")
def login() -> Any:
    """
    Handles the return from Keycloak and collects default values for the form
    """
    token = oauth.keycloak.authorize_access_token()

    userinfo = token["userinfo"]

    session["username"] = userinfo["preferred_username"]
    session["sub"] = userinfo["sub"]

    set_user(
        {
            "id": session["sub"],
            "username": session["username"],
            "ip_address": request.remote_addr,
        }
    )

    print(userinfo)

    session["has_access"] = "roles" in userinfo and "access" in userinfo["roles"]

    if session["has_access"]:
        # TODO check if user has IAT access  # pylint: disable=fixme
        pass

    return redirect(session["next"])


def search_by_email(email_address: Address) -> Dict[str, Any]:
    # search crosswalk by email
    cursor = db().execute(
        "SELECT gt_person_directory_id FROM crosswalk_email_address WHERE email_address = (:email_address)",  # noqa
        {"email_address": email_address.addr_spec.lower()},
    )
    row = cursor.fetchone()

    if row is not None:
        # found person in crosswalk, return that
        buzzapi_account = get_buzzapi_primary_account(gtPersonDirectoryId=row[0])

        if buzzapi_account is None:
            raise InternalServerError(
                "gtPersonDirectoryId from Crosswalk was not found in BuzzAPI"
            )

        return {
            "results": [
                format_search_result(
                    buzzapi_account,
                    search_whitepages(uid=buzzapi_account["gtPrimaryGTAccountUsername"]),
                ),
            ],
            "exactMatch": True,
        }

    # search whitepages by email
    entries = search_whitepages(mail=email_address.addr_spec)

    uid = None

    for entry in entries:
        this_uid = get_attribute_value("primaryUid", entry)

        if this_uid is not None:
            uid = this_uid

    if uid is None:
        # whitepages doesn't have email, check if the username looks like a GT username
        if (
            fullmatch(GEORGIA_TECH_USERNAME_REGEX, email_address.username, IGNORECASE)
            is not None
            and email_address.domain == "gatech.edu"
        ):
            # search crosswalk by username
            cursor = db().execute(
                "SELECT gt_person_directory_id FROM crosswalk WHERE primary_username = (:username)",  # noqa
                {"username": email_address.username},
            )
            row = cursor.fetchone()

            if row is not None:
                # found person in crosswalk, return that
                buzzapi_account = get_buzzapi_primary_account(gtPersonDirectoryId=row[0])

                if buzzapi_account is None:
                    raise InternalServerError(
                        "gtPersonDirectoryId from Crosswalk was not found in BuzzAPI"
                    )

                return {
                    "results": [
                        format_search_result(
                            buzzapi_account,
                            search_whitepages(
                                uid=buzzapi_account["gtPrimaryGTAccountUsername"]
                            ),
                        ),
                    ],
                    "exactMatch": True,
                }

            # search whitepages by username
            entries = search_whitepages(uid=email_address.username)

            uid = None

            for entry in entries:
                this_uid = get_attribute_value("primaryUid", entry)

                if this_uid is not None:
                    uid = this_uid

            if uid is not None:
                # found person in whitepages, return that
                buzzapi_account = get_buzzapi_primary_account(uid=email_address.username)

                if buzzapi_account is None:
                    raise InternalServerError("Account found in Whitepages but not BuzzAPI")

                return {
                    "results": [
                        format_search_result(buzzapi_account, entries),
                    ],
                    "exactMatch": True,
                }

    return {
        "results": [],
        "exactMatch": True
    }

@app.post("/search")
def search() -> (
    Dict[str, Any]
):  # pylint: disable=too-many-return-statements,too-many-branches,too-many-statements
    """
    Search for people matching the provided query
    """
    if "has_access" not in session:
        raise Unauthorized("Not authenticated")

    if session["has_access"] is not True:
        raise Forbidden("Access denied")

    query = request.json["query"].strip()  # type: ignore

    try:  # pylint: disable=too-many-nested-blocks
        # check if the query is formatted like an email address
        return search_by_email(Address(addr_spec=query))
    except InvalidHeaderDefect:
        # check if the query is formatted like a GT username
        if fullmatch(GEORGIA_TECH_USERNAME_REGEX, query, IGNORECASE) is not None:
            cursor = db().execute(
                "SELECT gt_person_directory_id FROM crosswalk WHERE primary_username = (:username)",
                {"username": query},
            )
            row = cursor.fetchone()

            if row is not None:
                buzzapi_account = get_buzzapi_primary_account(gtPersonDirectoryId=row[0])

                if buzzapi_account is None:
                    raise InternalServerError(  # pylint: disable=raise-missing-from
                        "gtPersonDirectoryId from Crosswalk was not found in BuzzAPI"
                    )

                return {
                    "results": [
                        format_search_result(buzzapi_account, search_whitepages(uid=query)),
                    ],
                    "exactMatch": True,
                }

            entries = search_whitepages(uid=query)

            uid = None
            mails = set()

            for entry in entries:
                this_uid = get_attribute_value("primaryUid", entry)

                if this_uid is not None:
                    uid = this_uid

                this_mail = get_attribute_value("mail", entry)

                if this_mail is not None:
                    mails.add(this_mail)

            if uid is None:
                return {
                    "results": [],
                    "exactMatch": True,
                }

            buzzapi_account = get_buzzapi_primary_account(uid=uid)

            if buzzapi_account is None:
                raise InternalServerError(  # pylint: disable=raise-missing-from
                    "Account found in Whitepages but not BuzzAPI"
                )

            db().execute(
                (
                    "INSERT INTO crosswalk (gt_person_directory_id, gtid, primary_username)"
                    " VALUES (:gt_person_directory_id, :gtid, :primary_username)"
                    " ON CONFLICT DO NOTHING"
                ),
                {
                    "gt_person_directory_id": buzzapi_account["gtPersonDirectoryId"],
                    "gtid": buzzapi_account["gtGTID"],
                    "primary_username": buzzapi_account["gtPrimaryGTAccountUsername"],
                },
            )
            db().execute(
                (
                    "INSERT INTO crosswalk_email_address (email_address, gt_person_directory_id)"
                    " VALUES (:email_address, :gt_person_directory_id)"
                    " ON CONFLICT DO UPDATE SET gt_person_directory_id = (:gt_person_directory_id) WHERE email_address = (:email_address)"  # noqa
                ),
                {
                    "email_address": buzzapi_account["mail"],
                    "gt_person_directory_id": buzzapi_account["gtPersonDirectoryId"],
                },
            )

            for mail in mails:
                db().execute(
                    (
                        "INSERT INTO crosswalk_email_address (email_address, gt_person_directory_id)"  # noqa
                        " VALUES (:email_address, :gt_person_directory_id)"
                        " ON CONFLICT DO UPDATE SET gt_person_directory_id = (:gt_person_directory_id) WHERE email_address = (:email_address)"  # noqa
                    ),
                    {
                        "email_address": mail,
                        "gt_person_directory_id": buzzapi_account["gtPersonDirectoryId"],
                    },
                )

            return {
                "results": [
                    format_search_result(buzzapi_account, entries),
                ],
                "exactMatch": True,
            }

        # check if the query is formatted like a first and last name
        split_name = query.split(" ")
        if len(split_name) == 2 and len(split_name[0]) > 1 and len(split_name[1]) > 1:
            entries = search_whitepages(givenName=split_name[0] + "*", sn=split_name[1] + "*")

            uids = set()

            print(entries)

            for entry in entries:
                this_uid = get_attribute_value("primaryUid", entry)

                if this_uid is not None:
                    uids.add(this_uid)

            formatted_results = []

            for uid in uids:
                entries = search_whitepages(uid=uid)

                mails = set()

                for entry in entries:
                    this_mail = get_attribute_value("mail", entry)

                    if this_mail is not None:
                        mails.add(this_mail)

                buzzapi_account = get_buzzapi_primary_account(uid=uid)

                if buzzapi_account is None:
                    raise InternalServerError(  # pylint: disable=raise-missing-from
                        "Account found in Whitepages but not BuzzAPI"
                    )

                db().execute(
                    (
                        "INSERT INTO crosswalk (gt_person_directory_id, gtid, primary_username)"
                        " VALUES (:gt_person_directory_id, :gtid, :primary_username)"
                        " ON CONFLICT DO NOTHING"
                    ),
                    {
                        "gt_person_directory_id": buzzapi_account["gtPersonDirectoryId"],
                        "gtid": buzzapi_account["gtGTID"],
                        "primary_username": buzzapi_account["gtPrimaryGTAccountUsername"],
                    },
                )
                db().execute(
                    (
                        "INSERT INTO crosswalk_email_address (email_address, gt_person_directory_id)"  # noqa
                        " VALUES (:email_address, :gt_person_directory_id)"
                        " ON CONFLICT DO UPDATE SET gt_person_directory_id = (:gt_person_directory_id) WHERE email_address = (:email_address)"  # noqa
                    ),
                    {
                        "email_address": buzzapi_account["mail"],
                        "gt_person_directory_id": buzzapi_account["gtPersonDirectoryId"],
                    },
                )

                for mail in mails:
                    db().execute(
                        (
                            "INSERT INTO crosswalk_email_address (email_address, gt_person_directory_id)"  # noqa
                            " VALUES (:email_address, :gt_person_directory_id)"
                            " ON CONFLICT DO UPDATE SET gt_person_directory_id = (:gt_person_directory_id) WHERE email_address = (:email_address)"  # noqa
                        ),
                        {
                            "email_address": mail,
                            "gt_person_directory_id": buzzapi_account["gtPersonDirectoryId"],
                        },
                    )

                formatted_results.append(format_search_result(buzzapi_account, entries))

            return {
                "results": formatted_results,
                "exactMatch": False,
            }

        return {
            "results": [],
            "exactMatch": True,
        }


@app.get("/view/<directory_id>/whitepages")
def get_whitepages_records(directory_id: str) -> List[Dict[str, Dict[str, List[str]]]]:
    """
    Get Whitepages entries for a provided gtPersonDirectoryId
    """
    if "has_access" not in session:
        raise Unauthorized("Not authenticated")

    if session["has_access"] is not True:
        raise Forbidden("Access denied")

    cursor = db().execute(
        "SELECT primary_username FROM crosswalk WHERE gt_person_directory_id = (:directory_id)",
        {"directory_id": directory_id},
    )
    row = cursor.fetchone()

    if row is not None:
        primary_username = row[0]
    else:
        buzzapi_account = get_buzzapi_primary_account(gtPersonDirectoryId=directory_id)

        if buzzapi_account is None:
            raise NotFound("Provided directory ID was not found in Crosswalk or BuzzAPI")

        primary_username = buzzapi_account["gtPrimaryGTAccountUsername"]

    return search_whitepages(uid=primary_username)  # type: ignore


@app.get("/view/<directory_id>/gted")
def get_gted_accounts(directory_id: str) -> List[Dict[str, Any]]:
    """
    Get GTED accounts for a given gtPersonDirectoryId
    """
    if "has_access" not in session:
        raise Unauthorized("Not authenticated")

    if session["has_access"] is not True:
        raise Forbidden("Access denied")

    accounts = search_gted(gtPersonDirectoryId=directory_id)

    if len(accounts) == 0:
        raise NotFound("Provided directory ID was not found in GTED")

    return accounts


@app.get("/ping")
def ping() -> Dict[str, str]:
    """
    Returns an arbitrary successful response, for health checks
    """
    return {"status": "ok"}
