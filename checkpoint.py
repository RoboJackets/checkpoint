"""
IAM support and troubleshooting tools
"""

import datetime
import logging
import re
import sqlite3
from base64 import b64encode
from email.errors import InvalidHeaderDefect
from email.headerregistry import Address
from hashlib import file_digest
from json import dumps, loads
from os import environ
from re import IGNORECASE, fullmatch
from sqlite3 import connect
from typing import Any, Dict, List, Union
from urllib.parse import urlparse, urlunparse
from zoneinfo import ZoneInfo

from authlib.integrations.flask_client import OAuth
from authlib.integrations.requests_client import OAuth2Session

from flask import Flask, g, render_template, request, session
from flask.helpers import get_debug_flag, redirect, url_for

from flask_caching import Cache

from google.oauth2 import service_account

from googleapiclient.discovery import build  # type: ignore

from ldap3 import (
    Connection,
    DEREF_ALWAYS,
    SUBTREE,
    Server,
)
from ldap3.operation.search import search_operation
from ldap3.utils.log import EXTENDED, set_library_log_detail_level

from requests import get, post

import sentry_sdk
from sentry_sdk import set_user
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.pure_eval import PureEvalIntegration

from slack_sdk import WebClient
from slack_sdk.signature import SignatureVerifier

from werkzeug.exceptions import BadRequest, Forbidden, InternalServerError, NotFound, Unauthorized

logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
req_log = logging.getLogger("urllib3")
req_log.setLevel(logging.DEBUG)
req_log.propagate = True

GEORGIA_TECH_USERNAME_REGEX = r"[a-zA-Z]+[0-9]+"
ACCESS_OVERRIDE_TIMESTAMP_REGEX = r"(?P<timestamp>\d{4}-\d{2}-\d{2})"
NUMBER_IN_QUOTES_REGEX = r"\"(?P<user_id>\d+)\""
PAYMENT_METHOD_REGEX = r"\"method\".+\"(?P<method>[a-z]+)\".+\"amount\""
CLIENT_NAME_REGEX = r"\"client_name\".+?\"(?P<client_name>.+?)\""

USER_AGENT = "Checkpoint/" + environ.get("NOMAD_SHORT_ALLOC_ID", "local")


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
keycloak.headers["User-Agent"] = USER_AGENT
keycloak.fetch_token()

apiary = OAuth2Session(
    client_id=app.config["APIARY_CLIENT_ID"],
    client_secret=app.config["APIARY_CLIENT_SECRET"],
    token_endpoint=app.config["APIARY_BASE_URL"] + "/oauth/token",
)
apiary.headers["User-Agent"] = USER_AGENT
apiary.headers["Accept"] = "application/json"
apiary.fetch_token()

cache = Cache(app)
cache.clear()

slack = WebClient(token=app.config["SLACK_BOT_TOKEN"])

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


@cache.cached(key_prefix="grouper_groups")
def get_grouper_groups() -> List[str]:
    """
    Fetch all Grouper groups under gt:services:robojackets and return extension names
    """
    response = post(
        url="https://grouper.gatech.edu/grouper-ws/servicesRest/v4_0_000/groups",
        auth=(app.config["GROUPER_USERNAME"], app.config["GROUPER_PASSWORD"]),
        headers={
            "User-Agent": USER_AGENT,
        },
        json={
            "WsRestFindGroupsLiteRequest": {
                "stemName": "gt:services:robojackets",
                "queryFilterType": "FIND_BY_STEM_NAME",
            }
        },
        timeout=(5, 30),
    )
    response.raise_for_status()
    return [group["extension"] for group in response.json()["WsFindGroupsResults"]["groupResults"]]


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


def build_keycloak_filter(**kwargs: str) -> str:
    """
    Builds up a Keycloak filter from kwargs

    :param kwargs: Dict of attribute name, value pairs
    :return: Keycloak search query representation of the dict
    """
    filters = []

    for name, value in kwargs.items():
        filters.append(f"{name}:{value}")

    return " ".join(filters)


def get_attribute_value(
    attribute_name: str, entry: Dict[str, Dict[str, List[str]]]
) -> Union[str, None]:
    """
    Get a given attribute value from a Whitepages entry or Keycloak account, if it exists
    """
    if (
        "attributes" in entry
        and attribute_name in entry["attributes"]
        and entry["attributes"][attribute_name] is not None
        and len(entry["attributes"][attribute_name]) > 0
    ):
        return entry["attributes"][attribute_name][0]

    return None


def get_gted_primary_account(**kwargs: str) -> Union[Dict[str, Any], None]:
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
        headers={
            "User-Agent": USER_AGENT,
        },
    )
    buzzapi_response.raise_for_status()

    if "api_result_data" not in buzzapi_response.json():
        return []

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
                " ON CONFLICT DO UPDATE SET gt_person_directory_id = (:gt_person_directory_id) WHERE email_address = (:email_address)"  # noqa
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
        record = loads(entry.entry_to_json())

        records.append(record)

        username = get_attribute_value("primaryUid", record)
        mail = get_attribute_value("mail", record)

        if username is not None and mail is not None:
            cursor = db().execute(
                "SELECT gt_person_directory_id FROM crosswalk WHERE primary_username = (:username)",
                {"username": username},
            )
            row = cursor.fetchone()

            if row is not None:
                db().execute(
                    (
                        "INSERT INTO crosswalk_email_address (email_address, gt_person_directory_id)"  # noqa
                        " VALUES (:email_address, :gt_person_directory_id)"
                        " ON CONFLICT DO UPDATE SET gt_person_directory_id = (:gt_person_directory_id) WHERE email_address = (:email_address)"  # noqa
                    ),
                    {
                        "email_address": mail,
                        "gt_person_directory_id": row[0],
                    },
                )

    return records


@cache.cached(key_prefix="realms")
def get_realms() -> List[Dict[str, Any]]:
    """
    Get realm information from Keycloak
    """
    keycloak_response = keycloak.get(
        url=urlunparse(
            (
                urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
                urlparse(app.config["KEYCLOAK_METADATA_URL"]).hostname,
                "/admin/realms",
                "",
                "",
                "",
            )
        ),
        timeout=(5, 5),
    )
    keycloak_response.raise_for_status()

    return keycloak_response.json()  # type: ignore


@cache.memoize()
def get_actor(**kwargs: str) -> Dict[str, Union[str, None]]:
    """
    Get the display name and link for an event actor
    """
    if (
        "full_name" in kwargs
        and "gtPersonDirectoryId" in kwargs
        and kwargs["gtPersonDirectoryId"] is not None
    ):
        return {
            "actorDisplayName": kwargs["full_name"],
            "actorLink": "/view/" + kwargs["gtPersonDirectoryId"],
        }

    if (
        "full_name" in kwargs
        and "id" in kwargs
        and kwargs["id"] is not None
        and "is_service_account" in kwargs
        and kwargs["is_service_account"] is True  # type: ignore
    ):
        display_name = kwargs["full_name"]

        if display_name.startswith("Service Account for "):
            display_name = display_name[len("Service Account for ") :]  # noqa

        return {
            "actorDisplayName": display_name,
            "actorLink": app.config["APIARY_BASE_URL"] + "/nova/resources/users/" + kwargs["id"],
        }

    if "gtPersonDirectoryId" in kwargs or "uid" in kwargs:
        gted_account = get_gted_primary_account(**kwargs)

        if gted_account is None:
            raise InternalServerError(
                "Failed to locate GTED account with given " + list(dict.keys(kwargs))[0]
            )

        return {
            "actorDisplayName": gted_account["givenName"] + " " + gted_account["sn"],
            "actorLink": "/view/" + gted_account["gtPersonDirectoryId"],
        }

    if "realmId" in kwargs and "userId" in kwargs:
        for realm in get_realms():
            if kwargs["realmId"] == realm["id"]:
                keycloak_response = keycloak.get(
                    url=urlunparse(
                        (
                            urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
                            urlparse(app.config["KEYCLOAK_METADATA_URL"]).hostname,
                            "/admin/realms/" + realm["realm"] + "/users/" + kwargs["userId"],
                            "",
                            "",
                            "",
                        )
                    ),
                    timeout=(5, 5),
                )
                keycloak_response.raise_for_status()

                if (
                    fullmatch(
                        GEORGIA_TECH_USERNAME_REGEX,
                        keycloak_response.json()["username"],
                        IGNORECASE,
                    )
                    is not None
                ):
                    return get_actor(uid=keycloak_response.json()["username"])  # type: ignore

                return {
                    "actorDisplayName": keycloak_response.json()["username"],
                    "actorLink": urlunparse(
                        (
                            urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
                            urlparse(app.config["KEYCLOAK_METADATA_URL"]).hostname,
                            "/admin/master/console/",
                            "",
                            "",
                            "/"
                            + realm["realm"]
                            + "/users/"
                            + keycloak_response.json()["id"]
                            + "/settings",
                        )
                    ),
                }

    if "apiary_user_id" in kwargs:
        apiary_response = apiary.get(
            url=app.config["APIARY_BASE_URL"] + "/api/v1/users/" + str(kwargs["apiary_user_id"]),
            timeout=(5, 5),
        )
        apiary_response.raise_for_status()

        if (
            "user" in apiary_response.json()
            and apiary_response.json()["user"] is not None
            and "full_name" in apiary_response.json()["user"]
            and apiary_response.json()["user"]["full_name"] is not None
        ):
            return {
                "actorDisplayName": apiary_response.json()["user"]["full_name"],
            }

    if "email" in kwargs:
        email_results = search_by_email(Address(addr_spec=kwargs["email"]), with_gted=False)

        if len(email_results["results"]) > 0:
            return {
                "actorDisplayName": email_results["results"][0]["givenName"]
                + " "
                + email_results["results"][0]["surname"],
                "actorLink": "/view/" + email_results["results"][0]["directoryId"],
            }

        if "customer_id" in kwargs:
            credentials = service_account.Credentials.from_service_account_info(  # type: ignore
                info=app.config["GOOGLE_SERVICE_ACCOUNT_CREDENTIALS"],
                scopes=[
                    "https://www.googleapis.com/auth/admin.directory.user.readonly",
                    "https://www.googleapis.com/auth/admin.directory.customer.readonly",
                ],
                subject=app.config["GOOGLE_SUBJECT"],
            )

            directory = build(serviceName="admin", version="directory_v1", credentials=credentials)

            customer_details = (
                directory.customers().get(customerKey=kwargs["customer_id"]).execute()
            )

            user_details = directory.users().get(userKey=kwargs["email"]).execute()

            return {
                "actorDisplayName": user_details["name"]["fullName"],
                "actorLink": "https://www.google.com/a/"
                + customer_details["customerDomain"]
                + "/ServiceLogin?continue=https://admin.google.com/ac/search?query="
                + user_details["primaryEmail"],
            }

    if (
        "callerType" in kwargs
        and "key" in kwargs
        and kwargs["callerType"] == "KEY"
        and kwargs["key"] == "SYSTEM"
    ):
        return {
            "actorDisplayName": "system",
            "actorLink": None,
        }

    raise InternalServerError("Unable to identify actor, given: " + dumps(kwargs))


def get_client_display_name(auth_details: Dict[str, str]) -> str:
    """
    Get the display name for a client from a Keycloak event
    """
    if "realmId" in auth_details and "clientId" in auth_details:
        for realm in get_realms():
            if auth_details["realmId"] == realm["id"]:
                keycloak_response = keycloak.get(
                    url=urlunparse(
                        (
                            urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
                            urlparse(app.config["KEYCLOAK_METADATA_URL"]).hostname,
                            "/admin/realms/"
                            + realm["realm"]
                            + "/clients/"
                            + auth_details["clientId"],
                            "",
                            "",
                            "",
                        )
                    ),
                    timeout=(5, 5),
                )
                keycloak_response.raise_for_status()

                print(keycloak_response.text)

                return keycloak_response.json()["clientId"]  # type: ignore

    raise InternalServerError("Unable to identify client")


def search_keycloak(**kwargs: Union[str, bool]) -> List[Dict[str, Any]]:
    """
    Search Keycloak for accounts matching criteria specified in kwargs
    """
    keycloak_response = keycloak.get(
        url=urlunparse(
            (
                urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
                urlparse(app.config["KEYCLOAK_METADATA_URL"]).hostname,
                "/admin/realms/" + app.config["KEYCLOAK_REALM"] + "/users",
                "",
                "",
                "",
            )
        ),
        params=kwargs,
        timeout=(5, 5),
    )
    keycloak_response.raise_for_status()

    for account in keycloak_response.json():
        cursor = db().execute(
            "SELECT gt_person_directory_id FROM crosswalk WHERE primary_username = (:username)",
            {"username": account["username"]},
        )
        row = cursor.fetchone()

        if row is not None:
            db().execute(
                (
                    "UPDATE crosswalk SET keycloak_user_id = (:keycloak_user_id) WHERE gt_person_directory_id = (:gt_person_directory_id)"  # noqa
                ),
                {
                    "keycloak_user_id": account["id"],
                    "gt_person_directory_id": row[0],
                },
            )

            db().execute(
                (
                    "INSERT INTO crosswalk_email_address (email_address, gt_person_directory_id)"
                    " VALUES (:email_address, :gt_person_directory_id)"
                    " ON CONFLICT DO UPDATE SET gt_person_directory_id = (:gt_person_directory_id) WHERE email_address = (:email_address)"  # noqa
                ),
                {
                    "email_address": account["email"],
                    "gt_person_directory_id": row[0],
                },
            )

            workspace_email = get_attribute_value("googleWorkspaceAccount", account)

            if workspace_email is not None:
                db().execute(
                    (
                        "INSERT INTO crosswalk_email_address (email_address, gt_person_directory_id)"  # noqa
                        " VALUES (:email_address, :gt_person_directory_id)"
                        " ON CONFLICT DO UPDATE SET gt_person_directory_id = (:gt_person_directory_id) WHERE email_address = (:email_address)"  # noqa
                    ),
                    {
                        "email_address": workspace_email,
                        "gt_person_directory_id": row[0],
                    },
                )

            ramp_email = get_attribute_value("rampLoginEmailAddress", account)

            if ramp_email is not None:
                db().execute(
                    (
                        "INSERT INTO crosswalk_email_address (email_address, gt_person_directory_id)"  # noqa
                        " VALUES (:email_address, :gt_person_directory_id)"
                        " ON CONFLICT DO UPDATE SET gt_person_directory_id = (:gt_person_directory_id) WHERE email_address = (:email_address)"  # noqa
                    ),
                    {
                        "email_address": ramp_email,
                        "gt_person_directory_id": row[0],
                    },
                )

    return keycloak_response.json()  # type: ignore


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
    gted_account: Dict[str, Any], whitepages_entries: List[Dict[str, Dict[str, List[str]]]]
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
                and "graduate teaching assistant" not in entry["attributes"]["title"][0].lower()
                and "research technologist" not in entry["attributes"]["title"][0].lower()
                and "instructional associate" not in entry["attributes"]["title"][0].lower()
            ):
                if title is not None:
                    raise InternalServerError(
                        "Selected multiple Whitepages entries to display in results for "
                        + gted_account["gtPrimaryGTAccountUsername"]
                    )

                title = entry["attributes"]["title"][0]

                organizational_unit = get_attribute_value("ou", entry)

    if (
        organizational_unit is None
        and "gtCurriculum" in gted_account
        and gted_account["gtCurriculum"] is not None
        and len(gted_account["gtCurriculum"]) > 0
    ):
        for curriculum in gted_account["gtCurriculum"]:
            parts = curriculum.split("/")

            if len(parts) == 3:
                organizational_unit = parts[2]

    return {
        "givenName": gted_account["givenName"],
        "surname": gted_account["sn"],
        "directoryId": gted_account["gtPersonDirectoryId"],
        "primaryAffiliation": (
            gted_account["eduPersonPrimaryAffiliation"]
            if gted_account["eduPersonPrimaryAffiliation"] != "member"
            else None
        ),
        "affiliations": clean_affiliations(gted_account["eduPersonScopedAffiliation"]),
        "title": title,
        "organizationalUnit": organizational_unit,
    }


def format_search_result_blocks(
    search_results: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Convert search results to Slack Block Kit blocks for a modal
    """
    if len(search_results["results"]) == 0:
        return [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "No Georgia Tech account found for this user.",
                },
            }
        ]

    blocks: List[Dict[str, Any]] = []

    for result in search_results["results"]:
        lines = [f"*{result['givenName']} {result['surname']}*"]

        detail_parts = []
        if result.get("title"):
            detail_parts.append(result["title"])

        if result.get("organizationalUnit"):
            if result["organizationalUnit"] in get_majors():
                detail_parts.append(get_majors()[result["organizationalUnit"]])
            else:
                detail_parts.append(result["organizationalUnit"])

        if detail_parts:
            lines.append(" | ".join(detail_parts))

        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "\n".join(lines),
                },
            }
        )

        cursor = db().execute(
            "SELECT primary_username FROM crosswalk WHERE gt_person_directory_id = (:directory_id)",
            {"directory_id": result["directoryId"]},
        )
        row = cursor.fetchone()

        if row is not None:
            primary_username = row[0]
        else:
            raise InternalServerError(
                "Primary username not found for directory ID: " + result["directoryId"]
            )

        apiary_button = []

        apiary_account = get_apiary_account(result["directoryId"], is_frontend_request=False)

        if (
            apiary_account is not None
            and "id" in apiary_account
            and apiary_account["id"] is not None
        ):
            apiary_button = [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View in Apiary"},
                    "url": app.config["APIARY_BASE_URL"]
                    + "/nova/resources/users/"
                    + apiary_account["id"],
                }
            ]

        keycloak_button = []

        keycloak_account = get_keycloak_account(result["directoryId"], is_frontend_request=False)

        if (
            keycloak_account is not None
            and "id" in keycloak_account
            and keycloak_account["id"] is not None
        ):
            keycloak_button = [
                {
                    "text": {"type": "plain_text", "text": "View in Keycloak"},
                    "url": urlunparse(
                        (
                            urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
                            urlparse(app.config["KEYCLOAK_METADATA_URL"]).hostname,
                            "/admin/master/console/",
                            "",
                            "",
                            "/"
                            + app.config["KEYCLOAK_REALM"]
                            + "/users/"
                            + keycloak_account["id"]
                            + "/settings",
                        )
                    ),
                }
            ]

        google_workspace_button = []
        google_workspace_account = get_google_workspace_account(
            result["directoryId"], is_frontend_request=False
        )

        if (
            google_workspace_account is not None
            and "primaryEmail" in google_workspace_account
            and google_workspace_account["primaryEmail"] is not None
        ):
            google_workspace_button = [
                {
                    "text": {"type": "plain_text", "text": "View in Google Workspace"},
                    "url": "https://www.google.com/a/robojackets.org/ServiceLogin?continue=https://admin.google.com/ac/search?query="  # noqa
                    + google_workspace_account["primaryEmail"],
                }
            ]

        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View in Checkpoint"},
                        "url": "https://checkpoint.bcdc.robojackets.net/view/"
                        + result["directoryId"],
                        "action_id": "view_in_checkpoint",
                    },
                    *apiary_button,
                    {
                        "type": "overflow",
                        "action_id": "overflow_menu",
                        "options": [
                            {
                                "text": {"type": "plain_text", "text": "View in IAT"},
                                "url": "https://iat.gatech.edu/prod/person/"
                                + result["directoryId"],
                            },
                            {
                                "text": {"type": "plain_text", "text": "View in Grouper"},
                                "url": "https://grouper.gatech.edu/grouper/grouperUi/app/UiV2Main.index?operation=UiV2Subject.viewSubject&subjectId="  # noqa
                                + primary_username
                                + "&sourceId=gted-accounts",
                            },
                            *keycloak_button,
                            *google_workspace_button,
                        ],
                    },
                ],
            }
        )

    return blocks


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
            "grouperGroups": get_grouper_groups(),
            "keycloakDeepLinkBaseUrl": urlunparse(
                (
                    urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
                    urlparse(app.config["KEYCLOAK_METADATA_URL"]).hostname,
                    "/admin/master/console/",
                    "",
                    "",
                    "/" + app.config["KEYCLOAK_REALM"] + "/users/",
                )
            ),
            "apiaryBaseUrl": urlunparse(
                (
                    urlparse(app.config["APIARY_BASE_URL"]).scheme,
                    urlparse(app.config["APIARY_BASE_URL"]).hostname,
                    "",
                    "",
                    "",
                    "",
                )
            ),
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

    return redirect(session["next"])


@cache.memoize()
def search_by_username(username: str) -> Dict[str, Any]:
    """
    Search for a person by username
    """
    gted_account = get_gted_primary_account(uid=username)

    if gted_account is None:
        return {
            "results": [],
            "exactMatch": True,
        }

    return {
        "results": [
            format_search_result(
                gted_account,
                search_whitepages(uid=gted_account["gtPrimaryGTAccountUsername"]),
            ),
        ],
        "exactMatch": True,
    }


@cache.memoize()
def search_by_email(email_address: Address, with_gted: bool = True) -> Any:
    """
    Search for a person by email address
    """
    # search crosswalk by email
    cursor = db().execute(
        "SELECT gt_person_directory_id FROM crosswalk_email_address WHERE email_address = (:email_address)",  # noqa
        {"email_address": email_address.addr_spec.lower()},
    )
    row = cursor.fetchone()

    if row is not None:
        # found person in crosswalk, return that
        gted_account = get_gted_primary_account(gtPersonDirectoryId=row[0])

        if gted_account is None:
            raise InternalServerError("gtPersonDirectoryId from Crosswalk was not found in GTED")

        return {
            "results": [
                format_search_result(
                    gted_account,
                    search_whitepages(uid=gted_account["gtPrimaryGTAccountUsername"]),
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
            fullmatch(GEORGIA_TECH_USERNAME_REGEX, email_address.username, IGNORECASE) is not None
            and email_address.domain == "gatech.edu"
        ):
            username_results = search_by_username(email_address.username)

            if len(username_results["results"]) > 0:
                return username_results

    apiary_result = apiary.post(
        url=app.config["APIARY_BASE_URL"] + "/api/v1/users/searchByEmail",
        json={
            "email": email_address.addr_spec,
        },
    )

    if apiary_result.status_code != 404:
        apiary_result.raise_for_status()

        if (
            "user" in apiary_result.json()
            and apiary_result.json()["user"] is not None
            and "uid" in apiary_result.json()["user"]
            and apiary_result.json()["user"]["uid"] is not None
        ):
            return search_by_username(apiary_result.json()["user"]["uid"])

    keycloak_results = search_keycloak(email=email_address.addr_spec, exact=True)

    if len(keycloak_results) > 0:
        return search_by_username(keycloak_results[0]["username"])

    keycloak_results = search_keycloak(
        q=build_keycloak_filter(googleWorkspaceAccount=email_address.addr_spec)
    )

    if len(keycloak_results) > 0:
        return search_by_username(keycloak_results[0]["username"])

    keycloak_results = search_keycloak(
        q=build_keycloak_filter(rampLoginEmailAddress=email_address.addr_spec)
    )

    if len(keycloak_results) > 0:
        return search_by_username(keycloak_results[0]["username"])

    if with_gted:
        gted_account = get_gted_primary_account(
            filter=build_ldap_filter(mail=email_address.addr_spec)
        )

        if gted_account is not None:
            return {
                "results": [
                    format_search_result(
                        gted_account,
                        search_whitepages(uid=gted_account["gtPrimaryGTAccountUsername"]),
                    ),
                ],
                "exactMatch": True,
            }

        gted_account = get_gted_primary_account(
            filter=build_ldap_filter(gtSecondaryMailAdddress=email_address.addr_spec)
        )

        if gted_account is not None:
            return {
                "results": [
                    format_search_result(
                        gted_account,
                        search_whitepages(uid=gted_account["gtPrimaryGTAccountUsername"]),
                    ),
                ],
                "exactMatch": True,
            }

    return {"results": [], "exactMatch": True}


@app.post("/search")
def search() -> (
    Any
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
            return search_by_username(query)

        # check if the query is formatted like a first and last name
        split_name = query.split(" ")
        if len(split_name) == 2 and len(split_name[0]) > 1 and len(split_name[1]) > 1:
            entries = search_whitepages(givenName=split_name[0] + "*", sn=split_name[1] + "*")

            uids = set()

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

                gted_account = get_gted_primary_account(uid=uid)

                if gted_account is None:
                    raise InternalServerError(  # pylint: disable=raise-missing-from
                        "Account found in Whitepages but not GTED"
                    )

                formatted_results.append(format_search_result(gted_account, entries))

            if len(formatted_results) > 0:
                return {
                    "results": formatted_results,
                    "exactMatch": False,
                }

        keycloak_results = search_keycloak(search=query)
        formatted_results = []

        for account in keycloak_results:
            formatted_results.append(
                format_search_result(
                    get_gted_primary_account(uid=account["username"]),  # type: ignore
                    search_whitepages(uid=account["username"]),
                )
            )

        if len(formatted_results) > 0:
            return {
                "results": formatted_results,
                "exactMatch": False,
            }

        apiary_response = apiary.post(
            url=app.config["APIARY_BASE_URL"] + "/api/v1/users/fuzzySearch",
            json={
                "query": query,
            },
            timeout=(5, 5),
        )
        apiary_response.raise_for_status()

        for account in apiary_response.json()["users"]:
            formatted_results.append(
                format_search_result(
                    get_gted_primary_account(uid=account["uid"]),  # type: ignore
                    search_whitepages(uid=account["uid"]),
                )
            )

        return {
            "results": formatted_results,
            "exactMatch": False,
        }


@app.get("/view/<directory_id>/whitepages")
def get_whitepages_records(directory_id: str) -> Any:
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
        gted_account = get_gted_primary_account(gtPersonDirectoryId=directory_id)

        if gted_account is None:
            raise NotFound("Provided directory ID was not found in Crosswalk or GTED")

        primary_username = gted_account["gtPrimaryGTAccountUsername"]

    return search_whitepages(uid=primary_username)


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


@app.get("/view/<directory_id>/gtad")
def get_gtad_account(directory_id: str) -> Any:
    """
    Get the GTAD account for a given gtPersonDirectoryId
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
        gted_account = get_gted_primary_account(gtPersonDirectoryId=directory_id)

        if gted_account is None:
            raise NotFound("Provided directory ID was not found in Crosswalk or GTED")

        primary_username = gted_account["gtPrimaryGTAccountUsername"]

    ldap = Connection(
        Server("campusad.ad.gatech.edu", connect_timeout=1),
        user=app.config["GTAD_BIND_DN"],
        password=app.config["GTAD_BIND_PASSWORD"],
        auto_bind=True,
        raise_exceptions=True,
        receive_timeout=1,
    )
    with sentry_sdk.start_span(op="ldap.search"):
        result = ldap.search(
            search_base="dc=ad,dc=gatech,dc=edu",
            search_filter="(uid=" + primary_username + ")",
            attributes=["*"],
        )

        if result is True:
            for entry in ldap.entries:
                return loads(entry.entry_to_json())

    return {}


@app.get("/view/<directory_id>/keycloak")
def get_keycloak_account(directory_id: str, is_frontend_request: bool = True) -> Dict[str, Any]:
    """
    Get the Keycloak account for a given gtPersonDirectoryId
    """
    if is_frontend_request:
        if "has_access" not in session:
            raise Unauthorized("Not authenticated")

        if session["has_access"] is not True:
            raise Forbidden("Access denied")

    cursor = db().execute(
        "SELECT keycloak_user_id FROM crosswalk WHERE gt_person_directory_id = (:directory_id)",
        {"directory_id": directory_id},
    )
    row = cursor.fetchone()

    if row is not None and row[0] is not None:
        keycloak_response = keycloak.get(
            url=urlunparse(
                (
                    urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
                    urlparse(app.config["KEYCLOAK_METADATA_URL"]).hostname,
                    "/admin/realms/" + app.config["KEYCLOAK_REALM"] + "/users/" + row[0],
                    "",
                    "",
                    "",
                )
            ),
            timeout=(5, 5),
        )
        keycloak_response.raise_for_status()

        return keycloak_response.json()  # type: ignore

    cursor = db().execute(
        "SELECT primary_username FROM crosswalk WHERE gt_person_directory_id = (:directory_id)",
        {"directory_id": directory_id},
    )
    row = cursor.fetchone()

    if row is not None:
        primary_username = row[0]
    else:
        gted_account = get_gted_primary_account(gtPersonDirectoryId=directory_id)

        if gted_account is None:
            raise NotFound("Provided directory ID was not found in Crosswalk or GTED")

        primary_username = gted_account["gtPrimaryGTAccountUsername"]

    keycloak_results = search_keycloak(username=primary_username, exact=True)

    if len(keycloak_results) > 0:
        return keycloak_results[0]

    return {}


@app.get("/view/<directory_id>/sums")
def get_sums_membership(directory_id: str) -> Dict[str, bool]:
    """
    Get SUMS membership for a given gtPersonDirectoryId
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
        gted_account = get_gted_primary_account(gtPersonDirectoryId=directory_id)

        if gted_account is None:
            raise NotFound("Provided directory ID was not found in Crosswalk or GTED")

        primary_username = gted_account["gtPrimaryGTAccountUsername"]

    sums_response = get(
        url="https://sums.gatech.edu/SUMSAPI/rest/SCC_BGMembership/GetMemberships",
        headers={
            "User-Agent": USER_AGENT,
        },
        params={
            "Key": app.config["SUMS_API_KEY"],
            "GTUsername": primary_username,
        },
        timeout=(5, 5),
    )
    sums_response.raise_for_status()

    return sums_response.json()  # type: ignore


@app.get("/view/<directory_id>/apiary")
def get_apiary_account(directory_id: str, is_frontend_request: bool = True) -> Dict[str, Any]:
    """
    Get the Apiary user for a given gtPersonDirectoryId
    """
    if is_frontend_request:
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
        gted_account = get_gted_primary_account(gtPersonDirectoryId=directory_id)

        if gted_account is None:
            raise NotFound("Provided directory ID was not found in Crosswalk or GTED")

        primary_username = gted_account["gtPrimaryGTAccountUsername"]

    apiary_response = apiary.get(
        url=app.config["APIARY_BASE_URL"] + "/api/v1/users/" + primary_username,
        params={
            "include": "actions,attendance.recorded,attendance.attendable,teams,roles",
        },
        headers={
            "x-cache-bypass": "bypass",
        },
        timeout=(5, 5),
    )
    if apiary_response.status_code == 404:
        return {}

    apiary_response.raise_for_status()

    return apiary_response.json()["user"]  # type: ignore


@app.get("/view/<directory_id>/events")
def get_events(directory_id: str) -> List[Dict[str, Any]]:
    """
    Get events that are relevant for a given gtPersonDirectoryId
    """
    if "has_access" not in session:
        raise Unauthorized("Not authenticated")

    if session["has_access"] is not True:
        raise Forbidden("Access denied")

    keycloak_user_id = None
    primary_username = None
    events = []

    cursor = db().execute(
        "SELECT keycloak_user_id FROM crosswalk WHERE gt_person_directory_id = (:directory_id)",
        {"directory_id": directory_id},
    )
    row = cursor.fetchone()

    if row is not None and row[0] is not None:
        keycloak_user_id = row[0]
    else:
        cursor = db().execute(
            "SELECT primary_username FROM crosswalk WHERE gt_person_directory_id = (:directory_id)",
            {"directory_id": directory_id},
        )
        row = cursor.fetchone()

        if row is not None:
            primary_username = row[0]
        else:
            gted_account = get_gted_primary_account(gtPersonDirectoryId=directory_id)

            if gted_account is None:
                raise NotFound("Provided directory ID was not found in Crosswalk or GTED")

            primary_username = gted_account["gtPrimaryGTAccountUsername"]

        keycloak_results = search_keycloak(username=primary_username, exact=True)

        if len(keycloak_results) > 0:
            keycloak_user_id = keycloak_results[0]["id"]

    if keycloak_user_id is not None:
        keycloak_response = keycloak.get(
            url=urlunparse(
                (
                    urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
                    urlparse(app.config["KEYCLOAK_METADATA_URL"]).hostname,
                    "/admin/realms/" + app.config["KEYCLOAK_REALM"] + "/events",
                    "",
                    "",
                    "",
                )
            ),
            params={
                "user": keycloak_user_id,
            },
            timeout=(5, 5),
        )
        keycloak_response.raise_for_status()

        for event in keycloak_response.json():
            if event["clientId"].startswith("http"):
                client_id = urlparse(event["clientId"]).netloc
            else:
                client_id = event["clientId"]

            events.append(
                {
                    "eventTimestamp": event["time"],
                    "eventDescription": "logged into " + client_id,
                    "eventLink": urlunparse(
                        (
                            urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
                            urlparse(app.config["KEYCLOAK_METADATA_URL"]).hostname,
                            "/admin/master/console/",
                            "",
                            "",
                            "/"
                            + app.config["KEYCLOAK_REALM"]
                            + "/users/"
                            + keycloak_user_id
                            + "/events",
                        )
                    ),
                }
                | get_actor(gtPersonDirectoryId=directory_id)
            )

        keycloak_response = keycloak.get(
            url=urlunparse(
                (
                    urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
                    urlparse(app.config["KEYCLOAK_METADATA_URL"]).hostname,
                    "/admin/realms/" + app.config["KEYCLOAK_REALM"] + "/admin-events",
                    "",
                    "",
                    "",
                )
            ),
            params={
                "resourcePath": "users/" + keycloak_user_id + "*",
            },
            timeout=(5, 5),
        )
        keycloak_response.raise_for_status()

        for event in keycloak_response.json():
            if event["operationType"] == "UPDATE":
                description = (
                    "updated "
                    + get_actor(gtPersonDirectoryId=directory_id)["actorDisplayName"]
                    + "'s Keycloak account using "
                    + get_client_display_name(event["authDetails"])
                )
            else:
                raise InternalServerError("Unrecognized operationType in Keycloak event")

            events.append(
                {
                    "eventTimestamp": event["time"],
                    "eventDescription": description,
                    "eventLink": urlunparse(
                        (
                            urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
                            urlparse(app.config["KEYCLOAK_METADATA_URL"]).hostname,
                            "/admin/master/console/",
                            "",
                            "",
                            "/"
                            + app.config["KEYCLOAK_REALM"]
                            + "/users/"
                            + keycloak_user_id
                            + "/events",
                        )
                    ),
                }
                | get_actor(**event["authDetails"])
            )

    if primary_username is None:
        cursor = db().execute(
            "SELECT primary_username FROM crosswalk WHERE gt_person_directory_id = (:directory_id)",
            {"directory_id": directory_id},
        )
        row = cursor.fetchone()

        if row is not None:
            primary_username = row[0]
        else:
            gted_account = get_gted_primary_account(gtPersonDirectoryId=directory_id)

            if gted_account is None:
                raise NotFound("Provided directory ID was not found in Crosswalk or GTED")

            primary_username = gted_account["gtPrimaryGTAccountUsername"]

    apiary_response = apiary.get(
        url=app.config["APIARY_BASE_URL"] + "/api/v1/users/" + primary_username,
        params={
            "include": "actions,attendance.recorded,attendance.attendable",
        },
        headers={
            "x-cache-bypass": "bypass",
        },
        timeout=(5, 5),
    )
    if apiary_response.status_code != 404:
        apiary_response.raise_for_status()

    if (
        "user" in apiary_response.json()
        and apiary_response.json()["user"] is not None
        and "attendance" in apiary_response.json()["user"]
        and apiary_response.json()["user"]["attendance"] is not None
    ):
        for attendance in apiary_response.json()["user"]["attendance"]:
            if "recorded_by" in attendance and attendance["recorded_by"] is not None:
                actor = get_actor(**attendance["recorded_by"])
            else:
                actor = {
                    "actorDisplayName": "import",
                    "actorLink": None,
                }

            events.append(
                {
                    "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                        attendance["created_at"]
                    ),
                    "eventDescription": (
                        "recorded attendance for "
                        + get_actor(gtPersonDirectoryId=directory_id)["actorDisplayName"]
                        + " at "
                        + attendance["attendable"]["name"]
                        + " using "
                        + attendance["source"]
                    ),
                    "eventLink": urlunparse(
                        (
                            urlparse(app.config["APIARY_BASE_URL"]).scheme,
                            urlparse(app.config["APIARY_BASE_URL"]).hostname,
                            "/nova/resources/attendance/" + str(attendance["id"]),
                            "",
                            "",
                            "",
                        )
                    ),
                }
                | actor
            )

    if (
        "user" in apiary_response.json()
        and apiary_response.json()["user"] is not None
        and "actions" in apiary_response.json()["user"]
        and apiary_response.json()["user"]["actions"] is not None
    ):
        for action in apiary_response.json()["user"]["actions"]:
            print(action)
            if "actionable" not in action or action["actionable"] is None:
                continue

            if action["name"] == "Detach":
                if "target" not in action or action["target"] is None:
                    # target was deleted after the action was logged
                    continue

                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "detached "
                            + get_relationship_description("target", action)
                            + " from "
                            + get_relationship_description("actionable", action)
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Update":
                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "updated "
                            + get_relationship_description("target", action)
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Delete":
                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "deleted "
                            + get_relationship_description("target", action)
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Reset API Token" or action["name"] == "Reset Api Token":
                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "reset the API token for "
                            + get_relationship_description("target", action)
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Attach":
                if "target" not in action or action["target"] is None:
                    # target was deleted after the action was logged
                    continue

                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "attached "
                            + get_relationship_description("target", action)
                            + " to "
                            + get_relationship_description("actionable", action)
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Create":
                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "created "
                            + get_relationship_description("target", action)
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Sync Access":
                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "synced access for "
                            + get_relationship_description("target", action)
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Override Access":
                until_string = ""

                timestamp_match = re.search(ACCESS_OVERRIDE_TIMESTAMP_REGEX, action["fields"])

                if timestamp_match is not None:
                    until_string = " until " + datetime.datetime.fromisoformat(
                        timestamp_match.group("timestamp")
                    ).strftime("%B %d, %Y")

                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "granted an access override for "
                            + get_relationship_description("target", action)
                            + until_string
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Generate Resume Book":
                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": ("generated a resume book using Nova"),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Update Majors":
                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "updated majors for "
                            + get_relationship_description("target", action)
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Refresh from GTED":
                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "refreshed "
                            + get_relationship_description("target", action)
                            + "'s Apiary account from GTED using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Reset Remote Attendance":
                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "reset the remote attendance link for "
                            + get_relationship_description("target", action)
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Restore":
                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "restored "
                            + get_relationship_description("target", action)
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Create Dues Packages":
                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "created dues packages for "
                            + get_relationship_description("target", action)
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Add Payment":
                method = ""

                method_match = re.search(PAYMENT_METHOD_REGEX, action["fields"])

                if method_match is not None:
                    method = method_match.group("method") + " "

                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "recorded a "
                            + method
                            + "payment for "
                            + get_relationship_description("target", action)
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Distribute Shirt":
                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "distributed shirt to "
                            + get_actor(apiary_user_id=action["target"]["user_id"])[
                                "actorDisplayName"
                            ]
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Distribute Polo":
                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "distributed polo to "
                            + get_actor(apiary_user_id=action["target"]["user_id"])[
                                "actorDisplayName"
                            ]
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Distribute Merchandise":
                to_member_string = ""

                user_id_match = re.search(NUMBER_IN_QUOTES_REGEX, action["fields"])

                if user_id_match is not None:
                    to_member_string = (
                        " to "
                        + get_actor(apiary_user_id=user_id_match.group("user_id"))[
                            "actorDisplayName"
                        ]
                    )

                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "distributed "
                            + get_relationship_description("target", action)
                            + to_member_string
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Undo Merchandise Distribution":
                to_member_string = ""

                user_id_match = re.search(NUMBER_IN_QUOTES_REGEX, action["fields"])

                if user_id_match is not None:
                    to_member_string = (
                        " for "
                        + get_actor(apiary_user_id=user_id_match.group("user_id"))[
                            "actorDisplayName"
                        ]
                    )

                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "reset merchandise distribution for "
                            + get_relationship_description("target", action)
                            + to_member_string
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Create Personal Access Token":
                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "created a personal access token for "
                            + get_relationship_description("target", action)
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Refund Payment":
                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": ("refunded a payment using Nova"),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif (
                action["name"] == "Revoke All OAuth2 Tokens"
                or action["name"] == "Revoke All Tokens"
            ):
                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "revoked all Apiary tokens for "
                            + get_relationship_description("target", action)
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Download Forms":
                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "downloaded travel forms for "
                            + get_relationship_description("target", action)
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Download IAA Request":
                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "downloaded IAA request for "
                            + get_relationship_description("target", action)
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Download Passenger Name List":
                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "downloaded passenger name list for "
                            + get_relationship_description("target", action)
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Void Envelope":
                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "voided a DocuSign envelope for "
                            + get_actor(apiary_user_id=action["actionable"]["signed_by"])[
                                "actorDisplayName"
                            ]
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Record Cash Payment":
                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "recorded a cash payment for "
                            + get_relationship_description("target", action)
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Record Check Payment":
                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "recorded a check payment for "
                            + get_relationship_description("target", action)
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Apply Waiver" or action["name"] == "Record Waiver Payment":
                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "applied a waiver for "
                            + get_relationship_description("target", action)
                            + " using Nova"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Matrix Airfare Search":
                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "searched for flights for "
                            + get_relationship_description("target", action)
                            + " using Matrix"
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Review Trip":
                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": (
                            "reviewed " + get_relationship_description("target", action)
                        ),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Create OAuth2 Client":
                client_name = ""

                client_name_match = re.search(CLIENT_NAME_REGEX, action["fields"])

                if client_name_match is not None:
                    client_name = client_name_match.group("client_name") + " "

                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(
                            action["created_at"]
                        ),
                        "eventDescription": ("created OAuth client " + client_name),
                        "eventLink": urlunparse(
                            (
                                urlparse(app.config["APIARY_BASE_URL"]).scheme,
                                urlparse(app.config["APIARY_BASE_URL"]).hostname,
                                "/nova/resources/action-events/" + str(action["id"]),
                                "",
                                "",
                                "",
                            )
                        ),
                    }
                    | get_actor(**action["actor"])
                )

            elif action["name"] == "Send Notification":
                continue

            else:
                raise InternalServerError(
                    "Unable to determine description for action: " + dumps(action)
                )

    email_addresses = get_email_addresses(directory_id)

    credentials = service_account.Credentials.from_service_account_info(  # type: ignore
        info=app.config["GOOGLE_SERVICE_ACCOUNT_CREDENTIALS"],
        scopes=["https://www.googleapis.com/auth/admin.reports.audit.readonly"],
        subject=app.config["GOOGLE_SUBJECT"],
    )
    activities = build(  # pylint: disable=no-member
        serviceName="admin", version="reports_v1", credentials=credentials
    ).activities()

    for email_address in email_addresses:
        groups_events = activities.list(
            userKey="all",
            applicationName="groups_enterprise",
            filters="member_id==" + email_address,
        ).execute()

        if "items" in groups_events and groups_events["items"] is not None:
            for item in groups_events["items"]:
                event_type = None
                to_from = None
                member_id = None
                group_id = None

                if "events" in item and item["events"] is not None and len(item["events"]) > 0:
                    if "name" in item["events"][0] and item["events"][0]["name"] in (
                        "add_user",
                        "add_member",
                    ):
                        event_type = "added"
                        to_from = "to"
                    elif "name" in item["events"][0] and item["events"][0]["name"] in (
                        "remove_user",
                        "remove_member",
                    ):
                        event_type = "removed"
                        to_from = "from"
                    else:
                        raise InternalServerError(
                            "Unable to determine group event type: " + dumps(item["events"][0])
                        )

                    for parameter in item["events"][0]["parameters"]:
                        if parameter["name"] == "member_id":
                            member_id = parameter["value"]
                        elif parameter["name"] == "group_id":
                            group_id = parameter["value"]

                if member_id is None:
                    raise InternalServerError(
                        "Unable to determine member ID: " + dumps(item["events"][0])
                    )

                if group_id is None:
                    raise InternalServerError(
                        "Unable to determine group ID: " + dumps(item["events"][0])
                    )

                event_description = (
                    event_type + " " + member_id + " " + to_from + " group " + group_id  # type: ignore  # noqa
                )

                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(item["id"]["time"]),
                        "eventDescription": event_description,
                        "eventLink": None,
                    }
                    | get_actor(**item["actor"], customer_id=item["id"]["customerId"])
                )

    workspace_account = get_google_workspace_account(directory_id)

    if "primaryEmail" in workspace_account and workspace_account["primaryEmail"] is not None:
        admin_events = activities.list(
            userKey="all",
            applicationName="admin",
            filters="USER_EMAIL==" + workspace_account["primaryEmail"],
        ).execute()

        if "items" in admin_events and admin_events["items"] is not None:
            for item in admin_events["items"]:
                if "events" in item and item["events"] is not None and len(item["events"]) > 0:
                    if (
                        "name" in item["events"][0]
                        and item["events"][0]["name"] == "ADD_GROUP_MEMBER"
                    ):
                        event_description = (
                            "added "
                            + get_parameter_value("USER_EMAIL", item["events"][0]["parameters"])
                            + " to group "
                            + get_parameter_value("GROUP_EMAIL", item["events"][0]["parameters"])
                        )

                    elif (
                        "name" in item["events"][0]
                        and item["events"][0]["name"] == "USER_LICENSE_ASSIGNMENT"
                    ):
                        event_description = (
                            "assigned "
                            + get_parameter_value("NEW_VALUE", item["events"][0]["parameters"])
                            + " license to "
                            + get_parameter_value("USER_EMAIL", item["events"][0]["parameters"])
                        )

                    elif "name" in item["events"][0] and item["events"][0]["name"] == "CREATE_USER":
                        event_description = "created user " + get_parameter_value(
                            "USER_EMAIL", item["events"][0]["parameters"]
                        )

                    elif (
                        "name" in item["events"][0]
                        and item["events"][0]["name"] == "MOVE_USER_TO_ORG_UNIT"
                    ):
                        event_description = (
                            "moved "
                            + get_parameter_value("USER_EMAIL", item["events"][0]["parameters"])
                            + " to "
                            + get_parameter_value("NEW_VALUE", item["events"][0]["parameters"])
                        )

                    else:
                        raise InternalServerError(
                            "Unable to determine admin event type: " + dumps(item)
                        )

                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(item["id"]["time"]),
                        "eventDescription": event_description,
                        "eventLink": None,
                    }
                    | get_actor(**item["actor"], customer_id=item["id"]["customerId"])
                )

        login_events = activities.list(
            userKey=workspace_account["id"],
            applicationName="login",
        ).execute()

        if "items" in login_events and login_events["items"] is not None:
            for item in login_events["items"]:
                print(dumps(item))

                if "events" in item and item["events"] is not None and len(item["events"]) > 0:
                    if "name" in item["events"][0] and item["events"][0]["name"] == "login_success":
                        event_description = (
                            "logged in to Google Workspace using "
                            + get_parameter_value("login_type", item["events"][0]["parameters"])
                        )

                    elif (
                        "name" in item["events"][0] and item["events"][0]["name"] == "login_failure"
                    ):
                        event_description = (
                            "failed login to Google Workspace using "
                            + get_parameter_value("login_type", item["events"][0]["parameters"])
                        )

                    elif "name" in item["events"][0] and item["events"][0]["name"] in (
                        "login_verification",
                        "login_challenge",
                    ):
                        event_description = (
                            get_parameter_value(
                                "login_challenge_status", item["events"][0]["parameters"]
                            )
                            + " login challenge for Google Workspace using "
                            + get_parameter_value(
                                "login_challenge_method", item["events"][0]["parameters"]
                            )
                        )

                    elif (
                        "name" in item["events"][0]
                        and item["events"][0]["name"] == "titanium_enroll"
                    ):
                        event_description = "enrolled in Advanced Protection for Google Workspace"

                    elif (
                        "name" in item["events"][0]
                        and item["events"][0]["name"] == "recovery_email_edit"
                    ):
                        event_description = "updated recovery email for Google Workspace"

                    elif (
                        "name" in item["events"][0]
                        and item["events"][0]["name"] == "recovery_phone_edit"
                    ):
                        event_description = "updated recovery phone for Google Workspace"

                    elif "name" in item["events"][0] and item["events"][0]["name"] == "logout":
                        event_description = "logged out of Google Workspace"

                    elif (
                        "name" in item["events"][0]
                        and item["events"][0]["name"] == "blocked_sender"
                    ):
                        event_description = (
                            "blocked sender "
                            + get_parameter_value(
                                "affected_email_address", item["events"][0]["parameters"]
                            )
                            + " in Gmail"
                        )

                    else:
                        raise InternalServerError(
                            "Unable to determine login event type: " + dumps(item)
                        )

                events.append(
                    {
                        "eventTimestamp": parse_apiary_timestamp_to_unix_millis(item["id"]["time"]),
                        "eventDescription": event_description,
                        "eventLink": None,
                    }
                    | get_actor(**item["actor"], customer_id=item["id"]["customerId"])
                )

    grouper_events = get_grouper_memberships(directory_id)

    if "wsMemberships" in grouper_events and grouper_events["wsMemberships"] is not None:
        for membership in grouper_events["wsMemberships"]:
            events.append(
                {
                    "eventTimestamp": parse_grouper_timestamp_to_unix_millis(
                        membership["createTime"]
                    ),
                    "eventDescription": "added "
                    + membership["subjectId"]
                    + " to "
                    + membership["groupName"]
                    + " in Grouper",
                    "eventLink": None,
                    "actorDisplayName": "system",
                    "actorLink": None,
                }
            )

    return events


def get_parameter_value(name: str, parameters: List[Dict[str, str]]) -> str:
    """
    Get the value for a parameter from a Google Workspace audit event
    """
    for parameter in parameters:
        if parameter["name"] == name:
            if "value" in parameter:
                return parameter["value"]

            return " and ".join(parameter["multiValue"])

    raise InternalServerError("Missing parameter " + name + " in " + dumps(parameters))


def get_relationship_description(relationship_type: str, action: Dict[str, Any]) -> str:
    """
    Get a brief description for a related model for a Nova action
    """
    if action[relationship_type + "_type"] == "App\\Models\\DuesPackage":
        return "dues package " + action[relationship_type]["name"]  # type: ignore
    if action[relationship_type + "_type"] == "Spatie\\Permission\\Models\\Role":
        return "role " + action[relationship_type]["name"]  # type: ignore
    if action[relationship_type + "_type"] == "App\\Models\\User":
        return action[relationship_type]["full_name"]  # type: ignore
    if (
        action[relationship_type + "_type"] == "App\\Models\\Team"
        or action[relationship_type + "_type"] == "team"
    ):
        return "team " + action[relationship_type]["name"]  # type: ignore
    if action[relationship_type + "_type"] == "Spatie\\Permission\\Models\\Permission":
        return "permission " + action[relationship_type]["name"]  # type: ignore
    if action[relationship_type + "_type"] == "App\\Models\\Major":
        return "major " + action[relationship_type]["display_name"]  # type: ignore
    if action[relationship_type + "_type"] == "App\\Models\\FiscalYear":
        return "fiscal year " + action[relationship_type]["ending_year"]  # type: ignore
    if action[relationship_type + "_type"] == "dues-transaction":
        return (  # type: ignore
            get_actor(apiary_user_id=action[relationship_type]["user_id"])["actorDisplayName"]
            + "'s dues transaction for "
            + action[relationship_type]["package"]["name"]
        )
    if action[relationship_type + "_type"] == "App\\Models\\MembershipAgreementTemplate":
        return (
            "membership agreement "
            + str(datetime.datetime.fromisoformat(action[relationship_type]["updated_at"]).year)
            + " edition"
        )
    if action[relationship_type + "_type"] == "App\\Models\\Merchandise":
        return action[relationship_type]["name"]  # type: ignore
    if action[relationship_type + "_type"] == "App\\Models\\RemoteAttendanceLink":
        return "remote attendance link for " + action[relationship_type]["attendable"]["name"]  # type: ignore  # noqa
    if action[relationship_type + "_type"] == "App\\Models\\ClassStanding":
        return "major " + action[relationship_type]["name"]  # type: ignore
    if action[relationship_type + "_type"] == "event":
        return action[relationship_type]["name"]  # type: ignore
    if action[relationship_type + "_type"] == "App\\Models\\Travel":
        return action[relationship_type]["name"]  # type: ignore
    if (
        action[relationship_type + "_type"] == "App\\Models\\Signature"
        or action[relationship_type + "_type"] == "signature"
    ):
        return (  # type: ignore
            "membership agreement for "
            + get_actor(apiary_user_id=action[relationship_type]["user_id"])["actorDisplayName"]
        )
    if action[relationship_type + "_type"] == "travel-assignment":
        return (  # type: ignore
            get_actor(apiary_user_id=action[relationship_type]["user_id"])["actorDisplayName"]
            + "'s trip assignment for "
            + action[relationship_type]["travel"]["name"]
        )
    if action[relationship_type + "_type"] == "App\\Models\\Payment":
        return "payment"
    if action[relationship_type + "_type"] == "App\\Models\\OAuth2Client":
        return "OAuth client " + action[relationship_type]["name"]  # type: ignore
    if action[relationship_type + "_type"] == "App\\Models\\Sponsor":
        return "sponsor " + action[relationship_type]["name"]  # type: ignore
    if action[relationship_type + "_type"] == "App\\Models\\SponsorDomain":
        return "sponsor domain " + action[relationship_type]["domain_name"]  # type: ignore

    raise InternalServerError("Unable to determine target for action: " + dumps(action))


def parse_apiary_timestamp_to_unix_millis(timestamp: str) -> int:
    """
    Convert a timestamp from Apiary into Unix milliseconds to send to the frontend
    """
    return int(
        datetime.datetime.fromisoformat(timestamp).replace(tzinfo=datetime.timezone.utc).timestamp()
        * 1000
    )


def parse_grouper_timestamp_to_unix_millis(timestamp: str) -> int:
    """
    Convert a timestamp from Grouper into Unix milliseconds to send to the frontend
    """
    eastern = ZoneInfo("America/New_York")
    dt = datetime.datetime.strptime(timestamp, "%Y/%m/%d %H:%M:%S.%f")
    dt_eastern = dt.replace(tzinfo=eastern)
    return int(dt_eastern.timestamp() * 1000)


def get_email_addresses(directory_id: str) -> set[str]:
    """
    Collect all known email addresses for a given gtPersonDirectoryId from Apiary, Keycloak,
    and Whitepages
    """
    email_addresses = set[str]()

    apiary_account = get_apiary_account(directory_id)

    if "gmail_address" in apiary_account and apiary_account["gmail_address"] is not None:
        email_addresses.add(apiary_account["gmail_address"])
    if "clickup_email" in apiary_account and apiary_account["clickup_email"] is not None:
        email_addresses.add(apiary_account["clickup_email"])
    if "gt_email" in apiary_account and apiary_account["gt_email"] is not None:
        email_addresses.add(apiary_account["gt_email"])

    keycloak_account = get_keycloak_account(directory_id)

    if "email" in keycloak_account and keycloak_account["email"] is not None:
        email_addresses.add(keycloak_account["email"])

    google_workspace_account = get_attribute_value("googleWorkspaceAccount", keycloak_account)
    if google_workspace_account is not None:
        email_addresses.add(google_workspace_account)

    ramp_login_email_address = get_attribute_value("rampLoginEmailAddress", keycloak_account)
    if ramp_login_email_address is not None:
        email_addresses.add(ramp_login_email_address)

    whitepages_entries = get_whitepages_records(directory_id)

    for entry in whitepages_entries:
        uid = get_attribute_value("primaryUid", entry)
        if uid is not None:
            email_addresses.add(uid + "@gatech.edu")

        mail = get_attribute_value("mail", entry)
        if mail is not None:
            email_addresses.add(mail)

    for email_address in email_addresses:
        db().execute(
            (
                "INSERT INTO crosswalk_email_address (email_address, gt_person_directory_id)"  # noqa
                " VALUES (:email_address, :gt_person_directory_id)"
                " ON CONFLICT DO UPDATE SET gt_person_directory_id = (:gt_person_directory_id) WHERE email_address = (:email_address)"  # noqa
            ),
            {
                "email_address": email_address,
                "gt_person_directory_id": directory_id,
            },
        )

    cursor = db().execute(
        "SELECT email_address FROM crosswalk_email_address WHERE gt_person_directory_id = (:directory_id)",  # noqa
        {"directory_id": directory_id},
    )
    rows = cursor.fetchall()

    for row in rows:
        email_addresses.add(row[0])

    return email_addresses


@app.get("/view/<directory_id>/google-groups")
def get_google_groups(directory_id: str) -> Any:
    """
    Get Google Groups for a given gtPersonDirectoryId
    """
    if "has_access" not in session:
        raise Unauthorized("Not authenticated")

    if session["has_access"] is not True:
        raise Forbidden("Access denied")

    email_addresses = get_email_addresses(directory_id)

    credentials = service_account.Credentials.from_service_account_info(  # type: ignore
        info=app.config["GOOGLE_SERVICE_ACCOUNT_CREDENTIALS"],
        scopes=["https://www.googleapis.com/auth/admin.directory.group.readonly"],
        subject=app.config["GOOGLE_SUBJECT"],
    )
    groups = build(  # pylint: disable=no-member
        serviceName="admin", version="directory_v1", credentials=credentials
    ).groups()

    group_memberships = {}

    for email_address in email_addresses:
        group_memberships[email_address] = groups.list(userKey=email_address).execute()

    return group_memberships


@app.get("/view/<directory_id>/google-workspace")
def get_google_workspace_account(directory_id: str, is_frontend_request: bool = True) -> Any:
    """
    Get Google Workspace account for a given gtPersonDirectoryId
    """
    if is_frontend_request:
        if "has_access" not in session:
            raise Unauthorized("Not authenticated")

        if session["has_access"] is not True:
            raise Forbidden("Access denied")

    credentials = service_account.Credentials.from_service_account_info(  # type: ignore
        info=app.config["GOOGLE_SERVICE_ACCOUNT_CREDENTIALS"],
        scopes=["https://www.googleapis.com/auth/admin.directory.user.readonly"],
        subject=app.config["GOOGLE_SUBJECT"],
    )
    users = build(  # pylint: disable=no-member
        serviceName="admin", version="directory_v1", credentials=credentials
    ).users()

    cursor = db().execute(
        "SELECT google_workspace_user_id FROM crosswalk WHERE gt_person_directory_id = (:directory_id)",  # noqa
        {"directory_id": directory_id},
    )
    row = cursor.fetchone()

    if row is not None and row[0] is not None:
        workspace_account = users.get(userKey=row[0]).execute()
        for email in workspace_account["emails"]:
            db().execute(
                (
                    "INSERT INTO crosswalk_email_address (email_address, gt_person_directory_id)"  # noqa
                    " VALUES (:email_address, :gt_person_directory_id)"
                    " ON CONFLICT DO UPDATE SET gt_person_directory_id = (:gt_person_directory_id) WHERE email_address = (:email_address)"  # noqa
                ),
                {
                    "email_address": email["address"],
                    "gt_person_directory_id": directory_id,
                },
            )

        if "recoveryEmail" in workspace_account and workspace_account["recoveryEmail"] is not None:
            db().execute(
                (
                    "INSERT INTO crosswalk_email_address (email_address, gt_person_directory_id)"  # noqa
                    " VALUES (:email_address, :gt_person_directory_id)"
                    " ON CONFLICT DO UPDATE SET gt_person_directory_id = (:gt_person_directory_id) WHERE email_address = (:email_address)"  # noqa
                ),
                {
                    "email_address": workspace_account["recoveryEmail"],
                    "gt_person_directory_id": directory_id,
                },
            )

        return workspace_account

    keycloak_account = get_keycloak_account(directory_id, is_frontend_request=is_frontend_request)

    google_workspace_account = get_attribute_value("googleWorkspaceAccount", keycloak_account)
    if google_workspace_account is not None:
        workspace_account = users.get(userKey=google_workspace_account).execute()

        db().execute(
            (
                "UPDATE crosswalk SET google_workspace_user_id = (:google_workspace_user_id) WHERE gt_person_directory_id = (:gt_person_directory_id)"  # noqa
            ),
            {
                "google_workspace_user_id": workspace_account["id"],
                "gt_person_directory_id": directory_id,
            },
        )
        for email in workspace_account["emails"]:
            db().execute(
                (
                    "INSERT INTO crosswalk_email_address (email_address, gt_person_directory_id)"  # noqa
                    " VALUES (:email_address, :gt_person_directory_id)"
                    " ON CONFLICT DO UPDATE SET gt_person_directory_id = (:gt_person_directory_id) WHERE email_address = (:email_address)"  # noqa
                ),
                {
                    "email_address": email["address"],
                    "gt_person_directory_id": directory_id,
                },
            )

        if "recoveryEmail" in workspace_account and workspace_account["recoveryEmail"] is not None:
            db().execute(
                (
                    "INSERT INTO crosswalk_email_address (email_address, gt_person_directory_id)"  # noqa
                    " VALUES (:email_address, :gt_person_directory_id)"
                    " ON CONFLICT DO UPDATE SET gt_person_directory_id = (:gt_person_directory_id) WHERE email_address = (:email_address)"  # noqa
                ),
                {
                    "email_address": workspace_account["recoveryEmail"],
                    "gt_person_directory_id": directory_id,
                },
            )

        return workspace_account

    return {}


@app.get("/view/<directory_id>/grouper")
def get_grouper_memberships(directory_id: str) -> Dict[str, Any]:
    """
    Get Grouper group memberships for a given gtPersonDirectoryId
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
        gted_account = get_gted_primary_account(gtPersonDirectoryId=directory_id)

        if gted_account is None:
            raise NotFound("Provided directory ID was not found in Crosswalk or GTED")

        primary_username = gted_account["gtPrimaryGTAccountUsername"]

    grouper_response = get(
        url="https://grouper.gatech.edu/grouper-ws/servicesRest/v4_0_000/subjects/"
        + primary_username
        + "/memberships",
        auth=(app.config["GROUPER_USERNAME"], app.config["GROUPER_PASSWORD"]),
        headers={
            "User-Agent": USER_AGENT,
        },
        timeout=(5, 30),
    )
    grouper_response.raise_for_status()

    return grouper_response.json()["WsGetMembershipsResults"]  # type: ignore


def handle_event_callback(body: Dict[str, Any]) -> Dict[str, str]:
    """
    Handle an event callback from the Slack Events API
    """
    event = body.get("event", {})

    if event.get("type") != "message":
        return {"status": "ok"}

    if "subtype" in event:
        return {"status": "ok"}

    if "user" not in event or "channel" not in event:
        return {"status": "ok"}

    if "thread_ts" in event:
        return {"status": "ok"}

    mentioned_users = re.findall(r"<@(U[A-Z0-9]+)>", event.get("text", ""))

    lookup_user_id = mentioned_users[0] if len(mentioned_users) == 1 else event["user"]

    lookup_user_info = slack.users_info(user=lookup_user_id)

    lookup_email: Union[str, None] = None

    if lookup_user_info.get("ok") is True:
        lookup_profile: Any = lookup_user_info.get("user", {})
        lookup_email = lookup_profile.get("profile", {}).get("email")

    if lookup_email is None:
        return {"status": "ok"}

    lookup_results = search_by_email(Address(addr_spec=lookup_email))

    if len(lookup_results["results"]) == 0:
        return {"status": "ok"}

    blocks = format_search_result_blocks(lookup_results)

    ephemeral_users = app.config.get("SLACK_EPHEMERAL_USERS", "")
    if isinstance(ephemeral_users, str):
        user_ids = [uid.strip() for uid in ephemeral_users.split(",") if uid.strip()]
    else:
        user_ids = []

    plain_text = (
        lookup_results["results"][0]["givenName"] + " " + lookup_results["results"][0]["surname"]
    )

    if lookup_results["results"][0]["title"] is not None:
        plain_text += " - " + lookup_results["results"][0]["title"]

    if lookup_results["results"][0]["organizationalUnit"] is not None:
        if lookup_results["results"][0]["organizationalUnit"] in get_majors():
            plain_text += " - " + get_majors()[lookup_results["results"][0]["organizationalUnit"]]
        else:
            plain_text += " - " + lookup_results["results"][0]["organizationalUnit"]

    for user_id in user_ids:
        slack.chat_postEphemeral(
            channel=event["channel"],
            user=user_id,
            text=plain_text,
            blocks=blocks,
        )

    return {"status": "ok"}


@app.post("/slack")
def handle_slack_event() -> Dict[str, str]:
    """
    Handle an event from Slack
    """
    verifier = SignatureVerifier(app.config["SLACK_SIGNING_SECRET"])

    if not verifier.is_valid_request(request.get_data(), request.headers):  # type: ignore
        raise Unauthorized("Slack signature verification failed")

    if request.content_type is not None and "application/json" in request.content_type:
        body = request.get_json()
        if body is not None and body.get("type") == "url_verification":
            return {"challenge": body["challenge"]}

    if request.content_type is not None and "application/json" in request.content_type:
        body = request.get_json()
        if body is not None and body.get("type") == "event_callback":
            return handle_event_callback(body)

    payload = loads(request.form.get("payload"))  # type: ignore

    if payload.get("type") == "block_actions":
        return {"status": "ok"}

    if payload.get("type") != "message_action":
        raise BadRequest("Unsupported payload type")

    triggering_user_info = slack.users_info(user=payload["user"]["id"])

    triggering_user_email: Union[str, None] = None

    if triggering_user_info.get("ok") is True:
        triggering_user_profile: Any = triggering_user_info.get("user", {})
        triggering_user_email = triggering_user_profile.get("profile", {}).get("email")

    if triggering_user_email is None:
        slack.views_open(
            trigger_id=payload["trigger_id"],
            view={
                "type": "modal",
                "title": {"type": "plain_text", "text": "Checkpoint"},
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "Could not determine your email address from Slack.",
                        },
                    }
                ],
            },
        )
        return {"status": "ok"}

    triggering_user_results = search_by_email(
        Address(addr_spec=triggering_user_email), with_gted=False
    )

    if len(triggering_user_results["results"]) == 0:
        slack.views_open(
            trigger_id=payload["trigger_id"],
            view={
                "type": "modal",
                "title": {"type": "plain_text", "text": "Checkpoint"},
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "No Georgia Tech account found for your email address.",
                        },
                    }
                ],
            },
        )
        return {"status": "ok"}

    keycloak_account = get_keycloak_account(triggering_user_results["results"][0]["directoryId"], is_frontend_request=False)

    if keycloak_account is None or "id" not in keycloak_account or keycloak_account["id"] is None:
        slack.views_open(
            trigger_id=payload["trigger_id"],
            view={
                "type": "modal",
                "title": {"type": "plain_text", "text": "Checkpoint"},
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "Could not find your Keycloak account.",
                        },
                    }
                ],
            },
        )
        return {"status": "ok"}

    keycloak_user_id = keycloak_account["id"]

    role_mappings_response = keycloak.get(
        url=urlunparse(
            (
                urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
                urlparse(app.config["KEYCLOAK_METADATA_URL"]).hostname,
                "/admin/realms/"
                + app.config["KEYCLOAK_REALM"]
                + "/users/"
                + keycloak_user_id
                + "/role-mappings",
                "",
                "",
                "",
            )
        ),
        timeout=(5, 5),
    )
    role_mappings_response.raise_for_status()

    if (
        "clientMappings" in role_mappings_response.json()
        and role_mappings_response.json()["clientMappings"] is not None
    ):
        if (
            "checkpoint" in role_mappings_response.json()["clientMappings"]
            and role_mappings_response.json()["clientMappings"]["checkpoint"] is not None
        ):
            if (
                "mappings" in role_mappings_response.json()["clientMappings"]["checkpoint"]
                and role_mappings_response.json()["clientMappings"]["checkpoint"]["mappings"]
                is not None
            ):
                for mapping in role_mappings_response.json()["clientMappings"]["checkpoint"][
                    "mappings"
                ]:
                    if mapping.get("name") == "access":
                        has_access = True
                        break

    if not has_access:
        slack.views_open(
            trigger_id=payload["trigger_id"],
            view={
                "type": "modal",
                "title": {"type": "plain_text", "text": "Checkpoint"},
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "You do not have access to Checkpoint.",
                        },
                    }
                ],
            },
        )
        return {"status": "ok"}

    mentioned_users = re.findall(r"<@(U[A-Z0-9]+)>", payload["message"].get("text", ""))

    lookup_user_id = mentioned_users[0] if len(mentioned_users) == 1 else payload["message"]["user"]

    lookup_user_info = slack.users_info(user=lookup_user_id)

    lookup_email: Union[str, None] = None

    if lookup_user_info.get("ok") is True:
        lookup_profile: Any = lookup_user_info.get("user", {})
        lookup_email = lookup_profile.get("profile", {}).get("email")

    if lookup_email is None:
        slack.views_open(
            trigger_id=payload["trigger_id"],
            view={
                "type": "modal",
                "title": {"type": "plain_text", "text": "Checkpoint"},
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "Could not determine the user's email address.",
                        },
                    }
                ],
            },
        )
        return {"status": "ok"}

    lookup_results = search_by_email(Address(addr_spec=lookup_email))

    slack.views_open(
        trigger_id=payload["trigger_id"],
        view={
            "type": "modal",
            "title": {"type": "plain_text", "text": "Checkpoint"},
            "blocks": format_search_result_blocks(lookup_results),
        },
    )

    return {"status": "ok"}


@app.get("/ping")
def ping() -> Dict[str, str]:
    """
    Returns an arbitrary successful response, for health checks
    """
    return {"status": "ok"}
