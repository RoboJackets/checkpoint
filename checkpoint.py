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
from typing import Any, Dict, Final, List, Union
from urllib.parse import urlparse, urlunparse
from zoneinfo import ZoneInfo

from authlib.integrations.flask_client import OAuth
from authlib.integrations.requests_client import OAuth2Session

from celery import Celery, Task, shared_task

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

from requests import get, post

import sentry_sdk
from sentry_sdk import set_user
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.pure_eval import PureEvalIntegration

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from slack_sdk.models.blocks import ContextBlock, SectionBlock, TextObject
from slack_sdk.signature import SignatureVerifier

from square import Square

from werkzeug.exceptions import BadRequest, Forbidden, InternalServerError, NotFound, Unauthorized

logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
req_log = logging.getLogger("urllib3")
req_log.setLevel(logging.DEBUG)
req_log.propagate = True

GEORGIA_TECH_USERNAME_REGEX: Final[str] = r"[a-zA-Z]+[0-9]+"
EMAIL_ADDRESS_REGEX: Final[str] = r"[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}"
ACCESS_OVERRIDE_TIMESTAMP_REGEX: Final[str] = r"(?P<timestamp>\d{4}-\d{2}-\d{2})"
NUMBER_IN_QUOTES_REGEX: Final[str] = r"\"(?P<user_id>\d+)\""
PAYMENT_METHOD_REGEX: Final[str] = r"\"method\".+\"(?P<method>[a-z]+)\".+\"amount\""
CLIENT_NAME_REGEX: Final[str] = r"\"client_name\".+?\"(?P<client_name>.+?)\""

USER_AGENT: Final[str] = (
    "Checkpoint/"
    + environ.get("NOMAD_TASK_NAME", "local")
    + "/"
    + environ.get("NOMAD_SHORT_ALLOC_ID", "local")
)

# Square error code descriptions from API documentation, to show to technicians
SQUARE_ERROR_CODE_DESCRIPTIONS: Final[Dict[str, str]] = {
    "INTERNAL_SERVER_ERROR": "A general server error occurred.",
    "UNAUTHORIZED": "A general authorization error occurred.",
    "ACCESS_TOKEN_EXPIRED": "The provided access token has expired.",
    "ACCESS_TOKEN_REVOKED": "The provided access token has been revoked.",
    "CLIENT_DISABLED": "The provided client has been disabled.",
    "FORBIDDEN": "A general access error occurred.",
    "INSUFFICIENT_SCOPES": "The provided access token does not have permission to execute the requested action.",
    "APPLICATION_DISABLED": "The calling application was disabled.",
    "V1_APPLICATION": "The calling application was created prior to 2016-03-30 and is not compatible with v2 Square API calls.",
    "V1_ACCESS_TOKEN": "The calling application is using an access token created prior to 2016-03-30 and is not compatible with v2 Square API calls.",
    "CARD_PROCESSING_NOT_ENABLED": "The location provided in the API call is not enabled for credit card processing.",
    "MERCHANT_SUBSCRIPTION_NOT_FOUND": "A required subscription was not found for the merchant.",
    "BAD_REQUEST": "A general error occurred with the request.",
    "MISSING_REQUIRED_PARAMETER": "The request is missing a required path, query, or body parameter.",
    "INCORRECT_TYPE": "The value provided in the request is the wrong type. For example, a string instead of an integer.",
    "INVALID_TIME": "Formatting for the provided time value is incorrect.",
    "INVALID_TIME_RANGE": "The time range provided in the request is invalid. For example, the end time is before the start time.",
    "INVALID_VALUE": "The provided value is invalid. For example, including % in a phone number.",
    "INVALID_CURSOR": "The pagination cursor included in the request is invalid.",
    "UNKNOWN_QUERY_PARAMETER": "The query parameters provided are invalid for the requested endpoint.",
    "CONFLICTING_PARAMETERS": "One or more of the request parameters conflict with each other.",
    "EXPECTED_JSON_BODY": "The request body is not a JSON object.",
    "INVALID_SORT_ORDER": "The provided sort order is not a valid key. Currently, sort order must be ASC or DESC.",
    "VALUE_REGEX_MISMATCH": "The provided value does not match an expected regular expression.",
    "VALUE_TOO_SHORT": "The provided string value is shorter than the minimum length allowed.",
    "VALUE_TOO_LONG": "The provided string value is longer than the maximum length allowed.",
    "VALUE_TOO_LOW": "The provided value is less than the supported minimum.",
    "VALUE_TOO_HIGH": "The provided value is greater than the supported maximum.",
    "VALUE_EMPTY": "The provided value has a default (empty) value such as a blank string.",
    "ARRAY_LENGTH_TOO_LONG": "The provided array has too many elements.",
    "ARRAY_LENGTH_TOO_SHORT": "The provided array has too few elements.",
    "ARRAY_EMPTY": "The provided array is empty.",
    "EXPECTED_BOOLEAN": "The endpoint expected the provided value to be a boolean.",
    "EXPECTED_INTEGER": "The endpoint expected the provided value to be an integer.",
    "EXPECTED_FLOAT": "The endpoint expected the provided value to be a float.",
    "EXPECTED_STRING": "The endpoint expected the provided value to be a string.",
    "EXPECTED_OBJECT": "The endpoint expected the provided value to be a JSON object.",
    "EXPECTED_ARRAY": "The endpoint expected the provided value to be an array or list.",
    "EXPECTED_MAP": "The endpoint expected the provided value to be a map or associative array.",
    "EXPECTED_BASE64_ENCODED_BYTE_ARRAY": "The endpoint expected the provided value to be an array encoded in base64.",
    "INVALID_ARRAY_VALUE": "One or more objects in the array does not match the array type.",
    "INVALID_ENUM_VALUE": "The provided static string is not valid for the field.",
    "INVALID_CONTENT_TYPE": "Invalid content type header.",
    "INVALID_FORM_VALUE": "Only relevant for applications created prior to 2016-03-30. Indicates there was an error while parsing form values.",
    "CUSTOMER_NOT_FOUND": "The provided customer ID can't be found in the merchant's customers list.",
    "ONE_INSTRUMENT_EXPECTED": "A general error occurred.",
    "NO_FIELDS_SET": "A general error occurred.",
    "TOO_MANY_MAP_ENTRIES": "Too many entries in the map field.",
    "MAP_KEY_LENGTH_TOO_SHORT": "The length of one of the provided keys in the map is too short.",
    "MAP_KEY_LENGTH_TOO_LONG": "The length of one of the provided keys in the map is too long.",
    "CUSTOMER_MISSING_NAME": "The provided customer does not have a recorded name.",
    "CUSTOMER_MISSING_EMAIL": "The provided customer does not have a recorded email.",
    "INVALID_PAUSE_LENGTH": "The subscription cannot be paused longer than the duration of the current phase.",
    "INVALID_DATE": "The subscription cannot be paused/resumed on the given date.",
    "UNSUPPORTED_COUNTRY": "The API request references an unsupported country.",
    "UNSUPPORTED_CURRENCY": "The API request references an unsupported currency.",
    "APPLE_TTP_PIN_TOKEN": "The payment was declined by the card issuer during an Apple Tap to Pay (TTP) transaction with a request for the card's PIN. This code will be returned alongside CARD_DECLINED_VERIFICATION_REQUIRED as a supplemental error, and will include an issuer-provided token in the details field that is needed to initiate the PIN collection flow on the iOS device.",
    "CARD_EXPIRED": "The card issuer declined the request because the card is expired.",
    "INVALID_EXPIRATION": "The expiration date for the payment card is invalid. For example, it indicates a date in the past.",
    "INVALID_EXPIRATION_YEAR": "The expiration year for the payment card is invalid. For example, it indicates a year in the past or contains invalid characters.",
    "INVALID_EXPIRATION_DATE": "The expiration date for the payment card is invalid. For example, it contains invalid characters.",
    "UNSUPPORTED_CARD_BRAND": "The credit card provided is not from a supported issuer.",
    "UNSUPPORTED_ENTRY_METHOD": "The entry method for the credit card (swipe, dip, tap) is not supported.",
    "INVALID_ENCRYPTED_CARD": "The encrypted card information is invalid.",
    "INVALID_CARD": "The credit card cannot be validated based on the provided details.",
    "PAYMENT_AMOUNT_MISMATCH": "The payment was declined because there was a payment amount mismatch. The money amount Square was expecting does not match the amount provided.",
    "GENERIC_DECLINE": "Square received a decline without any additional information. If the payment information seems correct, the buyer can contact their issuer to ask for more information.",
    "CVV_FAILURE": "The card issuer declined the request because the CVV value is invalid.",
    "ADDRESS_VERIFICATION_FAILURE": "The card issuer declined the request because the postal code is invalid.",
    "INVALID_ACCOUNT": "The issuer was not able to locate the account on record.",
    "CURRENCY_MISMATCH": "The currency associated with the payment is not valid for the provided funding source. For example, a gift card funded in USD cannot be used to process payments in GBP.",
    "INSUFFICIENT_FUNDS": "The funding source has insufficient funds to cover the payment.",
    "INSUFFICIENT_PERMISSIONS": "The Square account does not have the permissions to accept this payment. For example, Square may limit which merchants are allowed to receive gift card payments.",
    "CARDHOLDER_INSUFFICIENT_PERMISSIONS": "The card issuer has declined the transaction due to restrictions on where the card can be used. For example, a gift card is limited to a single merchant.",
    "INVALID_LOCATION": "The Square account cannot take payments in the specified region. A Square account can take payments only from the region where the account was created.",
    "TRANSACTION_LIMIT": "The card issuer has determined the payment amount is either too high or too low. The API returns the error code mostly for credit cards (for example, the card reached the credit limit). However, sometimes the issuer bank can indicate the error for debit or prepaid cards (for example, card has insufficient funds).",
    "VOICE_FAILURE": "The card issuer declined the request because the issuer requires voice authorization from the cardholder. The seller should ask the customer to contact the card issuing bank to authorize the payment.",
    "PAN_FAILURE": "The specified card number is invalid. For example, it is of incorrect length or is incorrectly formatted.",
    "EXPIRATION_FAILURE": "The card expiration date is either invalid or indicates that the card is expired.",
    "CARD_NOT_SUPPORTED": "The card is not supported either in the geographic region or by the merchant category code (MCC).",
    "READER_DECLINED": "The Square Card Reader declined the payment for an unknown reason.",
    "INVALID_PIN": "The card issuer declined the request because the PIN is invalid.",
    "MISSING_PIN": "The payment is missing a required PIN.",
    "MISSING_ACCOUNT_TYPE": "The payment is missing a required ACCOUNT_TYPE parameter.",
    "INVALID_POSTAL_CODE": "The postal code is incorrectly formatted.",
    "INVALID_FEES": "The app_fee_money on a payment is too high.",
    "MANUALLY_ENTERED_PAYMENT_NOT_SUPPORTED": "The card must be swiped, tapped, or dipped. Payments attempted by manually entering the card number are declined.",
    "PAYMENT_LIMIT_EXCEEDED": "Square declined the request because the payment amount exceeded the processing limit for this merchant.",
    "GIFT_CARD_AVAILABLE_AMOUNT": "Provides the available balance on a Square gift card when a gift card payment fails due to insufficient funds. This error is returned with an INSUFFICIENT_FUNDS error and contains the balance in the smallest denomination of the applicable currency.",
    "ACCOUNT_UNUSABLE": "The account provided cannot carry out transactions.",
    "BUYER_REFUSED_PAYMENT": "Bank account rejected or was not authorized for the payment.",
    "DELAYED_TRANSACTION_EXPIRED": "The application tried to update a delayed-capture payment that has expired.",
    "DELAYED_TRANSACTION_CANCELED": "The application tried to cancel a delayed-capture payment that was already cancelled.",
    "DELAYED_TRANSACTION_CAPTURED": "The application tried to capture a delayed-capture payment that was already captured.",
    "DELAYED_TRANSACTION_FAILED": "The application tried to update a delayed-capture payment that failed.",
    "CARD_TOKEN_EXPIRED": "The provided card token (nonce) has expired.",
    "CARD_TOKEN_USED": "The provided card token (nonce) was already used to process the payment or refund.",
    "AMOUNT_TOO_HIGH": "The requested payment amount is too high for the provided payment source.",
    "UNSUPPORTED_INSTRUMENT_TYPE": "The API request references an unsupported instrument type.",
    "REFUND_AMOUNT_INVALID": "The requested refund amount exceeds the amount available to refund.",
    "REFUND_ALREADY_PENDING": "The payment already has a pending refund.",
    "PAYMENT_NOT_REFUNDABLE": "The payment is not refundable. For example, the payment is too old to be refunded.",
    "PAYMENT_NOT_REFUNDABLE_DUE_TO_DISPUTE": "The payment is not refundable because it has been disputed.",
    "REFUND_ERROR_PAYMENT_NEEDS_COMPLETION": "The payment is not refundable because the payment is approved and needs to be completed first before the refund is issued.",
    "REFUND_DECLINED": "Request failed - The card issuer declined the refund.",
    "INSUFFICIENT_PERMISSIONS_FOR_REFUND": "The Square account does not have the permissions to process this refund.",
    "INVALID_CARD_DATA": "Generic error - the provided card data is invalid.",
    "SOURCE_USED": "The provided source ID was already used to create a card.",
    "SOURCE_EXPIRED": "The provided source ID has expired.",
    "UNSUPPORTED_LOYALTY_REWARD_TIER": "The referenced loyalty program reward tier is not supported. This could happen if the reward tier created in a first party application is incompatible with the Loyalty API.",
    "LOCATION_MISMATCH": "Generic error - the given location does not match what is expected.",
    "ORDER_UNPAID_NOT_RETURNABLE": "The order attempting to be returned is not yet paid and cannot be returned.",
    "PARTIAL_PAYMENT_DELAY_CAPTURE_NOT_SUPPORTED": "Delay capture of a partial payment is not supported.",
    "IDEMPOTENCY_KEY_REUSED": "The provided idempotency key has already been used.",
    "UNEXPECTED_VALUE": "General error - the value provided was unexpected.",
    "SANDBOX_NOT_SUPPORTED": "The API request is not supported in sandbox.",
    "INVALID_EMAIL_ADDRESS": "The provided email address is invalid.",
    "INVALID_PHONE_NUMBER": "The provided phone number is invalid.",
    "CHECKOUT_EXPIRED": "The provided checkout URL has expired.",
    "BAD_CERTIFICATE": "Bad certificate.",
    "INVALID_SQUARE_VERSION_FORMAT": "The provided Square-Version is incorrectly formatted.",
    "API_VERSION_INCOMPATIBLE": "The provided Square-Version is incompatible with the requested action.",
    "CARD_PRESENCE_REQUIRED": "The transaction requires that a card be present.",
    "UNSUPPORTED_SOURCE_TYPE": "The API request references an unsupported source type.",
    "CARD_MISMATCH": "The provided card does not match what is expected.",
    "PLAID_ERROR": "Generic Plaid error.",
    "PLAID_ERROR_ITEM_LOGIN_REQUIRED": "Plaid error - ITEM_LOGIN_REQUIRED.",
    "PLAID_ERROR_RATE_LIMIT": "Plaid error - RATE_LIMIT.",
    "PAYMENT_SOURCE_NOT_ENABLED_FOR_TARGET": "The provided merchant or location is not enabled to accept the requested payment source.",
    "CARD_DECLINED": "The card was declined.",
    "VERIFY_CVV_FAILURE": "The CVV could not be verified.",
    "VERIFY_AVS_FAILURE": "The AVS could not be verified.",
    "CARD_DECLINED_CALL_ISSUER": "The payment card was declined with a request for the cardholder to call the issuer.",
    "CARD_DECLINED_VERIFICATION_REQUIRED": "The payment card was declined with a request for additional verification.",
    "BAD_EXPIRATION": "The card expiration date is either missing or incorrectly formatted.",
    "CHIP_INSERTION_REQUIRED": "The card issuer requires that the card be read using a chip reader.",
    "ALLOWABLE_PIN_TRIES_EXCEEDED": "The card has exhausted its available PIN entry retries set by the card issuer. Resolving the error typically requires the cardholder to contact the card issuer.",
    "RESERVATION_DECLINED": "The card issuer declined the refund.",
    "UNKNOWN_BODY_PARAMETER": "The body parameter is not recognized by the requested endpoint.",
    "NOT_FOUND": "Not Found - a general error occurred.",
    "APPLE_PAYMENT_PROCESSING_CERTIFICATE_HASH_NOT_FOUND": "Square could not find the associated Apple Pay certificate.",
    "METHOD_NOT_ALLOWED": "Method Not Allowed - a general error occurred.",
    "NOT_ACCEPTABLE": "Not Acceptable - a general error occurred.",
    "REQUEST_TIMEOUT": "Request Timeout - a general error occurred.",
    "CONFLICT": "Conflict - a general error occurred.",
    "GONE": "The target resource is no longer available and this condition is likely to be permanent.",
    "REQUEST_ENTITY_TOO_LARGE": "Request Entity Too Large - a general error occurred.",
    "UNSUPPORTED_MEDIA_TYPE": "Unsupported Media Type - a general error occurred.",
    "UNPROCESSABLE_ENTITY": "Unprocessable Entity - a general error occurred.",
    "RATE_LIMITED": "Rate Limited - a general error occurred.",
    "NOT_IMPLEMENTED": "Not Implemented - a general error occurred.",
    "BAD_GATEWAY": "Bad Gateway - a general error occurred.",
    "SERVICE_UNAVAILABLE": "Service Unavailable - a general error occurred.",
    "TEMPORARY_ERROR": "A temporary internal error occurred. You can safely retry your call using the same idempotency key.",
    "GATEWAY_TIMEOUT": "Gateway Timeout - a general error occurred.",
}

VERIFICATION_CUSTOMER_MESSAGE: Final[str] = (
    "Your card issuer requested additional verification for this payment. Contact your card issuer for help."
)

# Square error code messages to show to customers
SQUARE_ERROR_CODE_CUSTOMER_MESSAGES: Final[Dict[str, str]] = {
    "GENERIC_DECLINE": "This payment was declined by your card issuer. Unfortunately, we don't have more details on our side. Contact your card issuer for help.",
    "CARD_DECLINED_VERIFICATION_REQUIRED": VERIFICATION_CUSTOMER_MESSAGE,
    "TRANSACTION_LIMIT": "This payment was declined by your card issuer due to insufficient funds. Check your balance, or contact your card issuer for help.",
    "CVV_FAILURE": "The CVV you provided is incorrect. Make sure you typed it correctly.",
    "ADDRESS_VERIFICATION_FAILURE": "The ZIP code you provided doesn't match your card's billing address. Make sure you typed it correctly.",
    "PAN_FAILURE": "The card number you provided is incorrect. Make sure you typed it correctly.",
    "CARD_EXPIRED": "Your card is expired. Try again with a different card.",
    "VOICE_FAILURE": VERIFICATION_CUSTOMER_MESSAGE,
    "CARDHOLDER_INSUFFICIENT_PERMISSIONS": "This payment was declined by your card issuer due to restrictions on where this card can be used. Contact your card issuer for help.",
}


def traces_sampler(sampling_context: Dict[str, Dict[str, str]]) -> bool:
    """
    Ignore ping events, sample all other events
    """
    try:
        request_uri = sampling_context["wsgi_environ"]["REQUEST_URI"]
    except KeyError:
        return False

    return request_uri != "/ping"


def init_celery(flask: Flask) -> Celery:
    """
    Initialize Celery
    """

    class FlaskTask(Task):  # type: ignore  # pylint: disable=abstract-method
        """
        Extend default Task class to have Flask context available

        https://flask.palletsprojects.com/en/stable/patterns/celery/
        """

        def __call__(self, *args, **kwargs):  # type: ignore
            with flask.app_context():
                return self.run(*args, **kwargs)

    new_celery_app = Celery("checkpoint", task_cls=FlaskTask)
    new_celery_app.config_from_object(flask.config, namespace="CELERY")
    new_celery_app.set_default()
    flask.extensions["celery"] = new_celery_app
    return new_celery_app  # type: ignore


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

celery_app = init_celery(app)

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
            urlparse(app.config["KEYCLOAK_METADATA_URL"]).netloc,
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

slack = WebClient(token=app.config["SLACK_BOT_TOKEN"])


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
        url=app.config["GROUPER_BASE_URL"] + "/grouper-ws/servicesRest/v4_0_000/groups",
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
        if (
            account.get("gtPersonDirectoryId") is None
            or account.get("gtGTID") is None
            or account.get("gtPrimaryGTAccountUsername") is None
        ):
            continue

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

        if account.get("mail") is not None:
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
    whitepages_port = app.config.get("WHITEPAGES_PORT")

    with sentry_sdk.start_span(op="whitepages.connect"):
        whitepages = Connection(
            Server(
                app.config.get("WHITEPAGES_HOST", "whitepages.gatech.edu"),
                port=int(whitepages_port) if whitepages_port is not None else None,
                connect_timeout=1,
            ),
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


@cache.memoize()
def search_gtad(uid: str) -> Union[Dict[str, List[str]], None]:
    """
    Look up an account in GTAD by uid and return its title/department attributes
    """
    gtad_port = app.config.get("GTAD_PORT")

    with sentry_sdk.start_span(op="gtad.connect"):
        ldap = Connection(
            Server(
                app.config.get("GTAD_HOST", "campusad.ad.gatech.edu"),
                port=int(gtad_port) if gtad_port is not None else None,
                connect_timeout=1,
            ),
            user=app.config["GTAD_BIND_DN"],
            password=app.config["GTAD_BIND_PASSWORD"],
            auto_bind=True,
            raise_exceptions=True,
            receive_timeout=1,
        )

    with sentry_sdk.start_span(op="gtad.search"):
        result = ldap.search(
            search_base="dc=ad,dc=gatech,dc=edu",
            search_filter="(uid=" + uid + ")",
            attributes=["title", "department"],
        )

        if result is True:
            for entry in ldap.entries:
                attributes: Dict[str, List[str]] = loads(entry.entry_to_json()).get(
                    "attributes", {}
                )
                return attributes

    return None


@cache.cached(key_prefix="realms")
def get_realms() -> List[Dict[str, Any]]:
    """
    Get realm information from Keycloak
    """
    keycloak_response = keycloak.get(
        url=urlunparse(
            (
                urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
                urlparse(app.config["KEYCLOAK_METADATA_URL"]).netloc,
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
                            urlparse(app.config["KEYCLOAK_METADATA_URL"]).netloc,
                            "/admin/realms/" + realm["realm"] + "/users/" + kwargs["userId"],
                            "",
                            "",
                            "",
                        )
                    ),
                    timeout=(5, 5),
                )
                keycloak_response.raise_for_status()

                keycloak_account = keycloak_response.json()

                if (
                    fullmatch(
                        GEORGIA_TECH_USERNAME_REGEX,
                        keycloak_account["username"],
                        IGNORECASE,
                    )
                    is not None
                ):
                    return get_actor(uid=keycloak_account["username"])  # type: ignore

                actor_display_name = keycloak_account["username"]

                if actor_display_name.startswith("service-account-"):
                    actor_display_name = actor_display_name[len("service-account-") :]  # noqa

                return {
                    "actorDisplayName": actor_display_name,
                    "actorLink": urlunparse(
                        (
                            urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
                            urlparse(app.config["KEYCLOAK_METADATA_URL"]).netloc,
                            "/admin/master/console/",
                            "",
                            "",
                            "/" + realm["realm"] + "/users/" + keycloak_account["id"] + "/settings",
                        )
                    ),
                }

    if "apiary_user_id" in kwargs:
        user = search_apiary(apiary_user_id=kwargs["apiary_user_id"])

        if user is not None and user.get("full_name") is not None:
            return {
                "actorDisplayName": user["full_name"],
            }

    if "email" in kwargs:
        email_results = search_by_email(
            Address(addr_spec=kwargs["email"]), with_gted=False, with_title_and_organization=False
        )

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


def get_client_display_name(**kwargs: str) -> str:
    """
    Get the display name for a client from a Keycloak event
    """
    if "realmId" in kwargs and "clientId" in kwargs:
        for realm in get_realms():
            if kwargs["realmId"] == realm["id"]:
                keycloak_response = keycloak.get(
                    url=urlunparse(
                        (
                            urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
                            urlparse(app.config["KEYCLOAK_METADATA_URL"]).netloc,
                            "/admin/realms/" + realm["realm"] + "/clients/" + kwargs["clientId"],
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
                urlparse(app.config["KEYCLOAK_METADATA_URL"]).netloc,
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


@cache.memoize(
    response_filter=lambda result: result is not None,
    args_to_ignore=["force_refresh"],
    forced_update=lambda *args, force_refresh=False, **kwargs: force_refresh,
)
def search_apiary(  # pylint: disable=too-many-arguments
    *,
    directory_id: Union[str, None] = None,
    gtid: Union[str, int, None] = None,
    uid: Union[str, None] = None,
    apiary_user_id: Union[str, int, None] = None,
    email: Union[str, None] = None,
    include: Union[List[str], None] = None,
    force_refresh: bool = False,
) -> Union[Dict[str, Any], None]:
    """
    Look up a single user in Apiary by one of the supported identifiers and update Crosswalk
    with the returned identifiers (gtPersonDirectoryId, gtid, primary_username, email addresses).

    Exactly one of directory_id, gtid, uid, apiary_user_id, email must be provided. On 404 for
    a directory_id or uid lookup, automatically retry with a gtid resolved from Crosswalk
    (falling back to GTED) if available.
    """
    provided = {
        "directory_id": directory_id,
        "gtid": gtid,
        "uid": uid,
        "apiary_user_id": apiary_user_id,
        "email": email,
    }
    supplied = [name for name, value in provided.items() if value is not None]

    if len(supplied) != 1:
        raise InternalServerError("search_apiary: must supply exactly one identifier")

    params = {"include": ",".join(include)} if include else {}

    if email is not None:
        apiary_response = apiary.post(
            url=app.config["APIARY_BASE_URL"] + "/api/v1/users/searchByEmail",
            json={"email": email},
            params=params,
            timeout=(5, 5),
        )
    else:
        key = directory_id or gtid or uid or apiary_user_id
        apiary_response = apiary.get(
            url=app.config["APIARY_BASE_URL"] + "/api/v1/users/" + str(key),
            params=params,
            timeout=(5, 5),
        )

    if apiary_response.status_code == 404:
        fallback_gtid: Union[str, int, None] = None

        if directory_id is not None:
            cursor = db().execute(
                "SELECT gtid FROM crosswalk WHERE gt_person_directory_id = (:directory_id)",
                {"directory_id": directory_id},
            )
            row = cursor.fetchone()

            if row is not None:
                fallback_gtid = row[0]
            else:
                gted_account = get_gted_primary_account(gtPersonDirectoryId=directory_id)
                if gted_account is not None:
                    fallback_gtid = gted_account["gtGTID"]
        elif uid is not None:
            cursor = db().execute(
                "SELECT gtid FROM crosswalk WHERE primary_username = (:uid)",
                {"uid": uid},
            )
            row = cursor.fetchone()

            if row is not None:
                fallback_gtid = row[0]
            else:
                gted_account = get_gted_primary_account(uid=uid)
                if gted_account is not None:
                    fallback_gtid = gted_account["gtGTID"]

        if fallback_gtid is None:
            return None

        return search_apiary(  # type: ignore[no-any-return]
            gtid=fallback_gtid, include=include, force_refresh=force_refresh
        )

    apiary_response.raise_for_status()

    user = apiary_response.json().get("user")

    if user is None:
        return None

    update_crosswalk_from_apiary_user(user)

    return user  # type: ignore[no-any-return]


def update_crosswalk_from_apiary_user(user: Dict[str, Any]) -> None:
    """
    Upsert the identifiers and email addresses from an Apiary user object into Crosswalk.
    """
    if (
        user.get("gtPersonDirectoryId") is None
        or user.get("gtid") is None
        or user.get("uid") is None
    ):
        return

    db().execute(
        (
            "INSERT INTO crosswalk (gt_person_directory_id, gtid, primary_username)"
            " VALUES (:gt_person_directory_id, :gtid, :primary_username)"
            " ON CONFLICT DO NOTHING"
        ),
        {
            "gt_person_directory_id": user["gtPersonDirectoryId"],
            "gtid": user["gtid"],
            "primary_username": user["uid"],
        },
    )

    if user.get("id") is not None:
        db().execute(
            (
                "UPDATE crosswalk SET apiary_user_id = (:apiary_user_id)"
                " WHERE gt_person_directory_id = (:gt_person_directory_id)"
            ),
            {
                "apiary_user_id": user["id"],
                "gt_person_directory_id": user["gtPersonDirectoryId"],
            },
        )

    for email_address in (
        user.get("gt_email"),
        user.get("gmail_address"),
        user.get("clickup_email"),
    ):
        if email_address is None:
            continue

        db().execute(
            (
                "INSERT INTO crosswalk_email_address (email_address, gt_person_directory_id)"  # noqa
                " VALUES (:email_address, :gt_person_directory_id)"
                " ON CONFLICT DO UPDATE SET gt_person_directory_id = (:gt_person_directory_id) WHERE email_address = (:email_address)"  # noqa
            ),
            {
                "email_address": email_address,
                "gt_person_directory_id": user["gtPersonDirectoryId"],
            },
        )


def fuzzy_search_apiary(query: str) -> List[Dict[str, Any]]:
    """
    Run a fuzzy user search against Apiary and update Crosswalk for each returned user.
    """
    apiary_response = apiary.post(
        url=app.config["APIARY_BASE_URL"] + "/api/v1/users/fuzzySearch",
        json={"query": query},
        timeout=(5, 5),
    )
    apiary_response.raise_for_status()

    users: List[Dict[str, Any]] = apiary_response.json().get("users", [])

    for user in users:
        update_crosswalk_from_apiary_user(user)

    return users


def update_crosswalk_from_keycloak_user(account: Dict[str, Any]) -> None:
    """
    Upsert the Keycloak identifiers and email addresses from a Keycloak user object
    into Crosswalk, anchored on the row whose primary_username matches the Keycloak
    username.
    """
    if account.get("username") is None:
        return

    cursor = db().execute(
        "SELECT gt_person_directory_id FROM crosswalk WHERE primary_username = (:username)",
        {"username": account["username"]},
    )
    row = cursor.fetchone()

    if row is None:
        return

    if account.get("id") is not None:
        db().execute(
            (
                "UPDATE crosswalk SET keycloak_user_id = (:keycloak_user_id)"
                " WHERE gt_person_directory_id = (:gt_person_directory_id)"
            ),
            {
                "keycloak_user_id": account["id"],
                "gt_person_directory_id": row[0],
            },
        )

    for email_address in (
        account.get("email"),
        get_attribute_value("googleWorkspaceAccount", account),
        get_attribute_value("rampLoginEmailAddress", account),
    ):
        if email_address is None:
            continue

        db().execute(
            (
                "INSERT INTO crosswalk_email_address (email_address, gt_person_directory_id)"  # noqa
                " VALUES (:email_address, :gt_person_directory_id)"
                " ON CONFLICT DO UPDATE SET gt_person_directory_id = (:gt_person_directory_id) WHERE email_address = (:email_address)"  # noqa
            ),
            {
                "email_address": email_address,
                "gt_person_directory_id": row[0],
            },
        )


def update_crosswalk_slack_user_id(slack_user_id: str, gt_person_directory_id: str) -> None:
    """
    Persist the mapping from a Slack user ID to a known gtPersonDirectoryId.
    """
    db().execute(
        (
            "UPDATE crosswalk SET slack_user_id = (:slack_user_id)"
            " WHERE gt_person_directory_id = (:gt_person_directory_id)"
        ),
        {
            "slack_user_id": slack_user_id,
            "gt_person_directory_id": gt_person_directory_id,
        },
    )


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
    gted_account: Dict[str, Any],
    whitepages_entries: List[Dict[str, Dict[str, List[str]]]],
    gtad_account: Union[Dict[str, List[str]], None] = None,
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
                and "temp" not in entry["attributes"]["title"][0].lower()
                and "work study" not in entry["attributes"]["title"][0].lower()
                and "UNKNOWN" != entry["attributes"]["title"][0]
            ):
                if title is not None:
                    raise InternalServerError(
                        "Selected multiple Whitepages entries to display in results for "
                        + gted_account["gtPrimaryGTAccountUsername"]
                    )

                title = entry["attributes"]["title"][0]

                organizational_unit = get_attribute_value("ou", entry)

    title_is_authoritative = title is not None

    if title is None and gtad_account is not None:
        gtad_title = gtad_account.get("title")
        if gtad_title is not None and len(gtad_title) > 0:
            title = gtad_title[0]

    if organizational_unit is None and gtad_account is not None:
        gtad_department = gtad_account.get("department")
        if gtad_department is not None and len(gtad_department) > 0:
            organizational_unit = gtad_department[0]

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
        "titleIsAuthoritative": title_is_authoritative,
        "organizationalUnit": organizational_unit,
    }


def build_search_result_context(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Gather viewer-independent data needed to render Slack search result blocks
    """
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

    apiary_user_id = None

    cursor = db().execute(
        "SELECT apiary_user_id FROM crosswalk WHERE gt_person_directory_id = (:directory_id)",
        {"directory_id": result["directoryId"]},
    )
    row = cursor.fetchone()

    if row is not None and row[0] is not None:
        apiary_user_id = row[0]
    else:
        apiary_account = search_apiary(directory_id=result["directoryId"])
        if apiary_account is not None and apiary_account.get("id") is not None:
            apiary_user_id = apiary_account["id"]

    keycloak_user_id = None

    keycloak_account = get_keycloak_account(result["directoryId"], is_frontend_request=False)

    if (
        keycloak_account is not None
        and "id" in keycloak_account
        and keycloak_account["id"] is not None
    ):
        keycloak_user_id = keycloak_account["id"]

    google_workspace_primary_email = None

    google_workspace_account = get_google_workspace_account(
        result["directoryId"], is_frontend_request=False
    )

    if (
        google_workspace_account is not None
        and "primaryEmail" in google_workspace_account
        and google_workspace_account["primaryEmail"] is not None
    ):
        google_workspace_primary_email = google_workspace_account["primaryEmail"]

    return {
        "givenName": result["givenName"],
        "surname": result["surname"],
        "directoryId": result["directoryId"],
        "title": result.get("title"),
        "organizationalUnit": result.get("organizationalUnit"),
        "primaryUsername": primary_username,
        "apiaryUserId": apiary_user_id,
        "keycloakUserId": keycloak_user_id,
        "googleWorkspacePrimaryEmail": google_workspace_primary_email,
    }


def format_search_result_blocks(
    result_context: Dict[str, Any],
    viewer_slack_user_id: str,
) -> List[Dict[str, Any]]:
    """
    Convert a search result context to Slack Block Kit blocks for a modal
    """
    lines = [f"*{result_context['givenName']} {result_context['surname']}*"]

    detail_parts = []
    if result_context.get("title"):
        detail_parts.append(result_context["title"])

    if result_context.get("organizationalUnit"):
        if result_context["organizationalUnit"] in get_majors():
            detail_parts.append(get_majors()[result_context["organizationalUnit"]])
        else:
            detail_parts.append(result_context["organizationalUnit"])

    if detail_parts:
        lines.append(" | ".join(detail_parts))

    apiary_button = []
    if result_context["apiaryUserId"] is not None:
        apiary_button = [
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "View in Apiary"},
                "url": app.config["APIARY_BASE_URL"]
                + "/nova/resources/users/"
                + str(result_context["apiaryUserId"]),
            }
        ]

    keycloak_button = []
    if result_context["keycloakUserId"] is not None and slack_user_has_keycloak_admin_access(
        viewer_slack_user_id
    ):
        keycloak_button = [
            {
                "text": {"type": "plain_text", "text": "View in Keycloak"},
                "url": urlunparse(
                    (
                        urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
                        urlparse(app.config["KEYCLOAK_METADATA_URL"]).netloc,
                        "/admin/master/console/",
                        "",
                        "",
                        "/"
                        + app.config["KEYCLOAK_REALM"]
                        + "/users/"
                        + result_context["keycloakUserId"]
                        + "/settings",
                    )
                ),
            }
        ]

    google_workspace_button = []
    if result_context[
        "googleWorkspacePrimaryEmail"
    ] is not None and slack_user_has_google_workspace_admin_access(viewer_slack_user_id):
        google_workspace_button = [
            {
                "text": {"type": "plain_text", "text": "View in Google Workspace"},
                "url": "https://www.google.com/a/robojackets.org/ServiceLogin?continue=https://admin.google.com/ac/search?query="  # noqa
                + result_context["googleWorkspacePrimaryEmail"],
            }
        ]

    iat_option = []
    if slack_user_has_iat_access(viewer_slack_user_id):
        iat_option = [
            {
                "text": {"type": "plain_text", "text": "View in IAT"},
                "url": "https://iat.gatech.edu/prod/person/" + result_context["directoryId"],
            }
        ]

    grouper_option = []
    if slack_user_has_privilege_separated_account(viewer_slack_user_id):
        grouper_option = [
            {
                "text": {"type": "plain_text", "text": "View in Grouper"},
                "url": app.config["GROUPER_BASE_URL"]
                + "/grouper/grouperUi/app/UiV2Main.index?operation=UiV2Subject.viewSubject&subjectId="  # noqa
                + result_context["primaryUsername"]
                + "&sourceId=gted-accounts",
            }
        ]

    overflow_options = [
        *iat_option,
        *grouper_option,
        *keycloak_button,
        *google_workspace_button,
    ]

    overflow_menu = []
    if len(overflow_options) > 0:
        overflow_menu = [
            {
                "type": "overflow",
                "action_id": "overflow_menu",
                "options": overflow_options,
            }
        ]

    return [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "\n".join(lines),
            },
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View in Checkpoint"},
                    "url": "https://checkpoint.bcdc.robojackets.net/view/"
                    + result_context["directoryId"],
                    "action_id": "view_in_checkpoint",
                },
                *apiary_button,
                *overflow_menu,
            ],
        },
    ]


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


@app.cli.command("migrate")
def migrate() -> None:
    """
    Create the database schema if it does not already exist
    """
    connection = connect(app.config["DATABASE_LOCATION"])
    try:
        connection.execute("PRAGMA foreign_keys = 1")
        connection.executescript(
            """
CREATE TABLE IF NOT EXISTS crosswalk (
    gt_person_directory_id TEXT NOT NULL PRIMARY KEY COLLATE NOCASE,
    gtid INTEGER NOT NULL UNIQUE,
    primary_username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    keycloak_user_id TEXT UNIQUE COLLATE NOCASE,
    google_workspace_user_id TEXT UNIQUE COLLATE NOCASE,
    apiary_user_id INTEGER UNIQUE,
    slack_user_id TEXT UNIQUE COLLATE NOCASE
) strict;

CREATE TABLE IF NOT EXISTS crosswalk_email_address (
    email_address TEXT NOT NULL PRIMARY KEY COLLATE NOCASE,
    gt_person_directory_id TEXT NOT NULL COLLATE NOCASE,
    FOREIGN KEY(gt_person_directory_id) REFERENCES crosswalk(gt_person_directory_id)
) strict;
"""
        )
    finally:
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
                        urlparse(app.config["KEYCLOAK_METADATA_URL"]).netloc,
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
                    urlparse(app.config["KEYCLOAK_METADATA_URL"]).netloc,
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


@cache.memoize(args_to_ignore=["with_title_and_organization"])
def search_by_username(username: str, with_title_and_organization: bool = True) -> Dict[str, Any]:
    """
    Search for a person by username
    """
    user = search_apiary(uid=username)

    if user is not None:
        return {
            "results": [
                format_search_result(
                    {
                        "givenName": user["first_name"],
                        "sn": user["last_name"],
                        "gtPersonDirectoryId": user["gtPersonDirectoryId"],
                        "eduPersonPrimaryAffiliation": None,
                        "eduPersonScopedAffiliation": [],
                    },
                    search_whitepages(uid=username) if with_title_and_organization else [],
                    search_gtad(uid=username) if with_title_and_organization else None,
                ),
            ],
            "exactMatch": True,
        }

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
                (
                    search_whitepages(uid=gted_account["gtPrimaryGTAccountUsername"])
                    if with_title_and_organization
                    else []
                ),
                (
                    search_gtad(uid=gted_account["gtPrimaryGTAccountUsername"])
                    if with_title_and_organization
                    else None
                ),
            ),
        ],
        "exactMatch": True,
    }


def only_cache_if_result_present(result: Dict[str, Any]) -> bool:
    """
    Only cache if the result is present
    """
    return len(result["results"]) > 0


@cache.memoize(
    args_to_ignore=["with_title_and_organization", "with_gted"],
    response_filter=only_cache_if_result_present,
)
def search_by_email(
    email_address: Address, with_gted: bool = True, with_title_and_organization: bool = True
) -> Any:
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
        user = search_apiary(directory_id=row[0])

        if user is not None:
            return {
                "results": [
                    format_search_result(
                        {
                            "givenName": user["first_name"],
                            "sn": user["last_name"],
                            "gtPersonDirectoryId": user["gtPersonDirectoryId"],
                            "eduPersonPrimaryAffiliation": None,
                            "eduPersonScopedAffiliation": [],
                        },
                        (search_whitepages(uid=user["uid"]) if with_title_and_organization else []),
                        (search_gtad(uid=user["uid"]) if with_title_and_organization else None),
                    ),
                ],
                "exactMatch": True,
            }

        gted_account = get_gted_primary_account(gtPersonDirectoryId=row[0])

        if gted_account is None:
            raise InternalServerError("gtPersonDirectoryId from Crosswalk was not found in GTED")

        return {
            "results": [
                format_search_result(
                    gted_account,
                    (
                        search_whitepages(uid=gted_account["gtPrimaryGTAccountUsername"])
                        if with_title_and_organization
                        else []
                    ),
                    (
                        search_gtad(uid=gted_account["gtPrimaryGTAccountUsername"])
                        if with_title_and_organization
                        else None
                    ),
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
            username_results = search_by_username(
                email_address.username, with_title_and_organization=with_title_and_organization
            )

            if len(username_results["results"]) > 0:
                return username_results

    apiary_user = search_apiary(email=email_address.addr_spec)

    if apiary_user is not None and apiary_user.get("uid") is not None:
        return search_by_username(
            apiary_user["uid"],
            with_title_and_organization=with_title_and_organization,
        )

    keycloak_results = search_keycloak(email=email_address.addr_spec, exact=True)

    if len(keycloak_results) > 0:
        return search_by_username(
            keycloak_results[0]["username"], with_title_and_organization=with_title_and_organization
        )

    keycloak_results = search_keycloak(
        q=build_keycloak_filter(googleWorkspaceAccount=email_address.addr_spec)
    )

    if len(keycloak_results) > 0:
        return search_by_username(
            keycloak_results[0]["username"], with_title_and_organization=with_title_and_organization
        )

    keycloak_results = search_keycloak(
        q=build_keycloak_filter(rampLoginEmailAddress=email_address.addr_spec)
    )

    if len(keycloak_results) > 0:
        return search_by_username(
            keycloak_results[0]["username"], with_title_and_organization=with_title_and_organization
        )

    if with_gted:
        gted_account = get_gted_primary_account(
            filter=build_ldap_filter(mail=email_address.addr_spec)
        )

        if gted_account is not None:
            return {
                "results": [
                    format_search_result(
                        gted_account,
                        (
                            search_whitepages(uid=gted_account["gtPrimaryGTAccountUsername"])
                            if with_title_and_organization
                            else []
                        ),
                        (
                            search_gtad(uid=gted_account["gtPrimaryGTAccountUsername"])
                            if with_title_and_organization
                            else None
                        ),
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
                        (
                            search_whitepages(uid=gted_account["gtPrimaryGTAccountUsername"])
                            if with_title_and_organization
                            else []
                        ),
                        (
                            search_gtad(uid=gted_account["gtPrimaryGTAccountUsername"])
                            if with_title_and_organization
                            else None
                        ),
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
        return search_by_email(Address(addr_spec=query), with_title_and_organization=False)
    except InvalidHeaderDefect:
        # check if the query is formatted like a GT username
        if fullmatch(GEORGIA_TECH_USERNAME_REGEX, query, IGNORECASE) is not None:
            return search_by_username(query, with_title_and_organization=False)

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

                formatted_results.append(
                    format_search_result(gted_account, entries, search_gtad(uid=uid))
                )

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
                    search_gtad(uid=account["username"]),
                )
            )

        if len(formatted_results) > 0:
            return {
                "results": formatted_results,
                "exactMatch": False,
            }

        for account in fuzzy_search_apiary(query):
            formatted_results.append(
                format_search_result(
                    get_gted_primary_account(uid=account["uid"]),  # type: ignore
                    search_whitepages(uid=account["uid"]),
                    search_gtad(uid=account["uid"]),
                )
            )

        return {
            "results": formatted_results,
            "exactMatch": False,
        }


@app.get("/view/<directory_id>/whitepages")
def get_whitepages_records(directory_id: str, is_frontend_request: bool = True) -> Any:
    """
    Get Whitepages entries for a provided gtPersonDirectoryId
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

    gtad_port = app.config.get("GTAD_PORT")

    ldap = Connection(
        Server(
            app.config.get("GTAD_HOST", "campusad.ad.gatech.edu"),
            port=int(gtad_port) if gtad_port is not None else None,
            connect_timeout=1,
        ),
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
                    urlparse(app.config["KEYCLOAK_METADATA_URL"]).netloc,
                    "/admin/realms/" + app.config["KEYCLOAK_REALM"] + "/users/" + row[0],
                    "",
                    "",
                    "",
                )
            ),
            timeout=(5, 5),
        )
        keycloak_response.raise_for_status()

        keycloak_account = keycloak_response.json()
        update_crosswalk_from_keycloak_user(keycloak_account)

        return keycloak_account  # type: ignore

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

    user = search_apiary(
        directory_id=directory_id,
        include=[
            "actions",
            "attendance.recorded",
            "attendance.attendable",
            "teams",
            "roles",
            "dues.payment",
        ],
        force_refresh=True,
    )

    return user or {}


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
                    urlparse(app.config["KEYCLOAK_METADATA_URL"]).netloc,
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

            if event["type"] == "LOGIN":
                description = "logged into " + client_id
            elif event["type"] == "CODE_TO_TOKEN":
                description = "logged into " + client_id
            elif event["type"] == "REGISTER":
                description = "logged into " + client_id
            elif event["type"] == "LOGOUT":
                description = "logged out of " + client_id
            elif event["type"] == "LOGIN_ERROR":
                description = "failed to log into " + client_id
            elif event["type"] == "LOGOUT_ERROR":
                description = "failed to log out of " + client_id
            else:
                print(dumps(event))
                raise InternalServerError("Unrecognized type in Keycloak event: " + event["type"])

            events.append(
                {
                    "eventTimestamp": event["time"],
                    "eventDescription": description,
                    "eventLink": urlunparse(
                        (
                            urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
                            urlparse(app.config["KEYCLOAK_METADATA_URL"]).netloc,
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
                    urlparse(app.config["KEYCLOAK_METADATA_URL"]).netloc,
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
                    + get_client_display_name(**event["authDetails"])
                )
            elif (
                event["operationType"] == "CREATE"
                and "resourceType" in event
                and event["resourceType"] == "CLIENT_ROLE_MAPPING"
            ):
                description = (
                    "attached "
                    + get_client_display_name(
                        realmId=event["realmId"], clientId=event["resourcePath"].split("/")[-1]
                    )
                    + " "
                    + loads(event["representation"])[0]["name"]
                    + " role to "
                    + get_actor(gtPersonDirectoryId=directory_id)["actorDisplayName"]
                    + "'s Keycloak account using "
                    + get_client_display_name(**event["authDetails"])
                )
            elif (
                event["operationType"] == "DELETE"
                and "resourceType" in event
                and event["resourceType"] == "CLIENT_ROLE_MAPPING"
            ):
                description = (
                    "detached "
                    + get_client_display_name(
                        realmId=event["realmId"], clientId=event["resourcePath"].split("/")[-1]
                    )
                    + " "
                    + loads(event["representation"])[0]["name"]
                    + " role from "
                    + get_actor(gtPersonDirectoryId=directory_id)["actorDisplayName"]
                    + "'s Keycloak account using "
                    + get_client_display_name(**event["authDetails"])
                )
            else:
                print(dumps(event))
                raise InternalServerError(
                    "Unrecognized operationType in Keycloak event: " + event["operationType"]
                )

            events.append(
                {
                    "eventTimestamp": event["time"],
                    "eventDescription": description,
                    "eventLink": urlunparse(
                        (
                            urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
                            urlparse(app.config["KEYCLOAK_METADATA_URL"]).netloc,
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

    apiary_user = (
        search_apiary(
            directory_id=directory_id,
            include=["actions", "attendance.recorded", "attendance.attendable"],
        )
        or {}
    )

    if apiary_user.get("attendance") is not None:
        for attendance in apiary_user["attendance"]:
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

    if apiary_user.get("actions") is not None:
        for action in apiary_user["actions"]:
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
                        and item["events"][0]["name"] == "REMOVE_GROUP_MEMBER"
                    ):
                        event_description = (
                            "removed "
                            + get_parameter_value("USER_EMAIL", item["events"][0]["parameters"])
                            + " from group "
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

                    elif (
                        "name" in item["events"][0]
                        and item["events"][0]["name"] == "CHANGE_USER_ORGANIZATION"
                    ):
                        user_email = get_parameter_value(
                            "USER_EMAIL", item["events"][0]["parameters"]
                        )
                        new_value = get_parameter_value(
                            "NEW_VALUE", item["events"][0]["parameters"]
                        ).strip('" :')

                        user_display_name = get_actor(
                            email=user_email, customer_id=item["id"]["customerId"]
                        )["actorDisplayName"]

                        event_description = (
                            "updated "
                            + str(user_display_name)
                            + "'s title and department to "
                            + str(new_value)
                            + " in Google Workspace"
                        )

                    elif (
                        "name" in item["events"][0]
                        and item["events"][0]["name"] == "CHANGE_USER_PHONE_NUMBER"
                    ):
                        user_email = get_parameter_value(
                            "USER_EMAIL", item["events"][0]["parameters"]
                        )
                        new_value = get_parameter_value(
                            "NEW_VALUE", item["events"][0]["parameters"]
                        ).strip('"')

                        user_display_name = get_actor(
                            email=user_email, customer_id=item["id"]["customerId"]
                        )["actorDisplayName"]

                        event_description = (
                            "updated "
                            + str(user_display_name)
                            + "'s phone number to "
                            + str(new_value)
                            + " in Google Workspace"
                        )

                    elif (
                        "name" in item["events"][0]
                        and item["events"][0]["name"] == "CHANGE_USER_RELATION"
                    ):
                        user_email = get_parameter_value(
                            "USER_EMAIL", item["events"][0]["parameters"]
                        )
                        old_value = get_parameter_value(
                            "OLD_VALUE", item["events"][0]["parameters"]
                        ).strip('"')
                        new_value = get_parameter_value(
                            "NEW_VALUE", item["events"][0]["parameters"]
                        ).strip('"')

                        user_display_name = get_actor(
                            email=user_email, customer_id=item["id"]["customerId"]
                        )["actorDisplayName"]

                        if new_value:
                            new_relation_type, _, new_relation_email = new_value.partition(":")
                            new_relation_display_name = get_actor(
                                email=new_relation_email, customer_id=item["id"]["customerId"]
                            )["actorDisplayName"]
                            event_description = (
                                "updated "
                                + str(user_display_name)
                                + "'s "
                                + new_relation_type.lower()
                                + " to "
                                + str(new_relation_display_name)
                                + " in Google Workspace"
                            )
                        else:
                            old_relation_type, _, old_relation_email = old_value.partition(":")
                            old_relation_display_name = get_actor(
                                email=old_relation_email, customer_id=item["id"]["customerId"]
                            )["actorDisplayName"]
                            event_description = (
                                "removed "
                                + str(user_display_name)
                                + "'s "
                                + old_relation_type.lower()
                                + " (was "
                                + str(old_relation_display_name)
                                + ") in Google Workspace"
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

                    elif (
                        "name" in item["events"][0]
                        and item["events"][0]["name"] == "risky_sensitive_action_allowed"
                    ):
                        event_description = "allowed an app access to Google Workspace data"

                    elif (
                        "name" in item["events"][0]
                        and item["events"][0]["name"] == "email_forwarding_out_of_domain"
                    ):
                        event_description = (
                            "configured email forwarding from "
                            + item["actor"]["email"]
                            + " to "
                            + get_parameter_value(
                                "email_forwarding_destination_address",
                                item["events"][0]["parameters"],
                            )
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


def get_email_addresses(directory_id: str, is_frontend_request: bool = True) -> set[str]:
    """
    Collect all known email addresses for a given gtPersonDirectoryId from Apiary, Keycloak,
    and Whitepages
    """
    email_addresses = set[str]()

    apiary_account = get_apiary_account(directory_id, is_frontend_request=is_frontend_request)

    if "gmail_address" in apiary_account and apiary_account["gmail_address"] is not None:
        email_addresses.add(apiary_account["gmail_address"])
    if "clickup_email" in apiary_account and apiary_account["clickup_email"] is not None:
        email_addresses.add(apiary_account["clickup_email"])
    if "gt_email" in apiary_account and apiary_account["gt_email"] is not None:
        email_addresses.add(apiary_account["gt_email"])

    keycloak_account = get_keycloak_account(directory_id, is_frontend_request=is_frontend_request)

    if "email" in keycloak_account and keycloak_account["email"] is not None:
        email_addresses.add(keycloak_account["email"])

    google_workspace_account = get_attribute_value("googleWorkspaceAccount", keycloak_account)
    if google_workspace_account is not None:
        email_addresses.add(google_workspace_account)

    ramp_login_email_address = get_attribute_value("rampLoginEmailAddress", keycloak_account)
    if ramp_login_email_address is not None:
        email_addresses.add(ramp_login_email_address)

    whitepages_entries = get_whitepages_records(
        directory_id, is_frontend_request=is_frontend_request
    )

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
        url=app.config["GROUPER_BASE_URL"]
        + "/grouper-ws/servicesRest/v4_0_000/subjects/"
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


@cache.memoize(
    args_to_ignore=["with_gted", "with_title_and_organization"],
    response_filter=only_cache_if_result_present,
)
def search_by_slack_user_id(
    slack_user_id: str, with_gted: bool, with_title_and_organization: bool
) -> Any:
    """
    Search for a person by Slack user ID
    """
    cursor = db().execute(
        "SELECT primary_username FROM crosswalk WHERE slack_user_id = (:slack_user_id)",
        {"slack_user_id": slack_user_id},
    )
    row = cursor.fetchone()

    if row is not None:
        return search_by_username(row[0], with_title_and_organization=with_title_and_organization)

    slack_user_info = slack.users_info(user=slack_user_id)

    if slack_user_info.get("ok") is False:
        return {"results": [], "exactMatch": True}

    slack_user_profile: Any = slack_user_info.get("user", {})
    slack_user_email = slack_user_profile.get("profile", {}).get("email")

    if slack_user_email is None:
        return {"results": [], "exactMatch": True}

    search_results = search_by_email(
        Address(addr_spec=slack_user_email),
        with_gted=with_gted,
        with_title_and_organization=with_title_and_organization,
    )

    if len(search_results["results"]) == 0:
        return {"results": [], "exactMatch": True}

    update_crosswalk_slack_user_id(slack_user_id, search_results["results"][0]["directoryId"])

    return search_results


@cache.memoize(timeout=0)
def get_checkpoint_access_slack_user_ids() -> List[str]:
    """
    Get the Slack user IDs for everyone with the "access" role on the checkpoint client
    """
    clients_response = keycloak.get(
        url=urlunparse(
            (
                urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
                urlparse(app.config["KEYCLOAK_METADATA_URL"]).netloc,
                "/admin/realms/" + app.config["KEYCLOAK_REALM"] + "/clients",
                "",
                "clientId=checkpoint",
                "",
            )
        ),
        timeout=(5, 5),
    )
    clients_response.raise_for_status()

    if len(clients_response.json()) == 0:
        return []

    client_uuid = clients_response.json()[0]["id"]

    users_response = keycloak.get(
        url=urlunparse(
            (
                urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
                urlparse(app.config["KEYCLOAK_METADATA_URL"]).netloc,
                "/admin/realms/"
                + app.config["KEYCLOAK_REALM"]
                + "/clients/"
                + client_uuid
                + "/roles/access/users",
                "",
                "",
                "",
            )
        ),
        timeout=(5, 5),
    )
    users_response.raise_for_status()

    slack_user_ids = list[str]()

    for keycloak_user in users_response.json():
        if keycloak_user.get("username") is None:
            continue

        search_results = search_by_username(
            keycloak_user["username"], with_title_and_organization=False
        )

        if len(search_results["results"]) == 0:
            continue

        directory_id = search_results["results"][0]["directoryId"]

        for email_address in get_email_addresses(directory_id, is_frontend_request=False):
            try:
                slack_user_info = slack.users_lookupByEmail(email=email_address)
            except SlackApiError:
                continue

            if slack_user_info.get("ok") and slack_user_info["user"]["id"] not in slack_user_ids:
                update_crosswalk_slack_user_id(slack_user_info["user"]["id"], directory_id)
                slack_user_ids.append(slack_user_info["user"]["id"])
                break

    return slack_user_ids


@cache.memoize()
def slack_user_has_access_to_checkpoint(slack_user_id: str) -> bool:
    """
    Check if a Slack user has access to Checkpoint
    """
    triggering_user_results = search_by_slack_user_id(
        slack_user_id, with_gted=False, with_title_and_organization=False
    )

    if len(triggering_user_results["results"]) == 0:
        return False

    keycloak_account = get_keycloak_account(
        triggering_user_results["results"][0]["directoryId"], is_frontend_request=False
    )

    if keycloak_account is None or "id" not in keycloak_account or keycloak_account["id"] is None:
        return False

    keycloak_user_id = keycloak_account["id"]

    role_mappings_response = keycloak.get(
        url=urlunparse(
            (
                urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
                urlparse(app.config["KEYCLOAK_METADATA_URL"]).netloc,
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
                        return True

    return False


@cache.memoize()
def slack_user_has_iat_access(slack_user_id: str) -> bool:
    """
    Check if a Slack user has IAT access via GTED entitlements
    """
    viewer_results = search_by_slack_user_id(
        slack_user_id, with_gted=False, with_title_and_organization=False
    )

    if len(viewer_results["results"]) == 0:
        return False

    gted_accounts = search_gted(gtPersonDirectoryId=viewer_results["results"][0]["directoryId"])

    for account in gted_accounts:
        entitlements = account.get("gtAccountEntitlement")
        if entitlements is None:
            continue

        for entitlement in entitlements:
            if "/iat/" in entitlement:
                return True

    return False


@cache.memoize()
def slack_user_has_privilege_separated_account(slack_user_id: str) -> bool:
    """
    Check if a Slack user has a privilege separated GTED account
    """
    viewer_results = search_by_slack_user_id(
        slack_user_id, with_gted=False, with_title_and_organization=False
    )

    if len(viewer_results["results"]) == 0:
        return False

    cursor = db().execute(
        "SELECT primary_username FROM crosswalk WHERE gt_person_directory_id = (:directory_id)",
        {"directory_id": viewer_results["results"][0]["directoryId"]},
    )
    row = cursor.fetchone()

    if row is None:
        return False

    primary_username = row[0]

    accounts = search_gted(filter=build_ldap_filter(uid="*-" + primary_username))

    return len(accounts) > 0


@cache.memoize()
def slack_user_has_keycloak_admin_access(slack_user_id: str) -> bool:
    """
    Check if a Slack user has the admin realm role in the Keycloak master realm
    """
    viewer_results = search_by_slack_user_id(
        slack_user_id, with_gted=False, with_title_and_organization=False
    )

    if len(viewer_results["results"]) == 0:
        return False

    cursor = db().execute(
        "SELECT primary_username FROM crosswalk WHERE gt_person_directory_id = (:directory_id)",
        {"directory_id": viewer_results["results"][0]["directoryId"]},
    )
    row = cursor.fetchone()

    if row is None:
        return False

    primary_username = row[0]

    users_response = keycloak.get(
        url=urlunparse(
            (
                urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
                urlparse(app.config["KEYCLOAK_METADATA_URL"]).netloc,
                "/admin/realms/master/users",
                "",
                "",
                "",
            )
        ),
        params={"username": primary_username, "exact": True},
        timeout=(5, 5),
    )
    users_response.raise_for_status()

    if len(users_response.json()) == 0:
        return False

    master_realm_user_id = users_response.json()[0]["id"]

    role_mappings_response = keycloak.get(
        url=urlunparse(
            (
                urlparse(app.config["KEYCLOAK_METADATA_URL"]).scheme,
                urlparse(app.config["KEYCLOAK_METADATA_URL"]).netloc,
                "/admin/realms/master/users/" + master_realm_user_id + "/role-mappings/realm",
                "",
                "",
                "",
            )
        ),
        timeout=(5, 5),
    )
    role_mappings_response.raise_for_status()

    for mapping in role_mappings_response.json():
        if mapping.get("name") == "admin":
            return True

    return False


@cache.memoize()
def slack_user_has_google_workspace_admin_access(slack_user_id: str) -> bool:
    """
    Check if a Slack user is a Google Workspace admin (has isAdmin on their account)
    """
    viewer_results = search_by_slack_user_id(
        slack_user_id, with_gted=False, with_title_and_organization=False
    )

    if len(viewer_results["results"]) == 0:
        return False

    google_workspace_account = get_google_workspace_account(
        viewer_results["results"][0]["directoryId"], is_frontend_request=False
    )

    return google_workspace_account is not None and google_workspace_account.get("isAdmin") is True


def determine_slack_lookup_target(text: str, poster_slack_user_id: str) -> str:
    """
    Determine the user of interest for a Slack message.

    Returns either an email address or a Slack user ID.
    """
    email_addresses: set[str] = {match.lower() for match in re.findall(EMAIL_ADDRESS_REGEX, text)}

    if len(email_addresses) == 1:
        email_address, *_ = email_addresses
        return email_address

    mentioned_users: list[str] = re.findall(r"<@(U[A-Z0-9]+)>", text)

    return mentioned_users[0] if len(mentioned_users) == 1 else poster_slack_user_id


def open_slack_view_or_ephemeral(
    *,
    trigger_id: str,
    channel_id: str,
    user_id: str,
    view: Dict[str, Any],
    text: str,
) -> None:
    """
    Open a Slack modal, or post an ephemeral message if the trigger_id has expired.
    """
    try:
        slack.views_open(trigger_id=trigger_id, view=view)
    except SlackApiError as error:
        if error.response["error"] != "expired_trigger_id":
            raise
        try:
            slack.chat_postEphemeral(
                channel=channel_id,
                user=user_id,
                text=text,
                blocks=view["blocks"],
            )
        except SlackApiError:
            pass


@shared_task
def handle_slack_search_request(payload: Dict[str, Any]) -> None:
    """
    Handle a Slack interaction event
    """
    if slack_user_has_access_to_checkpoint(payload["user"]["id"]) is False:
        open_slack_view_or_ephemeral(
            trigger_id=payload["trigger_id"],
            channel_id=payload["channel"]["id"],
            user_id=payload["user"]["id"],
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
            text="You do not have access to Checkpoint.",
        )

    lookup_target = determine_slack_lookup_target(
        payload["message"].get("text", ""), payload["message"]["user"]
    )

    if "@" in lookup_target:
        lookup_results = search_by_email(
            Address(addr_spec=lookup_target), with_gted=True, with_title_and_organization=True
        )
    else:
        lookup_results = search_by_slack_user_id(
            lookup_target, with_gted=True, with_title_and_organization=True
        )

    if len(lookup_results["results"]) == 0:
        open_slack_view_or_ephemeral(
            trigger_id=payload["trigger_id"],
            channel_id=payload["channel"]["id"],
            user_id=payload["user"]["id"],
            view={
                "type": "modal",
                "title": {"type": "plain_text", "text": "Checkpoint"},
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "Could not find a Georgia Tech account for this user.",
                        },
                    }
                ],
            },
            text="Could not find a Georgia Tech account for this user.",
        )

        return

    result_context = build_search_result_context(lookup_results["results"][0])

    open_slack_view_or_ephemeral(
        trigger_id=payload["trigger_id"],
        channel_id=payload["channel"]["id"],
        user_id=payload["user"]["id"],
        view={
            "type": "modal",
            "title": {"type": "plain_text", "text": "Checkpoint"},
            "blocks": format_search_result_blocks(result_context, payload["user"]["id"]),
        },
        text=result_context["givenName"] + " " + result_context["surname"],
    )


@shared_task
def handle_slack_message_event(event: Dict[str, Any]) -> None:
    """
    Handle a Slack message event
    """
    message_text = event.get("text", "").lower()
    lookup_target = determine_slack_lookup_target(event.get("text", ""), event["user"])

    if "@" in lookup_target:
        lookup_results = search_by_email(
            Address(addr_spec=lookup_target), with_gted=True, with_title_and_organization=True
        )
    else:
        lookup_results = search_by_slack_user_id(
            lookup_target, with_gted=True, with_title_and_organization=True
        )

    if len(lookup_results["results"]) == 0:
        return

    user_ids = get_checkpoint_access_slack_user_ids()

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

    result_context = build_search_result_context(lookup_results["results"][0])

    customer_directory_id = lookup_results["results"][0]["directoryId"]
    customer_slack_user_id = None
    sent_customer_message = False
    technician_context = []

    for email_address in get_email_addresses(customer_directory_id, is_frontend_request=False):
        try:
            slack_user_info = slack.users_lookupByEmail(email=email_address)
        except SlackApiError:
            continue

        if slack_user_info.get("ok") and slack_user_info["user"]["id"]:
            customer_slack_user_id = slack_user_info["user"]["id"]
            update_crosswalk_slack_user_id(customer_slack_user_id, customer_directory_id)
            break

    if (
        customer_slack_user_id is not None
        and cache.get("sent_customer_message_" + customer_slack_user_id) is not None
    ):
        return

    if customer_slack_user_id is not None:
        footer_block = ContextBlock(
            elements=[
                TextObject(
                    type="plain_text",
                    text="I am a bot, and this action was performed automatically. Please reply to this thread if you need more help.",
                )
            ]
        )

        markdown_greeting = "Hi, <@" + customer_slack_user_id + ">!"
        plain_text_greeting = "Hi, " + lookup_results["results"][0]["givenName"] + "!"

        need_dues_blocks = [
            SectionBlock(
                text=TextObject(
                    type="mrkdwn",
                    text=markdown_greeting
                    + " You don't have access to any RoboJackets services right now, because you haven't yet paid dues for this semester. Visit <https://my.robojackets.org|MyRoboJackets> to pay online now.",
                )
            ),
            footer_block,
        ]
        need_dues_plain_text = (
            plain_text_greeting
            + " You don't have access to any RoboJackets services right now, because you haven't yet paid dues for this semester. Visit MyRoboJackets to pay online now."
        )

        apiary_account = get_apiary_account(customer_directory_id, is_frontend_request=False)

        if "id" not in apiary_account or apiary_account["id"] is None:
            # customer does not have an apiary account, ask them to pay dues
            slack.chat_postMessage(
                channel=event["channel"],
                thread_ts=event.get("ts", None),
                text=need_dues_plain_text,
                blocks=need_dues_blocks,
            )
            technician_context.append(
                SectionBlock(
                    text=TextObject(
                        type="mrkdwn",
                        text="User does not have an Apiary account.",
                    )
                )
            )
            sent_customer_message = True
        elif "is_active" not in apiary_account or apiary_account["is_active"] is not True:
            # customer does not have an active membership
            if "pay" in message_text or "due" in message_text or "order" in message_text:
                # request is related to a payment, attempt to locate order id
                if (
                    "dues" in apiary_account
                    and apiary_account["dues"] is not None
                    and len(apiary_account["dues"]) > 0
                ):
                    for transaction in apiary_account["dues"]:
                        if (
                            "status" in transaction
                            and transaction["status"] == "pending"
                            and "payment" in transaction
                            and transaction["payment"] is not None
                            and len(transaction["payment"]) > 0
                        ):
                            for payment in transaction["payment"]:
                                if (
                                    "method"  # pylint: disable=too-many-boolean-expressions
                                    in payment
                                    and payment["method"] == "square"
                                    and "amount" in payment
                                    and payment["amount"] == "0.00"
                                    and "order_id" in payment
                                    and payment["order_id"] is not None
                                ):
                                    client = Square()
                                    order_details = client.orders.get(payment["order_id"])

                                    if (
                                        order_details.order.tenders is not None
                                        and len(order_details.order.tenders) > 0
                                    ):
                                        for tender in order_details.order.tenders:
                                            if (
                                                tender.type == "CARD"
                                                and tender.card_details is not None
                                                and tender.card_details.errors is not None
                                                and len(tender.card_details.errors) > 0
                                            ):
                                                error_codes = set[str]()
                                                for error in tender.card_details.errors:
                                                    error_codes.add(error.code)

                                                error_codes_for_technician = (
                                                    "Square returned the following error code"
                                                    + ("s" if len(error_codes) > 1 else "")
                                                    + "\n\n"
                                                )

                                                for error_code in error_codes:
                                                    if error_code in SQUARE_ERROR_CODE_DESCRIPTIONS:
                                                        error_codes_for_technician += f"`{error_code}`\n{SQUARE_ERROR_CODE_DESCRIPTIONS[error_code]}\n\n"
                                                    else:
                                                        error_codes_for_technician += f"`{error_code}`\nNo description available.\n\n"

                                                technician_context.append(
                                                    SectionBlock(
                                                        text=TextObject(
                                                            type="mrkdwn",
                                                            text=error_codes_for_technician,
                                                        )
                                                    )
                                                )

                                                if len(error_codes) == 1:
                                                    error_code = error_codes.pop()

                                                    if (
                                                        error_code
                                                        in SQUARE_ERROR_CODE_CUSTOMER_MESSAGES
                                                    ):
                                                        customer_message = (
                                                            SQUARE_ERROR_CODE_CUSTOMER_MESSAGES[
                                                                error_code
                                                            ]
                                                        )

                                                        slack.chat_postMessage(
                                                            channel=event["channel"],
                                                            thread_ts=event.get("ts", None),
                                                            text=" ".join(
                                                                [
                                                                    plain_text_greeting,
                                                                    customer_message,
                                                                ]
                                                            ),
                                                            blocks=[
                                                                SectionBlock(
                                                                    text=TextObject(
                                                                        type="mrkdwn",
                                                                        text=" ".join(
                                                                            [
                                                                                plain_text_greeting,
                                                                                customer_message,
                                                                            ]
                                                                        ),
                                                                    )
                                                                ),
                                                                footer_block,
                                                            ],
                                                        )
                                                        sent_customer_message = True

                                                        break

                # request is related to a payment but the bot wasn't able to generate a customer-facing message
                if sent_customer_message is False:
                    technician_context.append(
                        SectionBlock(
                            text=TextObject(
                                type="mrkdwn",
                                text="This appears to be a dues-related request.",
                            )
                        )
                    )

                    slack.chat_postMessage(
                        channel=event["channel"],
                        thread_ts=event.get("ts", None),
                        blocks=[
                            SectionBlock(
                                text=TextObject(
                                    type="mrkdwn",
                                    text=app.config["PAYMENT_OPERATIONS_SLACK_MENTION"],
                                )
                            ),
                            footer_block,
                        ],
                    )
                    sent_customer_message = True

            # customer doesn't have an active membership, check if access active
            elif (
                "is_access_active" not in apiary_account
                or apiary_account["is_access_active"] is not True
            ):
                # customer isn't access-active, ask them to pay dues
                slack.chat_postMessage(
                    channel=event["channel"],
                    thread_ts=event.get("ts", None),
                    text=need_dues_plain_text,
                    blocks=need_dues_blocks,
                )
                technician_context.append(
                    SectionBlock(
                        text=TextObject(
                            type="mrkdwn",
                            text="User has an Apiary account, but isn't access-active.",
                        )
                    )
                )
                sent_customer_message = True

        if (
            "is_access_active" in apiary_account
            and apiary_account["is_access_active"] is True
            and sent_customer_message is False
        ):
            # customer is access-active
            if "is_active" in apiary_account and apiary_account["is_active"] is True:
                technician_context.append(
                    SectionBlock(
                        text=TextObject(
                            type="mrkdwn",
                            text=lookup_results["results"][0]["givenName"]
                            + " has an active membership.",
                        )
                    )
                )
            else:
                technician_context.append(
                    SectionBlock(
                        text=TextObject(
                            type="mrkdwn",
                            text=lookup_results["results"][0]["givenName"]
                            + " is access-active but *doesn't have an active membership.*",
                        )
                    )
                )

            if (
                "slack" in message_text
                or "announc" in message_text
                or "channel" in message_text
                or "<#c" in message_text
                or "<#g" in message_text
            ):
                # slack-related request
                slack.chat_postMessage(
                    channel=event["channel"],
                    thread_ts=event.get("ts", None),
                    blocks=[
                        SectionBlock(
                            text=TextObject(
                                type="mrkdwn",
                                text=app.config["SLACK_ADMINS_SLACK_MENTION"],
                            )
                        ),
                        footer_block,
                    ],
                )
                sent_customer_message = True

                technician_context.append(
                    SectionBlock(
                        text=TextObject(
                            type="mrkdwn",
                            text="This appears to be a Slack administration request.",
                        )
                    )
                )

            elif (
                "uber" in message_text  # pylint: disable=too-many-boolean-expressions
                or "lyft" in message_text
                or "paypal" in message_text
                or "venmo" in message_text
                or "zelle" in message_text
                or "reimburse" in message_text
                or "refund" in message_text
            ):
                # payment-related request
                slack.chat_postMessage(
                    channel=event["channel"],
                    thread_ts=event.get("ts", None),
                    blocks=[
                        SectionBlock(
                            text=TextObject(
                                type="mrkdwn",
                                text=app.config["PAYMENT_OPERATIONS_SLACK_MENTION"],
                            )
                        ),
                        footer_block,
                    ],
                )
                sent_customer_message = True

                technician_context.append(
                    SectionBlock(
                        text=TextObject(
                            type="mrkdwn",
                            text="This appears to be a payment-related request.",
                        )
                    )
                )

            elif (
                "gate" in message_text
                or "access" in message_text
                or "door" in message_text
                or "building" in message_text
            ):
                # physical access-related request
                slack.chat_postMessage(
                    channel=event["channel"],
                    thread_ts=event.get("ts", None),
                    blocks=[
                        SectionBlock(
                            text=TextObject(
                                type="mrkdwn",
                                text=app.config["PHYSICAL_ACCESS_SLACK_MENTION"],
                            )
                        ),
                        footer_block,
                    ],
                )
                sent_customer_message = True

                technician_context.append(
                    SectionBlock(
                        text=TextObject(
                            type="mrkdwn",
                            text="This appears to be a physical access request.",
                        )
                    )
                )

    if sent_customer_message and customer_slack_user_id is not None:
        cache.set("sent_customer_message_" + customer_slack_user_id, True)

    for user_id in user_ids:
        try:
            slack.chat_postEphemeral(
                channel=event["channel"],
                thread_ts=event.get("ts", None) if sent_customer_message is True else None,
                user=user_id,
                text=plain_text,
                blocks=format_search_result_blocks(result_context, user_id) + technician_context,  # type: ignore
            )
        except SlackApiError:
            continue


@app.post("/slack/interaction")
def handle_slack_interaction() -> Dict[str, str]:
    """
    Handle a Slack interaction event
    """
    verifier = SignatureVerifier(app.config["SLACK_SIGNING_SECRET"])

    if not verifier.is_valid_request(request.get_data(), request.headers):  # type: ignore
        raise Unauthorized("Slack signature verification failed")

    payload = loads(request.form.get("payload"))  # type: ignore

    if payload.get("type") == "block_actions":
        return {"status": "ok"}

    if payload.get("type") != "message_action":
        raise BadRequest("Unsupported payload type")

    handle_slack_search_request.delay(payload)

    return {"status": "ok"}


@app.post("/slack/message")
def handle_slack_nessage() -> Dict[str, str]:
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

        if body is not None and body.get("type") == "event_callback":
            if body.get("event", {}).get("thread_ts") is None:
                handle_slack_message_event.delay(body.get("event", {}))
            return {"status": "ok"}

    raise BadRequest("Unsupported payload type")


@app.get("/ping")
def ping() -> Dict[str, str]:
    """
    Returns an arbitrary successful response, for health checks
    """
    return {"status": "ok"}
