"""
Tests for Keycloak client labels when a client no longer exists.
"""

import os
import unittest
from json import dumps
from typing import Any, Dict
from unittest.mock import MagicMock, patch

from requests.exceptions import HTTPError

from werkzeug.exceptions import InternalServerError

os.environ.setdefault("FLASK_SECRET_KEY", "test-secret")
os.environ.setdefault(
    "FLASK_KEYCLOAK_METADATA_URL",
    "http://keycloak.test/realms/robojackets/.well-known/openid-configuration",
)
os.environ.setdefault("FLASK_KEYCLOAK_CLIENT_ID", "checkpoint")
os.environ.setdefault("FLASK_KEYCLOAK_CLIENT_SECRET", "checkpoint-secret")
os.environ.setdefault("FLASK_KEYCLOAK_ADMIN_CLIENT_ID", "checkpoint-admin")
os.environ.setdefault("FLASK_KEYCLOAK_ADMIN_CLIENT_SECRET", "checkpoint-admin-secret")
os.environ.setdefault("FLASK_KEYCLOAK_REALM", "robojackets")
os.environ.setdefault("FLASK_APIARY_CLIENT_ID", "apiary")
os.environ.setdefault("FLASK_APIARY_CLIENT_SECRET", "apiary-secret")
os.environ.setdefault("FLASK_APIARY_BASE_URL", "http://apiary.test")
os.environ.setdefault("FLASK_SLACK_BOT_TOKEN", "xoxb-test")
os.environ.setdefault("FLASK_CACHE_TYPE", "SimpleCache")

with patch(
    "authlib.integrations.requests_client.OAuth2Session.fetch_token",
    return_value={
        "access_token": "test-token",
        "token_type": "Bearer",
        "expires_in": 3600,
    },
):
    import checkpoint  # pylint: disable=wrong-import-position


class ClientResponse:
    """
    Minimal Keycloak HTTP response used by display-name lookups.
    """

    def __init__(self, status_code: int, payload: Dict[str, Any] | None = None) -> None:
        self.status_code = status_code
        self.payload = {} if payload is None else payload
        self.text = dumps(self.payload)

    def raise_for_status(self) -> None:
        """
        Raise for HTTP statuses that Keycloak treats as failures.
        """
        if self.status_code >= 400:
            raise HTTPError(f"{self.status_code} Client Error")

    def json(self) -> Dict[str, Any]:  # pylint: disable=missing-function-docstring
        return self.payload


def make_response(status_code: int, payload: Dict[str, Any] | None = None) -> ClientResponse:
    """
    Build a Keycloak client lookup response.
    """
    return ClientResponse(status_code, payload)


class GetClientDisplayNameTests(unittest.TestCase):
    """
    Historical admin events can reference clients that were later deleted.
    """

    def setUp(self) -> None:
        self.realms = [{"id": "realm-1", "realm": "robojackets"}]
        self.get_realms = patch.object(checkpoint, "get_realms", return_value=self.realms)
        self.get_realms.start()
        self.addCleanup(self.get_realms.stop)

    def test_deleted_client_returns_unknown_client(self) -> None:
        """
        A 404 from the Keycloak client endpoint is shown as unknown client.
        """
        client_lookup = MagicMock(return_value=make_response(404))

        with patch.object(checkpoint.keycloak, "get", client_lookup):
            display_name = checkpoint.get_client_display_name(
                realmId="realm-1", clientId="deleted-client"
            )

        self.assertEqual(display_name, "unknown client")
        requested_url = client_lookup.call_args.kwargs["url"]
        self.assertIn("/admin/realms/robojackets/clients/deleted-client", requested_url)

    def test_existing_client_returns_client_id(self) -> None:
        """
        An existing client is labeled with its Keycloak client id.
        """
        client_lookup = MagicMock(return_value=make_response(200, {"clientId": "checkpoint"}))

        with patch.object(checkpoint.keycloak, "get", client_lookup):
            display_name = checkpoint.get_client_display_name(
                realmId="realm-1", clientId="existing-client"
            )

        self.assertEqual(display_name, "checkpoint")

    def test_other_client_errors_still_raise(self) -> None:
        """
        Failures other than a missing client still surface to the caller.
        """
        client_lookup = MagicMock(return_value=make_response(500))

        with patch.object(checkpoint.keycloak, "get", client_lookup):
            with self.assertRaises(HTTPError):
                checkpoint.get_client_display_name(realmId="realm-1", clientId="broken-client")

    def test_missing_client_details_still_raise(self) -> None:
        """
        Events without a realm and client id are still rejected.
        """
        with self.assertRaises(InternalServerError):
            checkpoint.get_client_display_name()


if __name__ == "__main__":
    unittest.main()
