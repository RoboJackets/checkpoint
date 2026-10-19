"""
Tests for Dropbox access troubleshooting decisions and the Apiary sync request.
"""

import os
import unittest
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


GENERAL_GROUPER_GTAD_DN = (
    "CN=general_robojackets_services_gt,OU=grouper-prod,"
    "OU=Gted,OU=GT_Resources,DC=ad,DC=gatech,DC=edu"
)
ELIGIBLE_ENTITLEMENT = "/gt/central/services/dropbox/dropbox-eligible/enabled"
PROVISIONED_ENTITLEMENT = "/gt/central/services/dropbox/dropbox-access/enabled"


def gted_account(*entitlements: str) -> Dict[str, Any]:
    """
    Build a GTED account containing only the entitlements under test.
    """
    return {"gtAccountEntitlement": list(entitlements)}


def diagnose(**overrides: Any) -> str:
    """
    Run a Dropbox diagnosis with a fully provisioned member as the default.
    """
    inputs: Dict[str, Any] = {
        "teams": [{"name": "RoboRacing"}],
        "grouper_groups": ["roboracing", "general"],
        "grouper_memberships": {"wsGroups": [{"extension": "general"}]},
        "gtad_member_of": [GENERAL_GROUPER_GTAD_DN],
        "gted_accounts": [gted_account(ELIGIBLE_ENTITLEMENT, PROVISIONED_ENTITLEMENT)],
    }
    inputs.update(overrides)

    return checkpoint.diagnose_dropbox_access(
        inputs["teams"],
        inputs["grouper_groups"],
        inputs["grouper_memberships"],
        inputs["gtad_member_of"],
        inputs["gted_accounts"],
    )


class DiagnoseDropboxAccessTests(unittest.TestCase):
    """
    Dropbox troubleshooting stops at the first unmet provisioning step.
    """

    def test_team_name_matches_grouper_group_case_insensitively(self) -> None:
        """
        An Apiary team is eligible when its name matches a Grouper extension, ignoring case.
        """
        self.assertTrue(
            checkpoint.has_grouper_eligible_team(
                [{"name": "RoboRacing"}, "not-a-team", {"name": None}],
                ["roboracing"],
            )
        )
        self.assertFalse(
            checkpoint.has_grouper_eligible_team([{"name": "Social"}], ["roboracing", "general"])
        )

    def test_missing_team_stops_before_later_provisioning(self) -> None:
        """
        A user who is otherwise fully provisioned is still asked to join a team.
        """
        status = diagnose(teams=[])

        self.assertEqual(status, checkpoint.DROPBOX_STATUS_JOIN_TEAM)

    def test_team_without_general_grouper_group_requests_sync(self) -> None:
        """
        Grouper is checked only after a Grouper-eligible team, and only the general group counts.
        """
        status = diagnose(grouper_memberships={"wsGroups": [{"extension": "roboracing"}]})

        self.assertEqual(status, checkpoint.DROPBOX_STATUS_SYNC_GROUPER)

    def test_grouper_without_gtad_general_group_is_still_provisioning(self) -> None:
        """
        GTAD must contain the general Grouper group distinguished name.
        """
        self.assertEqual(
            diagnose(gtad_member_of=["CN=other,DC=gatech,DC=edu"]),
            checkpoint.DROPBOX_STATUS_PROVISIONING,
        )
        self.assertEqual(diagnose(gtad_member_of=None), checkpoint.DROPBOX_STATUS_PROVISIONING)
        self.assertTrue(checkpoint.is_in_general_gtad_group([GENERAL_GROUPER_GTAD_DN]))

    def test_missing_eligibility_is_reported_before_the_provisioned_entitlement(self) -> None:
        """
        Georgia Tech eligibility is required even when the provisioned entitlement is present.
        """
        status = diagnose(gted_accounts=[gted_account(PROVISIONED_ENTITLEMENT)])

        self.assertEqual(status, checkpoint.DROPBOX_STATUS_NOT_ELIGIBLE)

    def test_eligible_user_without_provisioned_entitlement_must_request_an_account(self) -> None:
        """
        An eligible user who is loaded through GTAD still needs the provisioned entitlement.
        """
        status = diagnose(
            gted_accounts=[
                gted_account(),
                gted_account(ELIGIBLE_ENTITLEMENT),
            ]
        )

        self.assertEqual(status, checkpoint.DROPBOX_STATUS_REQUEST_ACCOUNT)

    def test_provisioned_entitlement_on_any_account_completes_the_flow(self) -> None:
        """
        Either entitlement can come from any of the user's GTED accounts.
        """
        status = diagnose(
            gted_accounts=[
                gted_account(ELIGIBLE_ENTITLEMENT),
                gted_account(PROVISIONED_ENTITLEMENT),
            ]
        )

        self.assertEqual(status, checkpoint.DROPBOX_STATUS_PROVISIONED)


class SyncApiaryAccessTests(unittest.TestCase):
    """
    A missing Grouper membership asks Apiary to sync that user.
    """

    def test_posts_sync_access_for_the_username(self) -> None:
        """
        The sync request uses the Apiary username path and a long read timeout.
        """
        response = MagicMock()
        post = MagicMock(return_value=response)

        with patch.object(checkpoint.apiary, "post", post):
            checkpoint.sync_apiary_access("kberzinch3")

        response.raise_for_status.assert_called_once_with()
        requested_url = post.call_args.kwargs["url"]
        self.assertEqual(
            requested_url,
            checkpoint.app.config["APIARY_BASE_URL"] + "/api/v1/users/kberzinch3/sync-access",
        )
        self.assertTrue(requested_url.endswith("/api/v1/users/kberzinch3/sync-access"))
        self.assertEqual(post.call_args.kwargs["timeout"], (5, 60))

    def test_http_errors_propagate(self) -> None:
        """
        A failed sync is not treated as success.
        """
        response = MagicMock()
        response.raise_for_status.side_effect = HTTPError("502 Server Error")

        with patch.object(checkpoint.apiary, "post", return_value=response):
            with self.assertRaises(HTTPError):
                checkpoint.sync_apiary_access("kberzinch3")

    def test_assess_syncs_only_when_the_general_group_is_missing(self) -> None:
        """
        The assessment calls sync-access after diagnosing a Grouper gap and skips later lookups.
        """
        with (
            patch.object(checkpoint, "get_grouper_groups", return_value=["roboracing"]),
            patch.object(
                checkpoint, "fetch_grouper_memberships", return_value={"wsGroups": []}
            ) as fetch_grouper,
            patch.object(checkpoint, "sync_apiary_access") as sync_access,
            patch.object(checkpoint, "get_gtad_member_of") as get_gtad_member_of,
            patch.object(checkpoint, "search_gted") as search_gted,
        ):
            status = checkpoint.assess_dropbox_access(
                {"uid": "kberzinch3", "teams": [{"name": "RoboRacing"}]},
                "directory-id",
            )

        self.assertEqual(status, checkpoint.DROPBOX_STATUS_SYNC_GROUPER)
        fetch_grouper.assert_called_once_with("kberzinch3")
        sync_access.assert_called_once_with("kberzinch3")
        get_gtad_member_of.assert_not_called()
        search_gted.assert_not_called()

    def test_assess_does_not_sync_when_the_user_needs_a_team(self) -> None:
        """
        Joining a team is resolved before any Grouper or Apiary sync call.
        """
        with (
            patch.object(checkpoint, "get_grouper_groups", return_value=["roboracing"]),
            patch.object(checkpoint, "fetch_grouper_memberships") as fetch_grouper,
            patch.object(checkpoint, "sync_apiary_access") as sync_access,
        ):
            status = checkpoint.assess_dropbox_access(
                {"uid": "kberzinch3", "teams": [{"name": "Social"}]},
                "directory-id",
            )

        self.assertEqual(status, checkpoint.DROPBOX_STATUS_JOIN_TEAM)
        fetch_grouper.assert_not_called()
        sync_access.assert_not_called()

    def test_assess_does_not_sync_while_gtad_is_still_provisioning(self) -> None:
        """
        A Grouper member who is not in the GTAD general group waits instead of syncing again.
        """
        with (
            patch.object(checkpoint, "get_grouper_groups", return_value=["roboracing", "general"]),
            patch.object(
                checkpoint,
                "fetch_grouper_memberships",
                return_value={"wsGroups": [{"extension": "general"}]},
            ),
            patch.object(checkpoint, "get_gtad_member_of", return_value=[]),
            patch.object(checkpoint, "search_gted") as search_gted,
            patch.object(checkpoint, "sync_apiary_access") as sync_access,
        ):
            status = checkpoint.assess_dropbox_access(
                {"uid": "kberzinch3", "teams": [{"name": "RoboRacing"}]},
                "directory-id",
            )

        self.assertEqual(status, checkpoint.DROPBOX_STATUS_PROVISIONING)
        sync_access.assert_not_called()
        search_gted.assert_not_called()

    def test_assess_does_not_sync_when_dropbox_is_already_provisioned(self) -> None:
        """
        A fully provisioned user is not sent through sync-access.
        """
        with (
            patch.object(checkpoint, "get_grouper_groups", return_value=["roboracing", "general"]),
            patch.object(
                checkpoint,
                "fetch_grouper_memberships",
                return_value={"wsGroups": [{"extension": "general"}]},
            ),
            patch.object(checkpoint, "get_gtad_member_of", return_value=[GENERAL_GROUPER_GTAD_DN]),
            patch.object(
                checkpoint,
                "search_gted",
                return_value=[gted_account(ELIGIBLE_ENTITLEMENT, PROVISIONED_ENTITLEMENT)],
            ) as search_gted,
            patch.object(checkpoint, "sync_apiary_access") as sync_access,
        ):
            status = checkpoint.assess_dropbox_access(
                {"uid": "kberzinch3", "teams": [{"name": "RoboRacing"}]},
                "directory-id",
            )

        self.assertEqual(status, checkpoint.DROPBOX_STATUS_PROVISIONED)
        search_gted.assert_called_once_with(gtPersonDirectoryId="directory-id")
        sync_access.assert_not_called()

    def test_customer_replies_include_the_required_links(self) -> None:
        """
        Team and account-request replies point at the public instructions.
        """
        join_reply = checkpoint.dropbox_access_reply(
            checkpoint.DROPBOX_STATUS_JOIN_TEAM, "Hi, Kristaps!", "Hi, <@U1>!"
        )
        request_reply = checkpoint.dropbox_access_reply(
            checkpoint.DROPBOX_STATUS_REQUEST_ACCOUNT, "Hi, Kristaps!", "Hi, <@U1>!"
        )
        provisioning_reply = checkpoint.dropbox_access_reply(
            checkpoint.DROPBOX_STATUS_PROVISIONING, "Hi, Kristaps!", "Hi, <@U1>!"
        )

        self.assertIn("https://my.robojackets.org/teams", join_reply["plain_text"])
        self.assertIn("https://my.robojackets.org/teams", join_reply["markdown"])
        self.assertIn("https://dropbox.gatech.edu/", request_reply["plain_text"])
        self.assertIn("https://dropbox.gatech.edu/", request_reply["markdown"])
        self.assertIn("24 hours", provisioning_reply["plain_text"])

    def test_unrecognized_status_is_rejected(self) -> None:
        """
        Customer copy exists only for the known diagnosis results.
        """
        with self.assertRaises(InternalServerError):
            checkpoint.dropbox_access_reply("unknown", "Hi, Kristaps!", "Hi, <@U1>!")


if __name__ == "__main__":
    unittest.main()
