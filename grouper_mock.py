"""
Mock Grouper web service for local development.

Exposes the same REST endpoints that checkpoint.py calls on the real
grouper.gatech.edu so that the application can start and serve the
search page without network connectivity to Georgia Tech.

Run standalone:
    poetry run flask --app grouper_mock run --port 9090

Endpoints:
    POST /grouper-ws/servicesRest/v4_0_000/groups
    GET  /grouper-ws/servicesRest/v4_0_000/subjects/<subject_id>/memberships
"""

from flask import Flask, jsonify, request
from typing import Any, Dict

mock_app = Flask(__name__)

MOCK_GROUPS = [
    "general",
    "core",
    "it",
    "battlebots",
    "robocup",
    "robonav",
    "roboracing",
    "robowrestling",
]

MOCK_MEMBERSHIPS: Dict[str, Any] = {
    "wsMemberships": [
        {
            "subjectId": "testuser",
            "groupName": "gt:services:robojackets:general",
            "createTime": "2024/01/15 10:30:00.000",
        },
        {
            "subjectId": "testuser",
            "groupName": "gt:services:robojackets:core",
            "createTime": "2024/02/01 14:00:00.000",
        },
    ],
    "wsGroups": [
        {"extension": "general"},
        {"extension": "core"},
    ],
}


@mock_app.post("/grouper-ws/servicesRest/v4_0_000/groups")
def find_groups() -> Any:
    return jsonify(
        {
            "WsFindGroupsResults": {
                "groupResults": [
                    {
                        "extension": group,
                        "name": f"gt:services:robojackets:{group}",
                        "displayName": f"gt:services:robojackets:{group}",
                    }
                    for group in MOCK_GROUPS
                ]
            }
        }
    )


@mock_app.get(
    "/grouper-ws/servicesRest/v4_0_000/subjects/<subject_id>/memberships"
)
def get_memberships(subject_id: str) -> Any:
    memberships = {
        "wsMemberships": [
            {**m, "subjectId": subject_id}
            for m in (MOCK_MEMBERSHIPS.get("wsMemberships") or [])
        ],
        "wsGroups": MOCK_MEMBERSHIPS.get("wsGroups", []),
    }
    return jsonify({"WsGetMembershipsResults": memberships})


@mock_app.get("/grouper-ws/healthcheck")
def healthcheck() -> Any:
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    mock_app.run(port=9090)
