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

# pylint: disable=missing-function-docstring

from typing import Dict

from flask import Flask

mock_app = Flask(__name__)


@mock_app.post("/grouper-ws/servicesRest/v4_0_000/groups")
def groups() -> Dict:
    return {
        "WsFindGroupsResults": {
            "groupResults": [
                {
                    "extension": "battlebots",
                    "typeOfGroup": "group",
                    "displayExtension": "battlebots",
                    "displayName": "gt:services:robojackets:battlebots",
                    "name": "gt:services:robojackets:battlebots",
                    "uuid": "72d6e25d1cf0479d870e8d3468355b03",
                    "idIndex": "5310976",
                    "enabled": "T",
                },
                {
                    "extension": "core",
                    "typeOfGroup": "group",
                    "displayExtension": "core",
                    "displayName": "gt:services:robojackets:core",
                    "name": "gt:services:robojackets:core",
                    "uuid": "58adab1bcf864843bb5ad276eedd2950",
                    "idIndex": "5310971",
                    "enabled": "T",
                },
                {
                    "extension": "general",
                    "typeOfGroup": "group",
                    "displayExtension": "general",
                    "displayName": "gt:services:robojackets:general",
                    "name": "gt:services:robojackets:general",
                    "uuid": "1d79469b960f4adda646e5b2669ff0cf",
                    "idIndex": "5309810",
                    "enabled": "T",
                },
                {
                    "extension": "it",
                    "typeOfGroup": "group",
                    "displayExtension": "it",
                    "description": "Information Technology",
                    "displayName": "gt:services:robojackets:it",
                    "name": "gt:services:robojackets:it",
                    "uuid": "69e8f9b53477408680ef2d7d1c9167e3",
                    "idIndex": "5345055",
                    "enabled": "T",
                },
                {
                    "extension": "robocup",
                    "typeOfGroup": "group",
                    "displayExtension": "robocup",
                    "displayName": "gt:services:robojackets:robocup",
                    "name": "gt:services:robojackets:robocup",
                    "uuid": "04088a542dfc42b9aae536826fec3cee",
                    "idIndex": "5310975",
                    "enabled": "T",
                },
                {
                    "extension": "robonav",
                    "typeOfGroup": "group",
                    "displayExtension": "robonav",
                    "displayName": "gt:services:robojackets:robonav",
                    "name": "gt:services:robojackets:robonav",
                    "uuid": "c30342fa958d428292518d1fd12a955a",
                    "idIndex": "5310973",
                    "enabled": "T",
                },
                {
                    "extension": "roboracing",
                    "typeOfGroup": "group",
                    "displayExtension": "roboracing",
                    "displayName": "gt:services:robojackets:roboracing",
                    "name": "gt:services:robojackets:roboracing",
                    "uuid": "5875bceb789b481fb579f71997e44262",
                    "idIndex": "5310972",
                    "enabled": "T",
                },
                {
                    "extension": "robowrestling",
                    "typeOfGroup": "group",
                    "displayExtension": "robowrestling",
                    "displayName": "gt:services:robojackets:robowrestling",
                    "name": "gt:services:robojackets:robowrestling",
                    "uuid": "c033d82ea7ca41ab92b996df1fcd6784",
                    "idIndex": "5310974",
                    "enabled": "T",
                },
                {
                    "extension": "training",
                    "typeOfGroup": "group",
                    "displayExtension": "training",
                    "displayName": "gt:services:robojackets:training",
                    "name": "gt:services:robojackets:training",
                    "uuid": "bd772f4cfffb4e699e1b48b2adbac8de",
                    "idIndex": "5310977",
                    "enabled": "T",
                },
            ],
            "resultMetadata": {
                "resultCode": "SUCCESS",
                "resultMessage": "Success for: clientVersion: 4.0.0, wsQueryFilter: WsQueryFilter[queryFilterType=FIND_BY_STEM_NAME,stemName=gt:services:robojackets]\n, includeGroupDetail: false, actAsSubject: null, paramNames: \n, params: null\n, wsGroupLookups: null",
                "success": "T",
            },
            "responseMetadata": {"millis": "208", "serverVersion": "5.13.5"},
        }
    }


@mock_app.get("/grouper-ws/servicesRest/v4_0_000/subjects/<subject_id>/memberships")
def memberships(subject_id: str) -> Dict:
    return {
        "WsGetMembershipsResults": {
            "wsMemberships": [
                {
                    "membershipId": "a5eee81a03374427aed091eafc76411f:ff814aa002644a518d95b72b3a0d7c8c",
                    "immediateMembershipId": "a5eee81a03374427aed091eafc76411f",
                    "listName": "members",
                    "listType": "list",
                    "membershipType": "immediate",
                    "enabled": "T",
                    "memberId": "ac60623b1be94495b87747aebe446453",
                    "groupId": "72d6e25d1cf0479d870e8d3468355b03",
                    "subjectId": subject_id,
                    "subjectSourceId": "gted-accounts",
                    "groupName": "gt:services:robojackets:battlebots",
                    "createTime": "2025/02/07 09:45:21.688",
                },
                {
                    "membershipId": "07cabab14ceb4ba89c545827c0b997a2:6f4b4297da2a4eefb0ce5595eb3ebf26",
                    "immediateMembershipId": "07cabab14ceb4ba89c545827c0b997a2",
                    "listName": "members",
                    "listType": "list",
                    "membershipType": "immediate",
                    "enabled": "T",
                    "memberId": "ac60623b1be94495b87747aebe446453",
                    "groupId": "58adab1bcf864843bb5ad276eedd2950",
                    "subjectId": subject_id,
                    "subjectSourceId": "gted-accounts",
                    "groupName": "gt:services:robojackets:core",
                    "createTime": "2025/02/07 09:45:21.852",
                },
                {
                    "membershipId": "07cabab14ceb4ba89c545827c0b997a2:8d5bf0087114443684f59338908ee470",
                    "immediateMembershipId": "07cabab14ceb4ba89c545827c0b997a2",
                    "listName": "members",
                    "listType": "list",
                    "membershipType": "effective",
                    "enabled": "T",
                    "memberId": "ac60623b1be94495b87747aebe446453",
                    "groupId": "1d79469b960f4adda646e5b2669ff0cf",
                    "subjectId": subject_id,
                    "subjectSourceId": "gted-accounts",
                    "groupName": "gt:services:robojackets:general",
                    "createTime": "2025/02/07 09:45:21.852",
                },
                {
                    "membershipId": "74ef9555bacc4a3f932a542516a1d56d:ef6989a1062046ca8a7e1c5d8c4a1f5d",
                    "immediateMembershipId": "74ef9555bacc4a3f932a542516a1d56d",
                    "listName": "members",
                    "listType": "list",
                    "membershipType": "effective",
                    "enabled": "T",
                    "memberId": "ac60623b1be94495b87747aebe446453",
                    "groupId": "1d79469b960f4adda646e5b2669ff0cf",
                    "subjectId": subject_id,
                    "subjectSourceId": "gted-accounts",
                    "groupName": "gt:services:robojackets:general",
                    "createTime": "2025/02/07 09:45:22.152",
                },
                {
                    "membershipId": "8bf70a409d234558bc4e57b44fe47e92:20bbd9eff4ee41d68c74fdbf15ed05fe",
                    "immediateMembershipId": "8bf70a409d234558bc4e57b44fe47e92",
                    "listName": "members",
                    "listType": "list",
                    "membershipType": "effective",
                    "enabled": "T",
                    "memberId": "ac60623b1be94495b87747aebe446453",
                    "groupId": "1d79469b960f4adda646e5b2669ff0cf",
                    "subjectId": subject_id,
                    "subjectSourceId": "gted-accounts",
                    "groupName": "gt:services:robojackets:general",
                    "createTime": "2025/02/07 09:45:21.993",
                },
                {
                    "membershipId": "91b3c64fbeb0486493d73759f3137bd6:b18d62e8124d4e10b19173e009cbdcc0",
                    "immediateMembershipId": "91b3c64fbeb0486493d73759f3137bd6",
                    "listName": "members",
                    "listType": "list",
                    "membershipType": "effective",
                    "enabled": "T",
                    "memberId": "ac60623b1be94495b87747aebe446453",
                    "groupId": "1d79469b960f4adda646e5b2669ff0cf",
                    "subjectId": subject_id,
                    "subjectSourceId": "gted-accounts",
                    "groupName": "gt:services:robojackets:general",
                    "createTime": "2025/02/07 09:45:22.301",
                },
                {
                    "membershipId": "a5eee81a03374427aed091eafc76411f:4a77d08b2401481f974b213e3ceb059c",
                    "immediateMembershipId": "a5eee81a03374427aed091eafc76411f",
                    "listName": "members",
                    "listType": "list",
                    "membershipType": "effective",
                    "enabled": "T",
                    "memberId": "ac60623b1be94495b87747aebe446453",
                    "groupId": "1d79469b960f4adda646e5b2669ff0cf",
                    "subjectId": subject_id,
                    "subjectSourceId": "gted-accounts",
                    "groupName": "gt:services:robojackets:general",
                    "createTime": "2025/02/07 09:45:21.688",
                },
                {
                    "membershipId": "d3f5c47859fb4a42932597fd14ace150:cf8d604645ad45a09adadc43f39415dc",
                    "immediateMembershipId": "d3f5c47859fb4a42932597fd14ace150",
                    "listName": "members",
                    "listType": "list",
                    "membershipType": "effective",
                    "enabled": "T",
                    "memberId": "ac60623b1be94495b87747aebe446453",
                    "groupId": "1d79469b960f4adda646e5b2669ff0cf",
                    "subjectId": subject_id,
                    "subjectSourceId": "gted-accounts",
                    "groupName": "gt:services:robojackets:general",
                    "createTime": "2025/02/07 09:45:22.432",
                },
                {
                    "membershipId": "c3356f5a9e844609b327a64b9e2feb8e:8972caa2d12148068e1c7a712d101905",
                    "immediateMembershipId": "c3356f5a9e844609b327a64b9e2feb8e",
                    "listName": "members",
                    "listType": "list",
                    "membershipType": "immediate",
                    "enabled": "T",
                    "memberId": "ac60623b1be94495b87747aebe446453",
                    "groupId": "69e8f9b53477408680ef2d7d1c9167e3",
                    "subjectId": subject_id,
                    "subjectSourceId": "gted-accounts",
                    "groupName": "gt:services:robojackets:it",
                    "createTime": "2024/09/09 02:05:05.778",
                },
                {
                    "membershipId": "8bf70a409d234558bc4e57b44fe47e92:88063d9bf7d2430f9b27a102a848f77f",
                    "immediateMembershipId": "8bf70a409d234558bc4e57b44fe47e92",
                    "listName": "members",
                    "listType": "list",
                    "membershipType": "immediate",
                    "enabled": "T",
                    "memberId": "ac60623b1be94495b87747aebe446453",
                    "groupId": "04088a542dfc42b9aae536826fec3cee",
                    "subjectId": subject_id,
                    "subjectSourceId": "gted-accounts",
                    "groupName": "gt:services:robojackets:robocup",
                    "createTime": "2025/02/07 09:45:21.993",
                },
                {
                    "membershipId": "74ef9555bacc4a3f932a542516a1d56d:860168b8d2654f908d89b7b8f2853246",
                    "immediateMembershipId": "74ef9555bacc4a3f932a542516a1d56d",
                    "listName": "members",
                    "listType": "list",
                    "membershipType": "immediate",
                    "enabled": "T",
                    "memberId": "ac60623b1be94495b87747aebe446453",
                    "groupId": "c30342fa958d428292518d1fd12a955a",
                    "subjectId": subject_id,
                    "subjectSourceId": "gted-accounts",
                    "groupName": "gt:services:robojackets:robonav",
                    "createTime": "2025/02/07 09:45:22.152",
                },
                {
                    "membershipId": "91b3c64fbeb0486493d73759f3137bd6:a1158e51d2764df7a35e60da268d6ffb",
                    "immediateMembershipId": "91b3c64fbeb0486493d73759f3137bd6",
                    "listName": "members",
                    "listType": "list",
                    "membershipType": "immediate",
                    "enabled": "T",
                    "memberId": "ac60623b1be94495b87747aebe446453",
                    "groupId": "5875bceb789b481fb579f71997e44262",
                    "subjectId": subject_id,
                    "subjectSourceId": "gted-accounts",
                    "groupName": "gt:services:robojackets:roboracing",
                    "createTime": "2025/02/07 09:45:22.301",
                },
                {
                    "membershipId": "d3f5c47859fb4a42932597fd14ace150:e7a04fab32ad4870ae8a4388764434ff",
                    "immediateMembershipId": "d3f5c47859fb4a42932597fd14ace150",
                    "listName": "members",
                    "listType": "list",
                    "membershipType": "immediate",
                    "enabled": "T",
                    "memberId": "ac60623b1be94495b87747aebe446453",
                    "groupId": "c033d82ea7ca41ab92b996df1fcd6784",
                    "subjectId": subject_id,
                    "subjectSourceId": "gted-accounts",
                    "groupName": "gt:services:robojackets:robowrestling",
                    "createTime": "2025/02/07 09:45:22.432",
                },
            ],
            "wsGroups": [
                {
                    "extension": "battlebots",
                    "typeOfGroup": "group",
                    "displayExtension": "battlebots",
                    "displayName": "gt:services:robojackets:battlebots",
                    "name": "gt:services:robojackets:battlebots",
                    "uuid": "72d6e25d1cf0479d870e8d3468355b03",
                    "idIndex": "5310976",
                    "enabled": "T",
                },
                {
                    "extension": "core",
                    "typeOfGroup": "group",
                    "displayExtension": "core",
                    "displayName": "gt:services:robojackets:core",
                    "name": "gt:services:robojackets:core",
                    "uuid": "58adab1bcf864843bb5ad276eedd2950",
                    "idIndex": "5310971",
                    "enabled": "T",
                },
                {
                    "extension": "general",
                    "typeOfGroup": "group",
                    "displayExtension": "general",
                    "displayName": "gt:services:robojackets:general",
                    "name": "gt:services:robojackets:general",
                    "uuid": "1d79469b960f4adda646e5b2669ff0cf",
                    "idIndex": "5309810",
                    "enabled": "T",
                },
                {
                    "extension": "it",
                    "typeOfGroup": "group",
                    "displayExtension": "it",
                    "description": "Information Technology",
                    "displayName": "gt:services:robojackets:it",
                    "name": "gt:services:robojackets:it",
                    "uuid": "69e8f9b53477408680ef2d7d1c9167e3",
                    "idIndex": "5345055",
                    "enabled": "T",
                },
                {
                    "extension": "robocup",
                    "typeOfGroup": "group",
                    "displayExtension": "robocup",
                    "displayName": "gt:services:robojackets:robocup",
                    "name": "gt:services:robojackets:robocup",
                    "uuid": "04088a542dfc42b9aae536826fec3cee",
                    "idIndex": "5310975",
                    "enabled": "T",
                },
                {
                    "extension": "robonav",
                    "typeOfGroup": "group",
                    "displayExtension": "robonav",
                    "displayName": "gt:services:robojackets:robonav",
                    "name": "gt:services:robojackets:robonav",
                    "uuid": "c30342fa958d428292518d1fd12a955a",
                    "idIndex": "5310973",
                    "enabled": "T",
                },
                {
                    "extension": "roboracing",
                    "typeOfGroup": "group",
                    "displayExtension": "roboracing",
                    "displayName": "gt:services:robojackets:roboracing",
                    "name": "gt:services:robojackets:roboracing",
                    "uuid": "5875bceb789b481fb579f71997e44262",
                    "idIndex": "5310972",
                    "enabled": "T",
                },
                {
                    "extension": "robowrestling",
                    "typeOfGroup": "group",
                    "displayExtension": "robowrestling",
                    "displayName": "gt:services:robojackets:robowrestling",
                    "name": "gt:services:robojackets:robowrestling",
                    "uuid": "c033d82ea7ca41ab92b996df1fcd6784",
                    "idIndex": "5310974",
                    "enabled": "T",
                },
            ],
            "wsSubjects": [
                {
                    "resultCode": "SUCCESS",
                    "success": "T",
                    "memberId": "ac60623b1be94495b87747aebe446453",
                    "id": subject_id,
                    "sourceId": "gted-accounts",
                }
            ],
            "resultMetadata": {
                "resultCode": "SUCCESS",
                "resultMessage": "Found 13 results involving 8 groups and 1 subjects",
                "success": "T",
            },
            "responseMetadata": {"millis": "2115", "serverVersion": "5.13.5"},
        }
    }


@mock_app.get("/grouper-ws/healthcheck")
def healthcheck() -> Dict:
    return {"status": "ok"}


if __name__ == "__main__":
    mock_app.run(port=9090)
