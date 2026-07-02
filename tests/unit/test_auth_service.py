import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from api.auth import AuthService, OperatorIdentity


def test_auth_service_jwt_roundtrip():
    service = AuthService("secret", users={"alice": {"password": "pw", "role": "analyst"}})
    identity = OperatorIdentity(username="alice", role="analyst", session_id="s1", mission_id="m1")
    token = service.issue_token(identity, lifetime_seconds=60)
    decoded = service.verify_token(token)

    assert decoded.username == "alice"
    assert decoded.role == "analyst"
    assert service.has_permission("analyst", "operate")
    assert not service.has_permission("observer", "approve")

