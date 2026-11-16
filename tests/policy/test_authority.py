import pytest

from local_gpt_mcp.policy import (
    AccessDenied,
    Caller,
    Capability,
    GrantRequest,
    PairingRequest,
    PolicyAuthority,
)


class LocalPrompter:
    def __init__(self) -> None:
        self.pair_allowed = True
        self.grant_allowed = True

    def approve_pairing(self, request: PairingRequest) -> bool:
        return self.pair_allowed

    def approve_grant(self, request: GrantRequest) -> bool:
        return self.grant_allowed


class Fixture:
    def __init__(self) -> None:
        self.now = 100.0
        self.ui = LocalPrompter()
        self.policy = PolicyAuthority(self.ui, clock=lambda: self.now)
        self.caller = Caller("human1", "device1", "session1")
        self.pairing = PairingRequest(self.caller.user_id, self.caller.device_id)
        self.request = GrantRequest(self.caller, "window:123", frozenset({Capability.WINDOW_READ}), 10)

    def approved(self) -> str:
        self.policy.pair(self.pairing)
        return self.policy.issue(self.request)


def test_default_deny_no_ui() -> None:
    policy = PolicyAuthority()
    with pytest.raises(AccessDenied, match="local approval"):
        policy.pair(PairingRequest("human", "device"))


def test_pairing_and_grant_need_separate_local_approvals() -> None:
    f = Fixture()
    f.ui.pair_allowed = False
    with pytest.raises(AccessDenied, match="local approval"):
        f.policy.pair(f.pairing)
    with pytest.raises(AccessDenied, match="unpaired"):
        f.policy.issue(f.request)
    f.ui.pair_allowed = True
    f.policy.pair(f.pairing)
    f.ui.grant_allowed = False
    with pytest.raises(AccessDenied, match="local approval"):
        f.policy.issue(f.request)


def test_approved_scope_and_expiry() -> None:
    f = Fixture()
    token = f.approved()
    f.policy.authorize(token, f.caller, "window:123", Capability.WINDOW_READ)
    f.now += 10
    with pytest.raises(AccessDenied, match="expired"):
        f.policy.authorize(token, f.caller, "window:123", Capability.WINDOW_READ)


@pytest.mark.parametrize("field", ["user_id", "device_id", "session_id"])
def test_cross_identity_is_denied(field: str) -> None:
    f = Fixture()
    token = f.approved()
    ids = {"user_id": "human1", "device_id": "device1", "session_id": "session1"}
    ids[field] = "other"
    with pytest.raises(AccessDenied, match="caller mismatch"):
        f.policy.authorize(token, Caller(**ids), "window:123", Capability.WINDOW_READ)


def test_target_and_capability_are_bounded() -> None:
    f = Fixture()
    token = f.approved()
    with pytest.raises(AccessDenied, match="scope mismatch"):
        f.policy.authorize(token, f.caller, "window:124", Capability.WINDOW_READ)
    with pytest.raises(AccessDenied, match="scope mismatch"):
        f.policy.authorize(token, f.caller, "window:123", Capability.WINDOW_INPUT)


def test_invalid_and_altered_tokens_fail_closed() -> None:
    f = Fixture()
    token = f.approved()
    with pytest.raises(AccessDenied, match="unknown"):
        f.policy.authorize(token + "altered", f.caller, "window:123", Capability.WINDOW_READ)
    f.policy.revoke(token)
    with pytest.raises(AccessDenied, match="revoked"):
        f.policy.authorize(token, f.caller, "window:123", Capability.WINDOW_READ)


def test_emergency_stop_is_permanent() -> None:
    f = Fixture()
    token = f.approved()
    f.policy.emergency_stop()
    assert f.policy.stopped
    with pytest.raises(AccessDenied, match="stopped"):
        f.policy.authorize(token, f.caller, "window:123", Capability.WINDOW_READ)
    with pytest.raises(AccessDenied, match="stopped"):
        f.policy.pair(f.pairing)


def test_pairing_revocation_invalidates_all_associated_grants() -> None:
    f = Fixture()
    token = f.approved()
    f.policy.revoke_pairing(f.pairing)
    with pytest.raises(AccessDenied):
        f.policy.authorize(token, f.caller, "window:123", Capability.WINDOW_READ)


@pytest.mark.parametrize("duration", [0, -1, 601, True])
def test_bad_expiry_rejected(duration: int) -> None:
    f = Fixture()
    f.policy.pair(f.pairing)
    with pytest.raises(AccessDenied, match="duration"):
        f.policy.issue(GrantRequest(f.caller, "window:123", f.request.capabilities, duration))


@pytest.mark.parametrize(
    "target, capability",
    [
        ("window:*", Capability.WINDOW_READ),
        ("window:0", Capability.WINDOW_READ),
        ("https://example.com/path", Capability.BROWSER_READ),
        ("https://user:pass@example.com", Capability.BROWSER_READ),
        ("http://example.com", Capability.BROWSER_READ),
        ("https://example.com?token=secret", Capability.BROWSER_READ),
        ("https://example.com:abc", Capability.BROWSER_READ),
        ("https://example.com:99999", Capability.BROWSER_READ),
        ("https://[::1", Capability.BROWSER_READ),
        ("https://example.com", Capability.WINDOW_INPUT),
    ],
)
def test_unsafe_target_or_capability_rejected(target: str, capability: Capability) -> None:
    f = Fixture()
    f.policy.pair(f.pairing)
    with pytest.raises(AccessDenied, match="scope"):
        f.policy.issue(GrantRequest(f.caller, target, frozenset({capability}), 5))


def test_exact_https_origin_scope_can_be_approved() -> None:
    f = Fixture()
    f.policy.pair(f.pairing)
    request = GrantRequest(f.caller, "https://example.com", frozenset({Capability.BROWSER_READ}), 5)
    token = f.policy.issue(request)
    f.policy.authorize(token, f.caller, "https://example.com", Capability.BROWSER_READ)


def test_audit_log_never_contains_tokens_or_urls() -> None:
    f = Fixture()
    token = f.approved()
    f.policy.authorize(token, f.caller, "window:123", Capability.WINDOW_READ)
    assert token not in repr(f.policy.events)
    assert "window:123" not in repr(f.policy.events)
    assert len(f.policy.events) == 3
