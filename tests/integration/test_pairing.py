"""Session security tests use a controllable clock and fake local approver."""

from __future__ import annotations

import pytest

from local_gpt_mcp.pairing import SessionBroker, SessionDenied
from local_gpt_mcp.policy import AccessDenied, Capability, GrantRequest, PairingRequest, PolicyAuthority


class Approval:
    def __init__(self) -> None:
        self.allowed = True
        self.grants = True
        self.pair_calls = 0

    def approve_pairing(self, request: PairingRequest) -> bool:
        self.pair_calls += 1
        return self.allowed

    def approve_grant(self, request: GrantRequest) -> bool:
        return self.grants


class BrokerFixture:
    def __init__(self) -> None:
        self.now = 100.0
        self.approval = Approval()
        self.policy = PolicyAuthority(self.approval, clock=lambda: self.now)
        self.broker = SessionBroker(self.policy, clock=lambda: self.now)
        self.serial = 0

    def nonce(self) -> str:
        self.serial += 1
        return f"{self.serial:032x}"

    def open(self) -> str:
        result = self.broker.open("user1", "device1", self.nonce())
        assert result["expires_in"] == 300
        assert isinstance(result["session_token"], str)
        return result["session_token"]

    def grant(self, session: str) -> str:
        result = self.broker.request_grant(
            session, self.nonce(), "window:11", frozenset({Capability.WINDOW_READ}), 60
        )
        return str(result["grant_token"])


def test_no_unattended_approval() -> None:
    f = BrokerFixture()
    f.approval.allowed = False
    with pytest.raises(AccessDenied, match="local approval"):
        f.open()
    assert f.approval.pair_calls == 1


def test_session_is_unpredictable_and_scoped() -> None:
    f = BrokerFixture()
    token = f.open()
    assert len(token) >= 32
    assert f.broker.status(token, f.nonce())["paired"] is True
    with pytest.raises(SessionDenied, match="unknown"):
        f.broker.status(token + "wrong", f.nonce())


def test_replay_is_rejected() -> None:
    f = BrokerFixture()
    token = f.open()
    nonce = f.nonce()
    f.broker.status(token, nonce)
    with pytest.raises(SessionDenied, match="replayed"):
        f.broker.status(token, nonce)


def test_pairing_nonce_replay_and_invalid_input() -> None:
    f = BrokerFixture()
    nonce = f.nonce()
    f.broker.open("user1", "device1", nonce)
    with pytest.raises(SessionDenied, match="repeated"):
        f.broker.open("user1", "device1", nonce)
    f.broker.open("user1", "device1", f.nonce())
    with pytest.raises(SessionDenied, match="limited"):
        f.broker.open("user1", "device1", f.nonce())
    # After a minute the attempt budget is replenished.
    f.now += 61
    with pytest.raises(SessionDenied, match="invalid"):
        f.broker.open("user1", "device1", "not-hex")


def test_pairing_attempts_are_bounded() -> None:
    f = BrokerFixture()
    f.approval.allowed = False
    for _ in range(3):
        with pytest.raises(AccessDenied):
            f.open()
    with pytest.raises(SessionDenied, match="limited"):
        f.open()
    assert f.approval.pair_calls == 3


def test_session_expiration_clears_owned_grants() -> None:
    f = BrokerFixture()
    token = f.open()
    grant = f.grant(token)
    f.now += 300
    with pytest.raises(SessionDenied, match="unknown"):
        f.broker.status(token, f.nonce())
    assert any(event.reason == "session grant invalidated" for event in f.policy.events)
    with pytest.raises(SessionDenied, match="unknown"):
        f.broker.authorize_grant(token, f.nonce(), grant, "window:11", Capability.WINDOW_READ)


def test_grant_requires_local_approval() -> None:
    f = BrokerFixture()
    token = f.open()
    f.approval.grants = False
    with pytest.raises(AccessDenied, match="local approval"):
        f.grant(token)


def test_grant_authorization_checks_target_and_capability() -> None:
    f = BrokerFixture()
    token = f.open()
    grant = f.grant(token)
    f.broker.authorize_grant(token, f.nonce(), grant, "window:11", Capability.WINDOW_READ)
    with pytest.raises(AccessDenied, match="scope mismatch"):
        f.broker.authorize_grant(token, f.nonce(), grant, "window:11", Capability.WINDOW_INPUT)
    with pytest.raises(AccessDenied, match="scope mismatch"):
        f.broker.authorize_grant(token, f.nonce(), grant, "window:12", Capability.WINDOW_READ)


def test_grant_cannot_be_stolen_by_another_session() -> None:
    f = BrokerFixture()
    token = f.open()
    grant = f.grant(token)
    token2 = f.open()
    with pytest.raises(SessionDenied, match="does not belong"):
        f.broker.authorize_grant(token2, f.nonce(), grant, "window:11", Capability.WINDOW_READ)
    with pytest.raises(SessionDenied, match="does not belong"):
        f.broker.revoke_grant(token2, f.nonce(), grant)


def test_revoke_and_close_are_effective() -> None:
    f = BrokerFixture()
    token = f.open()
    grant = f.grant(token)
    f.broker.revoke_grant(token, f.nonce(), grant)
    with pytest.raises(SessionDenied, match="does not belong"):
        f.broker.authorize_grant(token, f.nonce(), grant, "window:11", Capability.WINDOW_READ)
    f.grant(token)
    f.broker.close(token, f.nonce())
    with pytest.raises(SessionDenied, match="unknown"):
        f.broker.status(token, f.nonce())


def test_emergency_stop_cancels_every_session() -> None:
    f = BrokerFixture()
    token = f.open()
    f.broker.stop(token, f.nonce())
    assert f.policy.stopped
    with pytest.raises(SessionDenied, match="stopped"):
        f.broker.status(token, f.nonce())
    with pytest.raises(SessionDenied, match="stopped"):
        f.broker.open("user1", "device1", f.nonce())


def test_per_session_rate_limit() -> None:
    f = BrokerFixture()
    token = f.open()
    for _ in range(30):
        f.broker.status(token, f.nonce())
    with pytest.raises(SessionDenied, match="rate limit"):
        f.broker.status(token, f.nonce())
    f.now += 61
    assert f.broker.status(token, f.nonce())["paired"] is True


def test_session_grant_expiry_cannot_outlive_pairing_session() -> None:
    f = BrokerFixture()
    token = f.open()
    f.now += 270
    result = f.broker.request_grant(
        token, f.nonce(), "window:11", frozenset({Capability.WINDOW_READ}), 600
    )
    assert result["expires_in"] == 30


def test_invalid_grant_duration_is_denied() -> None:
    f = BrokerFixture()
    token = f.open()
    with pytest.raises(AccessDenied, match="duration"):
        f.broker.request_grant(
            token, f.nonce(), "window:11", frozenset({Capability.WINDOW_READ}), -3
        )


def test_bounded_replay_store() -> None:
    f = BrokerFixture()
    token = f.open()
    for i in range(128):
        if i and i % 29 == 0:
            f.now += 61
        f.broker.status(token, f.nonce())
    with pytest.raises(SessionDenied, match="nonce budget"):
        f.broker.status(token, f.nonce())


def test_denied_session_has_no_secrets_in_audit() -> None:
    f = BrokerFixture()
    token = f.open()
    grant = f.grant(token)
    with pytest.raises(SessionDenied):
        f.broker.authorize_grant(
            token, f.nonce(), grant + "invalid", "window:11", Capability.WINDOW_READ
        )
    assert token not in repr(f.policy.events)
    assert grant not in repr(f.policy.events)


def test_open_response_is_not_a_policy_grant() -> None:
    f = BrokerFixture()
    token = f.open()
    with pytest.raises(AccessDenied):
        f.policy.authorize(
            token, 
            f.broker._sessions[token].caller,
            "window:11",
            Capability.WINDOW_READ,
        )
