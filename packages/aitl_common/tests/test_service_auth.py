# No `from __future__ import annotations`: FastAPI must resolve the route's
# Annotated[..., Depends(local_dependency)] at runtime.
import hmac
import secrets
from pathlib import Path
from typing import Annotated
from unittest import mock

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from aitl_common.service_auth import MIN_TOKEN_LENGTH, ServiceTokenStore, require_service


def _token() -> str:
    return secrets.token_urlsafe(48)


@pytest.fixture
def tokens() -> dict[str, str]:
    return {"agent-runtime": _token(), "eval-service": _token(), "dashboard": _token()}


@pytest.fixture
def client(tokens: dict[str, str]) -> TestClient:
    store = ServiceTokenStore(tokens)
    only_agent_runtime = require_service(store, {"agent-runtime"})
    app = FastAPI()

    @app.post("/internal/thing")
    def internal(caller: Annotated[str, Depends(only_agent_runtime)]) -> dict[str, str]:
        return {"caller": caller}

    return TestClient(app)


def _post(client: TestClient, authorization: str | None) -> int:
    headers = {} if authorization is None else {"Authorization": authorization}
    return int(client.post("/internal/thing", headers=headers).status_code)


def test_allowed_caller_authenticated(client: TestClient, tokens: dict[str, str]) -> None:
    response = client.post(
        "/internal/thing", headers={"Authorization": f"Bearer {tokens['agent-runtime']}"}
    )
    assert response.status_code == 200
    assert response.json() == {"caller": "agent-runtime"}


def test_missing_credential_is_401(client: TestClient) -> None:
    response = client.post("/internal/thing")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json() == {"detail": "unauthorized"}


@pytest.mark.parametrize(
    "authorization",
    [
        "",
        "Bearer",
        "Bearer ",
        "Basic dXNlcjpwYXNz",
        "Token abc",
        "Bearer " + "x" * 64,
        "Bearer a b",
    ],
)
def test_invalid_credentials_are_401(client: TestClient, authorization: str) -> None:
    assert _post(client, authorization) == 401


def test_valid_token_of_other_caller_is_401(client: TestClient, tokens: dict[str, str]) -> None:
    assert _post(client, f"Bearer {tokens['eval-service']}") == 401
    assert _post(client, f"Bearer {tokens['dashboard']}") == 401


def test_token_prefix_or_suffix_is_401(client: TestClient, tokens: dict[str, str]) -> None:
    token = tokens["agent-runtime"]
    assert _post(client, f"Bearer {token[:-1]}") == 401
    assert _post(client, f"Bearer {token}x") == 401


def test_scheme_is_case_insensitive(client: TestClient, tokens: dict[str, str]) -> None:
    assert _post(client, f"bearer {tokens['agent-runtime']}") == 200


def test_comparison_is_constant_time_over_all_callers(tokens: dict[str, str]) -> None:
    store = ServiceTokenStore(tokens)
    original = hmac.compare_digest
    with mock.patch.object(hmac, "compare_digest", wraps=original) as spy:
        assert store.authenticate(tokens["agent-runtime"]) == "agent-runtime"
        assert spy.call_count == len(tokens)  # no early exit after the first match
        spy.reset_mock()
        assert store.authenticate("wrong-token") is None
        assert spy.call_count == len(tokens)


def test_rejected_credential_is_never_logged(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    presented = _token()
    with caplog.at_level("WARNING", logger="aitl.service_auth"):
        assert _post(client, f"Bearer {presented}") == 401
    assert presented not in caplog.text
    assert any(getattr(r, "aitl_event", None) == "service_auth.rejected" for r in caplog.records)


@pytest.mark.parametrize(
    "bad_token",
    [
        "",
        "short",
        "x" * (MIN_TOKEN_LENGTH - 1),
        "has space" + "x" * 40,
        "tab\t" + "x" * 40,
        "é" * 40,
    ],
)
def test_store_refuses_weak_or_malformed_tokens(bad_token: str) -> None:
    with pytest.raises(ValueError, match="too short or malformed"):
        ServiceTokenStore({"agent-runtime": bad_token})


def test_store_refuses_shared_tokens() -> None:
    shared = _token()
    with pytest.raises(ValueError, match="distinct"):
        ServiceTokenStore({"agent-runtime": shared, "eval-service": shared})


@pytest.mark.parametrize("name", ["", "Agent", "agent runtime", "../x", "a" * 64])
def test_store_refuses_invalid_service_names(name: str) -> None:
    with pytest.raises(ValueError, match="invalid service name"):
        ServiceTokenStore({name: _token()})


def test_store_refuses_empty() -> None:
    with pytest.raises(ValueError, match="at least one caller"):
        ServiceTokenStore({})


def test_require_service_refuses_unconfigured_or_empty_callers(tokens: dict[str, str]) -> None:
    store = ServiceTokenStore(tokens)
    with pytest.raises(ValueError, match="no token configured"):
        require_service(store, {"gateway-service"})
    with pytest.raises(ValueError, match="must not be empty"):
        require_service(store, set())


def test_from_directory_loads_token_files(tmp_path: Path, tokens: dict[str, str]) -> None:
    for caller, token in tokens.items():
        (tmp_path / caller).write_text(token + "\n", encoding="ascii")
    store = ServiceTokenStore.from_directory(tmp_path, tokens)
    assert store.callers == frozenset(tokens)
    assert store.authenticate(tokens["dashboard"]) == "dashboard"


def test_from_directory_missing_file_fails(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        ServiceTokenStore.from_directory(tmp_path, ["agent-runtime"])
