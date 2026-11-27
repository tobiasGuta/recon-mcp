"""Campaign authorization context shared by all campaign network operations."""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from functools import wraps
from inspect import signature

from recon.audit import write_audit_event
from recon.campaign_lock import campaign_operation
from recon.authorization import AuthorizationError, require_url, safe_target
from recon.campaigns import get_campaign


@dataclass(frozen=True)
class CampaignGrant:
    campaign_id: str
    tool: str
    fingerprint: str
    binding_id: str
    anchor: str


_active_grant: ContextVar[CampaignGrant | None] = ContextVar(
    "campaign_grant", default=None
)
_REVIEW = "Review the active policy and run the local reauthorize-campaign command."


def current_grant() -> CampaignGrant | None:
    return _active_grant.get()


def _binding(campaign_id: str) -> dict:
    active = get_campaign(campaign_id)
    if not active.get("ok"):
        raise AuthorizationError(
            "Active campaign could not be loaded. " + _REVIEW,
            code="invalid_campaign_binding",
        )
    if active["campaign"].get("status") == "archived":
        raise AuthorizationError("Campaign archival is pending or complete.", code="invalid_campaign_binding")
    binding = active["campaign"].get("scope_binding")
    if not isinstance(binding, dict) or not isinstance(binding.get("decision"), dict):
        raise AuthorizationError(
            "Campaign lacks a current policy binding. " + _REVIEW,
            code="invalid_campaign_binding",
        )
    return binding


def _grant(campaign_id: str, tool: str) -> CampaignGrant:
    binding = _binding(campaign_id)
    saved = binding["decision"]
    anchor = binding.get("anchor")
    fingerprint = saved.get("policy_fingerprint")
    binding_id = saved.get("decision_id")
    if not all(
        isinstance(value, str) and value for value in (anchor, fingerprint, binding_id)
    ):
        raise AuthorizationError(
            "Campaign binding is incomplete. " + _REVIEW,
            code="invalid_campaign_binding",
        )
    try:
        _, decision = require_url(anchor, expected_fingerprint=fingerprint)
    except AuthorizationError as exc:
        raise AuthorizationError(
            f"{exc} {_REVIEW}", code=exc.code, decision=exc.decision
        ) from exc
    if (
        saved.get("policy_schema_version") != decision["policy_schema_version"]
        or saved.get("policy_source") != decision["policy_source"]
        or saved.get("authorized") is not True
    ):
        raise AuthorizationError(
            "Campaign binding has an incompatible schema or policy source. " + _REVIEW,
            code="invalid_campaign_binding",
        )
    return CampaignGrant(campaign_id, tool, fingerprint, binding_id, anchor)


def verify_current_binding() -> None:
    grant = current_grant()
    if grant is None:
        return
    binding = _binding(grant.campaign_id)
    saved = binding["decision"]
    if (
        saved.get("decision_id") != grant.binding_id
        or saved.get("policy_fingerprint") != grant.fingerprint
        or binding.get("anchor") != grant.anchor
        or saved.get("authorized") is not True
    ):
        raise AuthorizationError(
            "Campaign binding changed during the operation. " + _REVIEW,
            code="policy_changed",
        )


def audit_dispatch(result: dict, *, phase: str) -> None:
    grant = current_grant()
    if grant:
        audit = write_audit_event(
            grant.campaign_id,
            grant.tool + ".authorization",
            target=result.get("target"),
            ok=result["authorized"],
            scope_decision=result,
            metadata={"phase": phase},
        )
        if not audit.get("ok") and result["authorized"]:
            raise AuthorizationError(
                "Could not audit authorization for the campaign request.",
                code="audit_unavailable",
            )


def campaign_network(target_argument: str, *, uses_network=None):
    """Guard a campaign operation without touching purely offline input variants."""

    def decorate(function):
        params = signature(function)

        @campaign_operation
        @wraps(function)
        def guarded(*args, **kwargs):
            bound = params.bind(*args, **kwargs)
            bound.apply_defaults()
            values = bound.arguments
            if uses_network and not uses_network(values):
                return function(*args, **kwargs)
            campaign_id = values["campaign_id"]
            existing = current_grant()
            try:
                grant = _grant(campaign_id, function.__name__)
                if existing and (existing.campaign_id, existing.binding_id) != (
                    grant.campaign_id,
                    grant.binding_id,
                ):
                    raise AuthorizationError(
                        "Campaign binding changed during the workflow. " + _REVIEW,
                        code="policy_changed",
                    )
            except AuthorizationError as exc:
                write_audit_event(
                    campaign_id,
                    function.__name__ + ".authorization",
                    target=safe_target(values[target_argument]),
                    ok=False,
                    scope_decision=exc.decision,
                    warnings=[str(exc)],
                    metadata={"reason_code": exc.code},
                )
                return {
                    "ok": False,
                    "error": str(exc),
                    "error_code": exc.code,
                    "scope_decision": exc.decision,
                }
            token = _active_grant.set(grant)
            try:
                return function(*args, **kwargs)
            finally:
                _active_grant.reset(token)

        return guarded

    return decorate
