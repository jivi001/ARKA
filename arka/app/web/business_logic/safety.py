"""Business Logic Safety Validator enforcing Section 3.8.5.

Guarantees ARKA never automatically performs destructive, financial,
or irreversible actions on targets.
"""

from __future__ import annotations

import re
import urllib.parse

from arka.app.core.state.models import PolicyDecision, PolicyDecisionType, RiskLevel
from arka.app.web.business_logic.models import DestructiveActionCategory
from arka.app.web.models.http import HTTPMethod, HTTPRequest

# Patterns identifying potentially destructive, irreversible, or financial endpoints
_DESTRUCTIVE_PATH_PATTERNS: list[tuple[DestructiveActionCategory, re.Pattern[str]]] = [
    (
        DestructiveActionCategory.PURCHASE_PAYMENT,
        re.compile(
            r"(?i)\b(checkout|purchase|pay|payment|charge|order/submit|order/confirm|buy)\b"
        ),
    ),
    (
        DestructiveActionCategory.FINANCIAL_TRANSACTION,
        re.compile(r"(?i)\b(transfer|withdraw|deposit|wire|payout|wallet/send)\b"),
    ),
    (
        DestructiveActionCategory.DELETE_ACCOUNT,
        re.compile(r"(?i)\b(account/delete|user/delete|profile/delete|unregister|close-account)\b"),
    ),
    (
        DestructiveActionCategory.SEND_MESSAGE_OR_EMAIL,
        re.compile(r"(?i)\b(send-email|send-sms|send-message|broadcast|notify-all)\b"),
    ),
]


class DestructiveOperationBlocked(Exception):
    """Raised when an automated agent attempts to execute a destructive operation."""

    def __init__(self, category: DestructiveActionCategory, url: str, reason: str):
        self.category = category
        self.url = url
        self.reason = reason
        super().__init__(
            f"Destructive business logic operation blocked [{category.value}] on '{url}': {reason}"
        )


class BusinessLogicSafetyValidator:
    """Enforces strict safety boundaries preventing automated destructive exploitation."""

    @classmethod
    def classify_request(
        cls, request: HTTPRequest
    ) -> tuple[bool, DestructiveActionCategory | None, str]:
        """Classify if an HTTP request represents a destructive business-logic operation.

        Returns (is_destructive, category, reason).
        """
        parsed = urllib.parse.urlparse(request.url)
        path = parsed.path or "/"
        method = request.method

        # Read-only methods (GET, HEAD, OPTIONS) are generally safe from destructive state change
        if method in (HTTPMethod.GET, HTTPMethod.HEAD, HTTPMethod.OPTIONS):
            return False, None, "Read-only HTTP method"

        # Check path against destructive categories
        for category, pat in _DESTRUCTIVE_PATH_PATTERNS:
            if pat.search(path):
                reason = (
                    f"Path '{path}' matches destructive pattern category '{category.value}'. "
                    "Automated execution strictly prohibited under Section 3.8.5."
                )
                return True, category, reason

        # Check for DELETE on broad resource collections
        if method == HTTPMethod.DELETE and path in (
            "/",
            "/api",
            "/api/v1",
            "/users",
            "/products",
            "/database",
            "/reset",
        ):
            return (
                True,
                DestructiveActionCategory.MODIFY_PRODUCTION_DATA,
                f"DELETE method targeting high-impact path '{path}'.",
            )

        return False, None, "Operation within safe business logic bounds"

    @classmethod
    def evaluate_safety_policy(
        cls,
        request: HTTPRequest,
        engagement_id: str,
        task_id: str = "",
        agent_id: str = "",
        scope_version: int = 1,
    ) -> PolicyDecision | None:
        """If request is destructive, authoritatively return PolicyDecision requiring approval."""
        is_destr, category, reason = cls.classify_request(request)
        if not is_destr:
            return None

        return PolicyDecision(
            engagement_id=engagement_id,
            task_id=task_id,
            agent_id=agent_id,
            action=f"execute_destructive_operation:{category.value if category else 'unknown'}",
            target=request.url,
            decision=PolicyDecisionType.REQUIRE_APPROVAL,
            reason=reason,
            risk_level=RiskLevel.CRITICAL,
            requires_approval=True,
            scope_version=scope_version,
        )
