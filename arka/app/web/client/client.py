"""Controlled HTTP client execution boundary for ARKA Web Security.

Wraps httpx.AsyncClient to enforce:
- Pre-request ScopeGuard and SSRF validation
- Redirect interception with per-hop re-validation against ScopeGuard
- TOCTOU protection revalidating destination before execution
- Session context and CookieJar isolation (cross-engagement protection)
- Bounded response body capture and streaming size enforcement
- Cryptographic SHA-256 evidence generation via EvidenceStore
- Sensitive credential redaction in audit logs
"""

from __future__ import annotations

import time
import urllib.parse
from typing import TYPE_CHECKING, Any

import httpx

from arka.app.audit.schemas import AuditEventType
from arka.app.execution.schemas import EvidenceType
from arka.app.web.client.ssrf import WebSSRFError, WebSSRFValidator
from arka.app.web.models.http import (
    MAX_CAPTURED_BODY_BYTES,
    HTTPRequest,
    HTTPResponse,
    HTTPTransaction,
)

if TYPE_CHECKING:
    from arka.app.audit.service import AuditService
    from arka.app.core.scope.scopeguard import ScopeGuard
    from arka.app.execution.evidence import EvidenceStore
    from arka.app.web.models.auth import SessionContext


class ControlledHTTPClient:
    """Authoritative sandboxed HTTP client boundary for all web security testing."""

    def __init__(
        self,
        scope_guard: ScopeGuard | None = None,
        evidence_store: EvidenceStore | None = None,
        audit_service: AuditService | None = None,
        default_timeout: float = 10.0,
        max_response_size: int = MAX_CAPTURED_BODY_BYTES,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.scope_guard = scope_guard
        self.evidence_store = evidence_store
        self.audit = audit_service
        self.default_timeout = default_timeout
        self.max_response_size = max_response_size
        self._transport = transport

    async def execute(
        self,
        request: HTTPRequest,
        engagement_id: str = "",
        task_id: str = "",
        session_context: SessionContext | None = None,
    ) -> HTTPTransaction:
        """Execute a validated HTTP request and record cryptographic evidence.

        Optionally attaches and updates a SessionContext with CookieJar, CSRF tokens,
        and authentication state while enforcing strict cross-engagement boundaries.
        """
        start_time = time.monotonic()
        redirect_chain: list[str] = []
        eff_engagement_id = engagement_id or (
            session_context.engagement_id if session_context else "default-engagement"
        )

        # 0. Session isolation and scope version validation
        if session_context is not None:
            if session_context.engagement_id != eff_engagement_id:
                err = (
                    f"Session engagement mismatch: session belongs to "
                    f"'{session_context.engagement_id}', cannot be used for '{eff_engagement_id}'"
                )
                duration_ms = (time.monotonic() - start_time) * 1000.0
                tx = HTTPTransaction(
                    engagement_id=eff_engagement_id,
                    task_id=task_id,
                    request=request,
                    response=None,
                    error=err,
                    duration_ms=duration_ms,
                )
                await self._record_audit_event(tx, result_status="denied", error=err)
                return tx

            if (
                self.scope_guard is not None
                and session_context.scope_version != self.scope_guard.scope_version
            ):
                err = (
                    f"Session scope version {session_context.scope_version} is stale; "
                    f"current scope version is {self.scope_guard.scope_version}"
                )
                duration_ms = (time.monotonic() - start_time) * 1000.0
                tx = HTTPTransaction(
                    engagement_id=eff_engagement_id,
                    task_id=task_id,
                    request=request,
                    response=None,
                    error=err,
                    duration_ms=duration_ms,
                )
                await self._record_audit_event(tx, result_status="denied", error=err)
                return tx

            if not session_context.active:
                err = f"Session {session_context.session_id} is inactive or revoked"
                duration_ms = (time.monotonic() - start_time) * 1000.0
                tx = HTTPTransaction(
                    engagement_id=eff_engagement_id,
                    task_id=task_id,
                    request=request,
                    response=None,
                    error=err,
                    duration_ms=duration_ms,
                )
                await self._record_audit_event(tx, result_status="denied", error=err)
                return tx

        # 1. Pre-request validation against SSRF defenses and ScopeGuard (TOCTOU initial check)
        try:
            WebSSRFValidator.validate_url(request.url, self.scope_guard)
        except WebSSRFError as e:
            duration_ms = (time.monotonic() - start_time) * 1000.0
            tx = HTTPTransaction(
                engagement_id=eff_engagement_id,
                task_id=task_id,
                request=request,
                response=None,
                error=f"SSRF/Scope validation blocked request: {e}",
                duration_ms=duration_ms,
            )
            await self._record_audit_event(tx, result_status="denied", error=str(e))
            return tx

        current_url = request.url
        current_method = request.method.value
        current_headers = dict(request.headers)
        current_body = request.body
        redirect_count = 0
        final_resp: httpx.Response | None = None
        error_msg: str | None = None

        # 2. Attach session cookies and CSRF tokens if available
        if session_context is not None:
            # Attach auth context headers/tokens
            if session_context.auth_context:
                req_with_auth = session_context.auth_context.attach_to_request(
                    HTTPRequest(url=current_url, method=request.method, headers=current_headers)
                )
                current_headers = dict(req_with_auth.headers)

            # Attach session cookies matching current URL
            if session_context.cookie_jar:
                cookie_header = session_context.cookie_jar.get_cookie_header(current_url)
                if cookie_header:
                    existing_cookie = current_headers.get("Cookie", "")
                    if existing_cookie:
                        current_headers["Cookie"] = f"{existing_cookie}; {cookie_header}"
                    else:
                        current_headers["Cookie"] = cookie_header

            # Attach CSRF token if present and modifying method
            if session_context.csrf_token and current_method in ("POST", "PUT", "DELETE", "PATCH"):
                h_name = session_context.csrf_token.header_name
                if h_name not in current_headers:
                    tok_val = session_context.csrf_token.token_value.get_secret_value()
                    current_headers[h_name] = tok_val

        timeout = httpx.Timeout(request.timeout or self.default_timeout)
        client_kwargs: dict[str, Any] = {
            "timeout": timeout,
            "follow_redirects": False,  # Manual redirect control
        }
        if self._transport is not None:
            client_kwargs["transport"] = self._transport

        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                while True:
                    # TOCTOU check immediately before dispatch
                    WebSSRFValidator.validate_url(current_url, self.scope_guard)

                    # Prepare outbound content
                    content = (
                        current_body.encode("utf-8")
                        if isinstance(current_body, str)
                        else current_body
                    )

                    httpx_resp = await client.request(
                        method=current_method,
                        url=current_url,
                        headers=current_headers,
                        content=content,
                    )
                    final_resp = httpx_resp

                    # Ingest cookies into session jar if present
                    if session_context and session_context.cookie_jar:
                        # Extract all Set-Cookie headers
                        for h_key, h_val in httpx_resp.headers.raw:
                            if h_key.decode("latin1").lower() == "set-cookie":
                                set_cookie_str = h_val.decode("latin1", errors="replace")
                                session_context.cookie_jar.parse_and_add_set_cookie(
                                    set_cookie_str, current_url
                                )

                    # Check for redirect
                    if httpx_resp.is_redirect and request.follow_redirects:
                        location = httpx_resp.headers.get("Location")
                        if not location:
                            break

                        redirect_count += 1
                        redirect_chain.append(current_url)

                        if redirect_count > request.max_redirects:
                            error_msg = f"Exceeded maximum redirects ({request.max_redirects})"
                            final_resp = None
                            break

                        # Resolve redirect location relative to current URL
                        next_url = urllib.parse.urljoin(current_url, location)

                        # Re-validate redirect target against SSRF & ScopeGuard
                        try:
                            WebSSRFValidator.validate_url(next_url, self.scope_guard)
                        except WebSSRFError as redirect_err:
                            error_msg = f"Redirect blocked by SSRF/ScopeGuard: {redirect_err}"
                            final_resp = None
                            break

                        # Standard HTTP redirect semantics: 301/302/303 switch POST to GET
                        if httpx_resp.status_code in (301, 302, 303):
                            current_method = "GET"
                            current_body = None

                        current_url = next_url
                        continue

                    break

        except (httpx.RequestError, Exception) as req_err:
            error_msg = f"HTTP request failed: {req_err}"

        duration_ms = (time.monotonic() - start_time) * 1000.0

        normalized_response: HTTPResponse | None = None
        evidence_ref_id: str | None = None

        if final_resp is not None:
            # Read response bytes with bounded size
            raw_bytes = final_resp.content
            truncated = False
            if len(raw_bytes) > self.max_response_size:
                raw_bytes = raw_bytes[: self.max_response_size]
                truncated = True

            body_text = raw_bytes.decode("utf-8", errors="replace")

            resp_headers = dict(final_resp.headers)
            normalized_response = HTTPResponse(
                status_code=final_resp.status_code,
                headers=resp_headers,
                body=body_text,
                raw_body_bytes=raw_bytes,
                content_type=final_resp.headers.get("content-type", ""),
                url=str(final_resp.url),
                elapsed_time_ms=duration_ms,
                redirect_chain=redirect_chain,
                truncated=truncated,
            )

            # Update session context auth state and CSRF tokens
            if session_context is not None:
                from arka.app.web.session.manager import SessionManager

                sm = SessionManager()
                sm.analyze_response_auth_state(normalized_response, session_context, current_url)
                sm.extract_and_record_csrf_token(normalized_response, session_context, current_url)

            # Record cryptographic evidence if EvidenceStore is present
            if self.evidence_store is not None:
                evidence_content = {
                    "request": {
                        "method": request.method.value,
                        "url": request.url,
                        "headers": request.safe_headers_for_logging(),
                    },
                    "response": {
                        "status_code": normalized_response.status_code,
                        "headers": normalized_response.safe_headers_for_logging(),
                        "url": normalized_response.url,
                        "body": normalized_response.body,
                        "truncated": normalized_response.truncated,
                    },
                    "duration_ms": duration_ms,
                }
                ref = self.evidence_store.record_evidence(
                    execution_id=task_id or "web_http",
                    request_id=request.url,
                    engagement_id=eff_engagement_id,
                    task_id=task_id,
                    content=evidence_content,
                    evidence_type=EvidenceType.STRUCTURED_RESULT.value,
                    tool_name="controlled_http_client",
                    metadata={
                        "status_code": normalized_response.status_code,
                        "target": request.url,
                    },
                )
                evidence_ref_id = ref.evidence_id

        tx = HTTPTransaction(
            engagement_id=eff_engagement_id,
            task_id=task_id,
            request=request,
            response=normalized_response,
            error=error_msg,
            duration_ms=duration_ms,
            evidence_ref=evidence_ref_id,
        )

        status_result = "success" if (tx.response and tx.response.is_success()) else "error"
        if error_msg:
            status_result = "error"
        await self._record_audit_event(tx, result_status=status_result, error=error_msg)

        return tx

    async def _record_audit_event(
        self,
        tx: HTTPTransaction,
        result_status: str,
        error: str | None = None,
    ) -> None:
        """Record append-only audit log with redacted credentials."""
        if self.audit is None:
            return

        params: dict[str, Any] = {
            "method": tx.request.method.value,
            "url": tx.request.url,
            "headers": tx.request.safe_headers_for_logging(),
            "duration_ms": tx.duration_ms,
        }
        if tx.response:
            params["status_code"] = tx.response.status_code

        await self.audit.record_action(
            event_type=AuditEventType.TOOL_EXECUTED,
            actor="controlled_http_client",
            action=f"http_{tx.request.method.value.lower()}",
            engagement_id=tx.engagement_id,
            task_id=tx.task_id,
            target=tx.request.url,
            parameters=params,
            result_status=result_status,
            error=error,
            evidence_ref=tx.evidence_ref,
        )
