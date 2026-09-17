"""Hardened, bounded asynchronous web crawler for ARKA Web Security.

Operates strictly within authorized engagement scope, enforcing hard limits
on pages, depth, concurrency, timeouts, and response sizes, with zero shell execution.
"""

from __future__ import annotations

import asyncio
import collections
import time
import urllib.parse
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from arka.app.web.crawler.config import CrawlerConfig
from arka.app.web.crawler.parser import (
    RobotsTxtParser,
    SitemapXMLParser,
    canonicalize_url,
    parse_html_content,
)
from arka.app.web.models.endpoint import DiscoveredForm, DiscoveredWebEndpoint
from arka.app.web.models.http import HTTPMethod, HTTPRequest, HTTPTransaction
from arka.app.web.models.parameters import Parameter, ParameterLocation

if TYPE_CHECKING:
    from arka.app.core.scope.scopeguard import ScopeGuard
    from arka.app.web.client.client import ControlledHTTPClient


class CrawlResult(BaseModel):
    """Execution summary and discovered artifacts from a crawler run."""

    model_config = ConfigDict(frozen=True)

    target_url: str
    pages_crawled: int = 0
    urls_discovered: list[str] = Field(default_factory=list)
    endpoints: list[DiscoveredWebEndpoint] = Field(default_factory=list)
    forms: list[DiscoveredForm] = Field(default_factory=list)
    transactions: list[HTTPTransaction] = Field(default_factory=list)
    out_of_scope_urls: list[str] = Field(default_factory=list)
    duration_seconds: float = 0.0
    terminated_reason: str = "completed"


class WebCrawler:
    """Hardened BFS web crawler bound to ScopeGuard and ControlledHTTPClient."""

    def __init__(
        self,
        client: ControlledHTTPClient,
        scope_guard: ScopeGuard | None = None,
        config: CrawlerConfig | None = None,
    ) -> None:
        self.client = client
        self.scope_guard = scope_guard
        self.config = config or CrawlerConfig()

    def _is_same_origin(self, url: str, base_parsed: urllib.parse.ParseResult) -> bool:
        """Check if url shares the same scheme, host, and port as the base URL."""
        parsed = urllib.parse.urlparse(url)
        if (parsed.scheme or "").lower() != base_parsed.scheme.lower():
            return False

        host = (parsed.hostname or "").lower()
        base_host = (base_parsed.hostname or "").lower()

        if host == base_host:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            base_port = base_parsed.port or (443 if base_parsed.scheme == "https" else 80)
            return port == base_port

        if self.config.allow_subdomains:
            return host.endswith("." + base_host)

        return False

    def _extract_parameters_from_url(self, url: str) -> list[Parameter]:
        """Extract query parameters into canonical Parameter models."""
        parsed = urllib.parse.urlparse(url)
        params: list[Parameter] = []
        if parsed.query:
            query_tuples = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            for k, v in query_tuples:
                params.append(
                    Parameter(
                        name=k,
                        location=ParameterLocation.QUERY,
                        sample_value=v,
                        required=False,
                    )
                )
        return params

    async def crawl(
        self,
        start_url: str,
        engagement_id: str = "",
        task_id: str = "",
    ) -> CrawlResult:
        """Perform a bounded crawl starting from start_url."""
        start_time = time.monotonic()
        canon_start = canonicalize_url(start_url, start_url)
        if not canon_start:
            return CrawlResult(
                target_url=start_url,
                terminated_reason="invalid_start_url",
            )

        base_parsed = urllib.parse.urlparse(canon_start)
        base_origin = f"{base_parsed.scheme}://{base_parsed.netloc}"

        visited: set[str] = set()
        discovered_urls: set[str] = {canon_start}
        out_of_scope_urls: set[str] = set()
        discovered_endpoints: dict[str, DiscoveredWebEndpoint] = {}
        discovered_forms: list[DiscoveredForm] = []
        transactions: list[HTTPTransaction] = []

        # BFS queue of (url, depth)
        queue: collections.deque[tuple[str, int]] = collections.deque([(canon_start, 0)])

        requests_count = 0
        pages_crawled = 0
        terminated_reason = "completed"

        # 1. Optional robots.txt discovery
        if self.config.respect_robots_txt:
            robots_url = f"{base_origin}/robots.txt"
            if self.scope_guard is None or self.scope_guard.validate_url(robots_url):
                robots_req = HTTPRequest(
                    url=robots_url,
                    method=HTTPMethod.GET,
                    timeout=self.config.request_timeout,
                )
                tx_robots = await self.client.execute(robots_req, engagement_id, task_id)
                transactions.append(tx_robots)
                requests_count += 1
                if tx_robots.response and tx_robots.response.is_success():
                    robots_data = RobotsTxtParser.parse(tx_robots.response.body, base_origin)
                    for path_url in robots_data["disallowed"] + robots_data["allowed"]:
                        discovered_urls.add(path_url)
                        if self.scope_guard is None or self.scope_guard.validate_url(path_url):
                            if path_url not in visited:
                                queue.append((path_url, 1))
                        else:
                            out_of_scope_urls.add(path_url)

                    # Enqueue sitemaps if discovered
                    for sm in robots_data["sitemaps"]:
                        if self.scope_guard is None or self.scope_guard.validate_url(sm):
                            queue.append((sm, 1))

        # 2. Main BFS crawling loop
        semaphore = asyncio.Semaphore(self.config.max_concurrency)

        while queue:
            # Check elapsed crawl timeout
            if (time.monotonic() - start_time) > self.config.crawl_timeout:
                terminated_reason = "crawl_timeout"
                break

            # Check max pages
            if pages_crawled >= self.config.max_pages:
                terminated_reason = "max_pages_reached"
                break

            # Check max requests
            if requests_count >= self.config.max_requests:
                terminated_reason = "max_requests_reached"
                break

            current_url, depth = queue.popleft()
            if current_url in visited:
                continue

            visited.add(current_url)

            # Check depth limit
            if depth > self.config.max_depth:
                continue

            # Verify same-origin constraint
            if self.config.same_origin_only and not self._is_same_origin(current_url, base_parsed):
                out_of_scope_urls.add(current_url)
                continue

            # Verify ScopeGuard on this URL
            if self.scope_guard is not None and not self.scope_guard.validate_url(current_url):
                out_of_scope_urls.add(current_url)
                continue

            # Execute fetch through ControlledHTTPClient
            async with semaphore:
                req = HTTPRequest(
                    url=current_url,
                    method=HTTPMethod.GET,
                    timeout=self.config.request_timeout,
                    follow_redirects=True,
                    max_redirects=self.config.max_redirects,
                )
                tx = await self.client.execute(req, engagement_id, task_id)
                transactions.append(tx)
                requests_count += 1
                pages_crawled += 1

            if not tx.response or not tx.response.is_success():
                continue

            resp = tx.response
            content_type = resp.content_type.lower()
            parsed_url = urllib.parse.urlparse(resp.url)
            port_val = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)

            # Register discovered endpoint
            ep_params = self._extract_parameters_from_url(resp.url)
            endpoint_key = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            if endpoint_key not in discovered_endpoints:
                discovered_endpoints[endpoint_key] = DiscoveredWebEndpoint(
                    url=resp.url,
                    scheme=parsed_url.scheme,
                    host=parsed_url.hostname or "",
                    port=port_val,
                    path=parsed_url.path or "/",
                    method=HTTPMethod.GET,
                    parameters=ep_params,
                    status_code=resp.status_code,
                    content_type=content_type,
                    source="crawler",
                )

            # Handle XML sitemap
            if "xml" in content_type or current_url.endswith(".xml"):
                sitemap_links = SitemapXMLParser.parse(resp.body, current_url)
                for s_link in sitemap_links:
                    discovered_urls.add(s_link)
                    if self.scope_guard is None or self.scope_guard.validate_url(s_link):
                        if s_link not in visited:
                            queue.append((s_link, depth + 1))
                    else:
                        out_of_scope_urls.add(s_link)
                continue

            # Handle HTML content
            if "html" in content_type or not content_type:
                html_res = parse_html_content(resp.body, resp.url)

                # Collect forms
                for form in html_res.forms:
                    discovered_forms.append(form)

                # Process all extracted links & references
                extracted_candidates = (
                    html_res.links
                    | html_res.scripts
                    | html_res.stylesheets
                    | set(html_res.meta_redirects)
                )

                for candidate in extracted_candidates:
                    discovered_urls.add(candidate)

                    # Re-evaluate candidate against ScopeGuard (safely handle malformed URLs)
                    in_scope = False
                    if self.scope_guard is None:
                        in_scope = True
                    else:
                        try:
                            in_scope = self.scope_guard.validate_url(candidate)
                        except Exception:
                            in_scope = False
                    same_origin = self._is_same_origin(candidate, base_parsed)

                    if in_scope and (not self.config.same_origin_only or same_origin):
                        if candidate not in visited:
                            queue.append((candidate, depth + 1))
                    else:
                        out_of_scope_urls.add(candidate)

        duration = time.monotonic() - start_time
        return CrawlResult(
            target_url=start_url,
            pages_crawled=pages_crawled,
            urls_discovered=sorted(discovered_urls),
            endpoints=list(discovered_endpoints.values()),
            forms=discovered_forms,
            transactions=transactions,
            out_of_scope_urls=sorted(out_of_scope_urls),
            duration_seconds=duration,
            terminated_reason=terminated_reason,
        )
