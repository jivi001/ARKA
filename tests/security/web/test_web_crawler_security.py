"""Security tests for Phase 3.2 WebCrawler.

Verifies:
- Crawler immunity to hostile links (localhost, cloud metadata, attacker domains)
- Scope re-validation: discovering untrusted links NEVER grants authorization or executes fetches
- Defense against crawler infinite loops and recursive query explosion
- Defense against oversized HTML responses
"""

import httpx
import pytest

from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import ScopeDefinition, ScopeTarget
from arka.app.web.client.client import ControlledHTTPClient
from arka.app.web.crawler.config import CrawlerConfig
from arka.app.web.crawler.crawler import WebCrawler


@pytest.fixture
def target_scope():
    scope = ScopeDefinition(
        engagement_id="eng-crawler-sec",
        includes=ScopeTarget(domains=["target.example.com"], ports=[80, 443]),
        excludes=ScopeTarget(domains=["private.target.example.com"]),
    )
    return ScopeGuard(scope)


class TestCrawlerSecurityInvariants:
    @pytest.mark.asyncio
    async def test_hostile_html_with_ssrf_links_is_never_fetched(self, target_scope):
        """Hostile HTML containing links to metadata, localhost, and internal IPs."""
        hostile_html = """
        <html>
        <body>
            <h1>Welcome to Target</h1>
            <!-- Malicious links attempting SSRF and scope escape -->
            <a href="http://169.254.169.254/latest/meta-data/">Cloud Metadata</a>
            <a href="http://127.0.0.1:8080/admin">Localhost Admin</a>
            <a href="http://localhost:3000/">Localhost Juice Shop</a>
            <a href="http://10.0.0.1/internal">Private Router</a>
            <a href="http://attacker.com/steal">Attacker</a>
            <a href="http://private.target.example.com/vault">Excluded Subdomain</a>
            <a href="http://target.example.com/legit">Legitimate Link</a>
        </body>
        </html>
        """

        fetched_urls: list[str] = []

        async def mock_handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            fetched_urls.append(url_str)
            if url_str == "http://target.example.com/":
                return httpx.Response(200, text=hostile_html, headers={"Content-Type": "text/html"})
            if url_str == "http://target.example.com/legit":
                return httpx.Response(
                    200,
                    text="<html><body>Legit</body></html>",
                    headers={"Content-Type": "text/html"},
                )
            return httpx.Response(200, text="Untrusted target fetched!")

        transport = httpx.MockTransport(mock_handler)
        client = ControlledHTTPClient(scope_guard=target_scope, transport=transport)
        crawler = WebCrawler(
            client=client,
            scope_guard=target_scope,
            config=CrawlerConfig(max_pages=10, same_origin_only=True),
        )

        result = await crawler.crawl("http://target.example.com/", engagement_id="eng-crawler-sec")

        # Verify ONLY legitimate in-scope target URLs were fetched
        assert "http://target.example.com/" in fetched_urls
        assert "http://target.example.com/legit" in fetched_urls
        assert "http://169.254.169.254/latest/meta-data/" not in fetched_urls
        assert "http://127.0.0.1:8080/admin" not in fetched_urls
        assert "http://attacker.com/steal" not in fetched_urls
        assert "http://private.target.example.com/vault" not in fetched_urls

        # Verify malicious links are recorded as out-of-scope discoveries
        assert any("169.254.169.254" in u for u in result.out_of_scope_urls)
        assert any("attacker.com" in u for u in result.out_of_scope_urls)

    @pytest.mark.asyncio
    async def test_circular_link_infinite_loop_defense(self, target_scope):
        """Pages linking back and forth to each other (A -> B -> A) must not cause infinite loop."""

        async def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "page_a" in url:
                return httpx.Response(
                    200,
                    text='<html><body><a href="/page_b">B</a></body></html>',
                    headers={"Content-Type": "text/html"},
                )
            if "page_b" in url:
                return httpx.Response(
                    200,
                    text='<html><body><a href="/page_a">A</a></body></html>',
                    headers={"Content-Type": "text/html"},
                )
            return httpx.Response(
                200,
                text='<html><body><a href="/page_a">A</a></body></html>',
                headers={"Content-Type": "text/html"},
            )

        transport = httpx.MockTransport(mock_handler)
        client = ControlledHTTPClient(scope_guard=target_scope, transport=transport)
        crawler = WebCrawler(
            client=client,
            scope_guard=target_scope,
            config=CrawlerConfig(max_pages=20, max_depth=5),
        )

        res = await crawler.crawl("http://target.example.com/", engagement_id="eng-crawler-sec")
        # Crawl completes once all 3 unique URLs (root, page_a, page_b) are visited
        assert res.pages_crawled <= 3
        assert res.terminated_reason == "completed"

    @pytest.mark.asyncio
    async def test_oversized_response_defense(self, target_scope):
        """Giant response does not exhaust memory and is truncated safely."""
        giant_body = "<html><body>" + ("<p>Text</p>" * 500_000) + "</body></html>"  # ~6MB

        async def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text=giant_body, headers={"Content-Type": "text/html"})

        transport = httpx.MockTransport(mock_handler)
        client = ControlledHTTPClient(
            scope_guard=target_scope,
            max_response_size=500_000,  # 500 KB limit
            transport=transport,
        )
        crawler = WebCrawler(
            client=client,
            scope_guard=target_scope,
            config=CrawlerConfig(max_pages=2),
        )

        res = await crawler.crawl("http://target.example.com/", engagement_id="eng-crawler-sec")
        assert res.pages_crawled == 1
        assert res.transactions[0].response.truncated is True
