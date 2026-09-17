"""Unit tests for Phase 3.2 WebCrawler, SafeHTMLParser, and URL Canonicalization."""

import httpx
import pytest

from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import ScopeDefinition, ScopeTarget
from arka.app.web.client.client import ControlledHTTPClient
from arka.app.web.crawler.config import CrawlerConfig
from arka.app.web.crawler.crawler import WebCrawler
from arka.app.web.crawler.parser import (
    RobotsTxtParser,
    SitemapXMLParser,
    canonicalize_url,
    parse_html_content,
)
from arka.app.web.models.http import HTTPMethod


class TestURLCanonicalization:
    def test_relative_url_resolution(self):
        base = "http://example.com/dir/page.html"
        assert canonicalize_url("sub.html", base) == "http://example.com/dir/sub.html"
        assert canonicalize_url("/root.html", base) == "http://example.com/root.html"
        assert canonicalize_url("../parent.html", base) == "http://example.com/parent.html"

    def test_default_ports_omitted(self):
        assert (
            canonicalize_url("http://example.com:80/home", "http://example.com")
            == "http://example.com/home"
        )
        assert (
            canonicalize_url("https://example.com:443/login", "https://example.com")
            == "https://example.com/login"
        )
        assert (
            canonicalize_url("http://example.com:8080/test", "http://example.com")
            == "http://example.com:8080/test"
        )

    def test_duplicate_slashes_collapsed(self):
        assert (
            canonicalize_url("http://example.com///a//b///c", "http://example.com")
            == "http://example.com/a/b/c"
        )

    def test_deterministic_query_parameter_sorting(self):
        u1 = canonicalize_url("http://example.com/search?z=9&a=1&m=5", "http://example.com")
        u2 = canonicalize_url("http://example.com/search?a=1&m=5&z=9", "http://example.com")
        assert u1 == u2
        assert u1 == "http://example.com/search?a=1&m=5&z=9"

    def test_fragment_dropped(self):
        assert (
            canonicalize_url("http://example.com/page#section2", "http://example.com")
            == "http://example.com/page"
        )

    def test_non_http_schemes_filtered(self):
        assert canonicalize_url("javascript:alert(1)", "http://example.com") is None
        assert canonicalize_url("mailto:user@example.com", "http://example.com") is None
        assert canonicalize_url("tel:+123456789", "http://example.com") is None
        assert canonicalize_url("#anchor", "http://example.com") is None


class TestSafeHTMLParser:
    def test_parse_links_and_title(self):
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Test Page Title</title></head>
        <body>
            <a href="/about">About Us</a>
            <a href="https://example.com/contact">Contact</a>
            <a href="javascript:void(0)">Invalid</a>
            <script src="/js/app.js"></script>
            <link rel="stylesheet" href="/css/style.css">
        </body>
        </html>
        """
        res = parse_html_content(html, "http://example.com")
        assert res.title == "Test Page Title"
        assert "http://example.com/about" in res.links
        assert "https://example.com/contact" in res.links
        assert "http://example.com/js/app.js" in res.scripts
        assert "http://example.com/css/style.css" in res.stylesheets

    def test_parse_forms_and_inputs(self):
        html = """
        <form action="/login" method="POST" id="login-form">
            <input type="text" name="username" value="" required>
            <input type="password" name="password" required>
            <input type="hidden" name="csrf_token" value="abc123xyz">
            <button type="submit">Log In</button>
        </form>
        """
        res = parse_html_content(html, "http://example.com")
        assert len(res.forms) == 1
        form = res.forms[0]
        assert form.action == "http://example.com/login"
        assert form.method == HTTPMethod.POST
        assert len(form.fields) == 3
        names = {f.name: f for f in form.fields}
        assert "username" in names
        assert names["username"].required is True
        assert names["csrf_token"].default_value == "abc123xyz"

    def test_meta_refresh_extraction(self):
        html = '<meta http-equiv="refresh" content="5; url=/new-dashboard">'
        res = parse_html_content(html, "http://example.com")
        assert "http://example.com/new-dashboard" in res.meta_redirects


class TestRobotsAndSitemapParsers:
    def test_robots_parser(self):
        robots_txt = """
        User-agent: *
        Disallow: /admin/
        Disallow: /private/secret.html
        Allow: /public/
        Sitemap: http://example.com/sitemap.xml
        """
        parsed = RobotsTxtParser.parse(robots_txt, "http://example.com")
        assert "http://example.com/admin/" in parsed["disallowed"]
        assert "http://example.com/private/secret.html" in parsed["disallowed"]
        assert "http://example.com/public/" in parsed["allowed"]
        assert "http://example.com/sitemap.xml" in parsed["sitemaps"]

    def test_sitemap_parser(self):
        sitemap_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url><loc>http://example.com/</loc></url>
            <url><loc>http://example.com/catalog?item=1</loc></url>
        </urlset>
        """
        urls = SitemapXMLParser.parse(sitemap_xml, "http://example.com")
        assert "http://example.com/" in urls
        assert "http://example.com/catalog?item=1" in urls


class TestWebCrawlerExecution:
    @pytest.mark.asyncio
    async def test_crawler_bfs_and_limits(self):
        # Simulated website
        site_content = {
            "http://example.com/": (
                "<html><head><title>Home</title></head><body>"
                '<a href="/about">About</a><a href="/products">Products</a>'
                "</body></html>"
            ),
            "http://example.com/about": (
                "<html><head><title>About</title></head><body>"
                '<a href="/team">Team</a><a href="/external">Out</a>'
                "</body></html>"
            ),
            "http://example.com/products": (
                '<html><body><a href="/item?id=101">Item 101</a></body></html>'
            ),
            "http://example.com/item?id=101": "<html><body>Item details</body></html>",
            "http://example.com/team": "<html><body>Team page</body></html>",
            "http://example.com/robots.txt": "User-agent: *\nDisallow: /hidden\n",
            "http://example.com/hidden": "<html><body>Hidden Admin</body></html>",
        }

        async def mock_handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if url_str in site_content:
                return httpx.Response(
                    200, text=site_content[url_str], headers={"Content-Type": "text/html"}
                )
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(mock_handler)
        scope = ScopeDefinition(
            engagement_id="eng-crawl-1",
            includes=ScopeTarget(domains=["example.com"], ports=[80]),
        )
        guard = ScopeGuard(scope)
        client = ControlledHTTPClient(scope_guard=guard, transport=transport)

        config = CrawlerConfig(
            max_pages=10,
            max_depth=2,
            respect_robots_txt=True,
            same_origin_only=True,
        )
        crawler = WebCrawler(client=client, scope_guard=guard, config=config)

        res = await crawler.crawl("http://example.com/", engagement_id="eng-crawl-1")

        assert res.pages_crawled >= 3
        assert "http://example.com/" in res.urls_discovered
        assert "http://example.com/about" in res.urls_discovered
        assert "http://example.com/products" in res.urls_discovered
        assert len(res.endpoints) >= 3
        assert res.terminated_reason == "completed"
