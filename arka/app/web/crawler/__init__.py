"""Crawler package for ARKA Web Security."""

from arka.app.web.crawler.config import CrawlerConfig
from arka.app.web.crawler.crawler import CrawlResult, WebCrawler
from arka.app.web.crawler.parser import (
    ParsedHTMLResult,
    RobotsTxtParser,
    SafeHTMLParser,
    SitemapXMLParser,
    canonicalize_url,
    parse_html_content,
)

__all__ = [
    "CrawlResult",
    "CrawlerConfig",
    "ParsedHTMLResult",
    "RobotsTxtParser",
    "SafeHTMLParser",
    "SitemapXMLParser",
    "WebCrawler",
    "canonicalize_url",
    "parse_html_content",
]
