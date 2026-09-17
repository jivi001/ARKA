"""Configuration and safety bounds for ARKA Hardened Web Crawler."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class CrawlerConfig(BaseModel):
    """Safety bounds and runtime policy for WebCrawler."""

    model_config = ConfigDict(frozen=True)

    max_pages: int = Field(default=50, ge=1, le=200, description="Max HTML pages to fetch")
    max_depth: int = Field(default=3, ge=0, le=10, description="Max BFS crawl depth from root")
    max_requests: int = Field(
        default=100, ge=1, le=500, description="Hard cap on total HTTP requests"
    )
    max_response_size: int = Field(
        default=2_097_152, ge=1024, le=10_485_760, description="Max bytes per response (2MB)"
    )
    max_redirects: int = Field(default=5, ge=0, le=10, description="Max redirects per request")
    max_concurrency: int = Field(default=3, ge=1, le=10, description="Max concurrent request tasks")
    request_timeout: float = Field(
        default=10.0, ge=0.5, le=60.0, description="Per-request timeout in seconds"
    )
    crawl_timeout: float = Field(
        default=120.0, ge=5.0, le=600.0, description="Overall crawl timeout in seconds"
    )
    same_origin_only: bool = Field(
        default=True, description="Strictly limit crawl to the starting scheme://host:port"
    )
    allow_subdomains: bool = Field(
        default=False, description="Allow crawling subdomains if permitted by scope"
    )
    respect_robots_txt: bool = Field(
        default=True, description="Parse robots.txt to discover hidden paths and boundaries"
    )
    parse_sitemap: bool = Field(
        default=True, description="Attempt to parse sitemap.xml if referenced or found"
    )
    user_agent: str = Field(
        default="ARKA-Security-Scanner/0.3.0 (+https://github.com/jivi001/ARKA)",
        description="Outbound User-Agent header",
    )
