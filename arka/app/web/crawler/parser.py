"""Safe HTML, Robots.txt, and Sitemap parsers with URL canonicalization.

Uses Python's standard library html.parser and defusedxml to ensure zero
native vulnerability exposure and defense against parser injection/XXE attacks.
"""

from __future__ import annotations

import posixpath
import re
import urllib.parse
from html.parser import HTMLParser
from typing import Any

import defusedxml.ElementTree as DefusedET

from arka.app.web.models.endpoint import DiscoveredForm, FormField
from arka.app.web.models.http import HTTPMethod


def canonicalize_url(raw_url: str, base_url: str) -> str | None:
    """Resolve and normalize a raw discovered URL against a base URL.

    Returns:
        Canonicalized URL string, or None if the URL is invalid or non-HTTP.
    """
    clean = raw_url.strip()
    if not clean or clean.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "blob:")):
        return None

    try:
        joined = urllib.parse.urljoin(base_url, clean)
        parsed = urllib.parse.urlparse(joined)
    except Exception:
        return None

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return None

    host = (parsed.hostname or "").lower()
    if not host:
        return None

    port = parsed.port
    # Omit default ports
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None

    netloc = host if port is None else f"{host}:{port}"

    # Normalize path: collapse duplicate slashes and resolve '.' and '..'
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"

    # Use posixpath.normpath to resolve traversals while preserving trailing slash if present
    ends_with_slash = path.endswith("/") and path != "/"
    norm_path = posixpath.normpath(path)
    if not norm_path.startswith("/"):
        norm_path = f"/{norm_path}"
    if ends_with_slash and not norm_path.endswith("/"):
        norm_path = f"{norm_path}/"

    # Deterministically sort query parameters
    query_parts = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    sorted_query = urllib.parse.urlencode(sorted(query_parts))

    # Drop fragment
    return urllib.parse.urlunparse((scheme, netloc, norm_path, "", sorted_query, ""))


class ParsedHTMLResult:
    """Structured extraction result from SafeHTMLParser."""

    def __init__(self) -> None:
        self.links: set[str] = set()
        self.forms: list[DiscoveredForm] = []
        self.scripts: set[str] = set()
        self.stylesheets: set[str] = set()
        self.meta_redirects: list[str] = []
        self.title: str = ""


class SafeHTMLParser(HTMLParser):
    """Robust, memory-safe HTML parser for links, forms, scripts, and meta tags."""

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.result = ParsedHTMLResult()
        self._in_title = False
        self._title_parts: list[str] = []
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = {k.lower(): v or "" for k, v in attrs}

        tag_lower = tag.lower()

        # Extract title
        if tag_lower == "title":
            self._in_title = True

        # Extract links: <a>, <area>
        elif tag_lower in ("a", "area"):
            href = attr_dict.get("href")
            if href:
                canon = canonicalize_url(href, self.base_url)
                if canon:
                    self.result.links.add(canon)

        # Extract scripts: <script src="...">
        elif tag_lower == "script":
            src = attr_dict.get("src")
            if src:
                canon = canonicalize_url(src, self.base_url)
                if canon:
                    self.result.scripts.add(canon)

        # Extract stylesheets / icons: <link href="...">
        elif tag_lower == "link":
            href = attr_dict.get("href")
            if href:
                canon = canonicalize_url(href, self.base_url)
                if canon:
                    self.result.stylesheets.add(canon)

        # Extract meta redirects: <meta http-equiv="refresh" content="...">
        elif tag_lower == "meta":
            http_equiv = attr_dict.get("http-equiv", "").lower()
            if http_equiv == "refresh":
                content = attr_dict.get("content", "")
                url_match = re.search(r"url=([^;]+)", content, re.IGNORECASE)
                if url_match:
                    raw_target = url_match.group(1).strip(" '\"")
                    canon = canonicalize_url(raw_target, self.base_url)
                    if canon:
                        self.result.meta_redirects.append(canon)

        # Extract forms: <form>
        elif tag_lower == "form":
            raw_action = attr_dict.get("action", "") or self.base_url
            canon_action = canonicalize_url(raw_action, self.base_url) or self.base_url
            raw_method = attr_dict.get("method", "GET").strip().upper()
            try:
                method = HTTPMethod(raw_method)
            except ValueError:
                method = HTTPMethod.GET

            self._current_form = {
                "action": canon_action,
                "method": method,
                "fields": [],
                "form_id": attr_dict.get("id"),
                "form_name": attr_dict.get("name"),
                "page_url": self.base_url,
            }

        # Extract form inputs: <input>, <textarea>, <select>, <button>
        elif (
            tag_lower in ("input", "textarea", "select", "button")
            and self._current_form is not None
        ):
            name = attr_dict.get("name")
            if name:
                field_type = attr_dict.get(
                    "type", "text" if tag_lower == "input" else tag_lower
                ).lower()
                is_required = "required" in attr_dict
                default_val = attr_dict.get("value")
                self._current_form["fields"].append(
                    FormField(
                        name=name,
                        field_type=field_type,
                        default_value=default_val,
                        required=is_required,
                    )
                )

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        if tag_lower == "title":
            self._in_title = False
            self.result.title = "".join(self._title_parts).strip()
        elif tag_lower == "form" and self._current_form is not None:
            self.result.forms.append(DiscoveredForm(**self._current_form))
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)


def parse_html_content(html_content: str, base_url: str) -> ParsedHTMLResult:
    """Safely parse HTML string and extract links, forms, scripts, and meta tags."""
    parser = SafeHTMLParser(base_url=base_url)
    parser.feed(html_content)
    # If unclosed form remained at end of document, commit it
    if parser._current_form is not None:
        parser.result.forms.append(DiscoveredForm(**parser._current_form))
    return parser.result


class RobotsTxtParser:
    """Parser for robots.txt files to discover application paths and boundaries."""

    @classmethod
    def parse(cls, content: str, base_url: str) -> dict[str, list[str]]:
        """Parse robots.txt content.

        Returns:
            dict with 'disallowed', 'allowed', and 'sitemaps' lists of URLs.
        """
        disallowed: list[str] = []
        allowed: list[str] = []
        sitemaps: list[str] = []

        for line in content.splitlines():
            clean = line.strip()
            if not clean or clean.startswith("#"):
                continue

            if ":" not in clean:
                continue

            directive, _, value = clean.partition(":")
            directive = directive.strip().lower()
            val = value.strip()

            if directive == "disallow" and val:
                canon = canonicalize_url(val, base_url)
                if canon:
                    disallowed.append(canon)
            elif directive == "allow" and val:
                canon = canonicalize_url(val, base_url)
                if canon:
                    allowed.append(canon)
            elif directive == "sitemap" and val:
                canon = canonicalize_url(val, base_url)
                if canon:
                    sitemaps.append(canon)

        return {
            "disallowed": disallowed,
            "allowed": allowed,
            "sitemaps": sitemaps,
        }


class SitemapXMLParser:
    """Parser for sitemap.xml files using defusedxml for XXE defense."""

    @classmethod
    def parse(cls, xml_content: str, base_url: str) -> list[str]:
        """Extract URLs from a sitemap XML payload safely."""
        urls: list[str] = []
        try:
            root = DefusedET.fromstring(xml_content)
            # Find all <loc> elements across standard namespaces
            for elem in root.iter():
                tag_clean = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                if tag_clean.lower() == "loc" and elem.text:
                    canon = canonicalize_url(elem.text.strip(), base_url)
                    if canon:
                        urls.append(canon)
        except Exception:
            pass
        return urls
