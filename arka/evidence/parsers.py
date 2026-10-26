"""
ARKA Quarantined Safe Parsers.

Implements:
- CTRL-PARSER-SANDBOX-001: Sandboxed Isolated Evidence Parsing
- TEST-EVIDENCE-PARSER-001: Evidence Parser Sandbox Containment Contract
- Neutralization of THREAT-EVIDENCE-PARSER-COMPROMISE (XXE, XML bombs, ReDoS)
"""

from abc import ABC, abstractmethod
from html.parser import HTMLParser
import io
import json
import logging
import re
from typing import Any, Dict, List, Optional, Set

import defusedxml.ElementTree as DefusedET
from defusedxml.common import DefusedXmlException

from .exceptions import EvidenceParserError, ParserBombError

logger = logging.getLogger("arka.evidence.parsers")

MAX_DEFAULT_PARSE_BYTES: int = 1024 * 1024  # 1 MB
MAX_RECURSION_DEPTH: int = 8


class SafeParser(ABC):
    """Abstract base class for safe, sandboxed parsers."""

    @abstractmethod
    def parse(self, raw_bytes: bytes, max_bytes: int = MAX_DEFAULT_PARSE_BYTES) -> Dict[str, Any]:
        """Parses raw bytes into structured data safely without host compromise."""
        pass


class SafeJsonParser(SafeParser):
    """
    Safe JSON parser enforcing payload bounds, maximum nesting depth, and duplicate key rejection.
    """

    def __init__(self, max_depth: int = MAX_RECURSION_DEPTH):
        self.max_depth = max_depth

    def parse(self, raw_bytes: bytes, max_bytes: int = MAX_DEFAULT_PARSE_BYTES) -> Dict[str, Any]:
        if len(raw_bytes) > max_bytes:
            raise EvidenceParserError(
                f"JSON payload size {len(raw_bytes)} bytes exceeds limit {max_bytes} bytes."
            )

        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as e:
            raise EvidenceParserError(f"Invalid UTF-8 encoding in JSON evidence: {e}") from e

        # Iterative depth-tracking traversal to avoid Python call stack recursion limits
        def check_depth(root: Any) -> None:
            stack = [(root, 0)]
            while stack:
                obj, current_depth = stack.pop()
                if current_depth > self.max_depth:
                    raise ParserBombError(
                        f"JSON nesting depth exceeds maximum allowable depth ({self.max_depth})."
                    )
                if isinstance(obj, dict):
                    for v in obj.values():
                        stack.append((v, current_depth + 1))
                elif isinstance(obj, list):
                    for item in obj:
                        stack.append((item, current_depth + 1))

        def reject_duplicates(ordered_pairs: List[tuple]) -> Dict[str, Any]:
            d: Dict[str, Any] = {}
            for k, v in ordered_pairs:
                if k in d:
                    raise EvidenceParserError(f"Duplicate JSON key rejected: {k}")
                d[k] = v
            return d

        try:
            data = json.loads(text, object_pairs_hook=reject_duplicates)
        except RecursionError as e:
            raise ParserBombError(f"JSON recursion depth exceeded parser limit: {e}") from e
        except json.JSONDecodeError as e:
            raise EvidenceParserError(f"Malformed JSON syntax: {e}") from e

        check_depth(data)
        if isinstance(data, dict):
            return data
        return {"items": data}


class SafeXmlParser(SafeParser):
    """
    Hardened XML parser utilizing defusedxml.
    
    Neutralizes:
    - XML External Entity (XXE) attacks
    - Billion Laughs / quadratic entity expansion bombs
    - DTD retrieval
    """

    def __init__(self, max_depth: int = MAX_RECURSION_DEPTH):
        self.max_depth = max_depth

    def parse(self, raw_bytes: bytes, max_bytes: int = MAX_DEFAULT_PARSE_BYTES) -> Dict[str, Any]:
        if len(raw_bytes) > max_bytes:
            raise EvidenceParserError(
                f"XML payload size {len(raw_bytes)} bytes exceeds limit {max_bytes} bytes."
            )

        try:
            # Parse with defusedxml (blocks entities, DTDs, and expansion bombs)
            root = DefusedET.fromstring(raw_bytes)
        except DefusedXmlException as e:
            raise ParserBombError(f"XML security policy violation (bomb or entity detected): {e}") from e
        except Exception as e:
            raise EvidenceParserError(f"Malformed XML syntax: {e}") from e

        def element_to_dict(elem: Any, current_depth: int = 0) -> Dict[str, Any]:
            if current_depth > self.max_depth:
                raise ParserBombError(
                    f"XML element depth exceeds maximum allowable depth ({self.max_depth})."
                )

            node: Dict[str, Any] = {"tag": elem.tag}
            if elem.attrib:
                node["attrib"] = dict(elem.attrib)
            if elem.text and elem.text.strip():
                node["text"] = elem.text.strip()

            children: List[Dict[str, Any]] = []
            for child in elem:
                children.append(element_to_dict(child, current_depth + 1))
            if children:
                node["children"] = children

            return node

        return element_to_dict(root)


class NmapXmlParser(SafeParser):
    """
    Safely extracts open ports, protocols, and services from Nmap XML outputs.
    """

    def __init__(self):
        self._xml_parser = SafeXmlParser(max_depth=12)

    def parse(self, raw_bytes: bytes, max_bytes: int = MAX_DEFAULT_PARSE_BYTES) -> Dict[str, Any]:
        tree = self._xml_parser.parse(raw_bytes, max_bytes=max_bytes)

        hosts_found: List[Dict[str, Any]] = []

        def find_hosts(node: Dict[str, Any]) -> None:
            if node.get("tag") == "host":
                host_info: Dict[str, Any] = {"addresses": [], "ports": []}
                for child in node.get("children", []):
                    if child.get("tag") == "address":
                        addr = child.get("attrib", {}).get("addr")
                        if addr:
                            host_info["addresses"].append(addr)
                    elif child.get("tag") == "ports":
                        for port_elem in child.get("children", []):
                            if port_elem.get("tag") == "port":
                                attrib = port_elem.get("attrib", {})
                                port_id = int(attrib.get("portid", 0))
                                protocol = attrib.get("protocol", "tcp")
                                state = "unknown"
                                service_name = "unknown"
                                for pchild in port_elem.get("children", []):
                                    if pchild.get("tag") == "state":
                                        state = pchild.get("attrib", {}).get("state", "unknown")
                                    elif pchild.get("tag") == "service":
                                        service_name = pchild.get("attrib", {}).get("name", "unknown")
                                host_info["ports"].append(
                                    {
                                        "port": port_id,
                                        "protocol": protocol,
                                        "state": state,
                                        "service": service_name,
                                    }
                                )
                hosts_found.append(host_info)

            for child in node.get("children", []):
                find_hosts(child)

        find_hosts(tree)
        return {"nmap_hosts": hosts_found}


class SafeHtmlParser(SafeParser):
    """
    Strict HTML parser stripping scripts, embedded objects, and styles.
    """

    class _InternalHtmlParser(HTMLParser):
        FORBIDDEN_TAGS: Set[str] = {"script", "style", "object", "embed", "iframe"}

        def __init__(self):
            super().__init__()
            self.title: Optional[str] = None
            self.links: List[str] = []
            self.forms: List[Dict[str, str]] = []
            self.headings: List[str] = []
            self._in_title = False
            self._skip_data = False

        def handle_starttag(self, tag: str, attrs: List[tuple]):
            tag_lower = tag.lower()
            if tag_lower in self.FORBIDDEN_TAGS:
                self._skip_data = True
                return

            if tag_lower == "title":
                self._in_title = True
            elif tag_lower == "a":
                for k, v in attrs:
                    if k.lower() == "href" and v:
                        self.links.append(v)
            elif tag_lower == "form":
                form_meta = {k.lower(): v for k, v in attrs if v}
                self.forms.append(form_meta)
            elif tag_lower in ("h1", "h2", "h3"):
                pass

        def handle_endtag(self, tag: str):
            tag_lower = tag.lower()
            if tag_lower in self.FORBIDDEN_TAGS:
                self._skip_data = False
            elif tag_lower == "title":
                self._in_title = False

        def handle_data(self, data: str):
            if self._skip_data:
                return
            if self._in_title and not self.title:
                self.title = data.strip()

    def parse(self, raw_bytes: bytes, max_bytes: int = MAX_DEFAULT_PARSE_BYTES) -> Dict[str, Any]:
        if len(raw_bytes) > max_bytes:
            raise EvidenceParserError(
                f"HTML payload size {len(raw_bytes)} bytes exceeds limit {max_bytes} bytes."
            )

        text = raw_bytes.decode("utf-8", errors="replace")
        parser = self._InternalHtmlParser()
        try:
            parser.feed(text)
        except Exception as e:
            raise EvidenceParserError(f"HTML parsing failure: {e}") from e

        return {
            "title": parser.title,
            "links_count": len(parser.links),
            "links": parser.links[:50],  # Bounded sample
            "forms_count": len(parser.forms),
            "forms": parser.forms,
        }


class HttpOutputParser(SafeParser):
    """
    Safely parses raw HTTP response byte streams into headers and bounded content.
    """

    def parse(self, raw_bytes: bytes, max_bytes: int = MAX_DEFAULT_PARSE_BYTES) -> Dict[str, Any]:
        if len(raw_bytes) > max_bytes:
            bounded_bytes = raw_bytes[:max_bytes]
            truncated = True
        else:
            bounded_bytes = raw_bytes
            truncated = False

        text = bounded_bytes.decode("utf-8", errors="replace")
        parts = text.split("\r\n\r\n", 1)
        if len(parts) == 1:
            parts = text.split("\n\n", 1)

        headers_part = parts[0]
        body_part = parts[1] if len(parts) > 1 else ""

        header_lines = headers_part.splitlines()
        status_code = 0
        status_message = ""
        headers: Dict[str, str] = {}

        if header_lines:
            status_match = re.match(r"HTTP/\d\.\d\s+(\d+)\s*(.*)", header_lines[0])
            if status_match:
                status_code = int(status_match.group(1))
                status_message = status_match.group(2).strip()

            for line in header_lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

        return {
            "status_code": status_code,
            "status_message": status_message,
            "headers": headers,
            "body_length": len(body_part),
            "body_preview": body_part[:1024],
            "truncated": truncated,
        }
