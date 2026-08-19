# Multimodal Architecture

ARKA supports multimodal context ingestion (screenshots, network diagrams, HTTP responses, and HTML) to enable visual and artifact-driven security analysis.

---

## 1. Multimodal Content Schema

Messages in `LLMRequest` can contain multiple parts represented by `MultimodalContent` (`arka/app/llm/schemas/llm_schemas.py`):

```python
class ContentType(str, Enum):
    TEXT = "text"
    IMAGE = "image"
    HTML = "html"
    JSON = "json"
    TERMINAL_OUTPUT = "terminal_output"
    HTTP_RESPONSE = "http_response"


class MultimodalContent(BaseModel):
    content_type: ContentType
    text: str | None = None
    media_url: str | None = None
    media_base64: str | None = None
    mime_type: str | None = None  # e.g., "image/png"
```

---

## 2. Gateway Serialization

In `LLMGateway.complete()`, multimodal content is serialized into provider-compatible structures:

- **Text / Terminal / HTTP Response**: Converted to standard text parts:
  ```json
  {"type": "text", "text": "..."}
  ```
- **Remote Image URLs**: Formatted as:
  ```json
  {"type": "image_url", "image_url": {"url": "https://example.com/diagram.png"}}
  ```
- **Base64 Embedded Images**: Serialized as inline data URLs:
  ```json
  {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw..."}}
  ```
