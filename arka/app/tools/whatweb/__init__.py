"""WhatWeb technology fingerprinter adapter for ARKA."""

from arka.app.tools.whatweb.definition import (
    WhatWebToolDefinition,
    get_whatweb_tool_definition,
    register_whatweb_tool,
)
from arka.app.tools.whatweb.executor import WhatWebToolExecutor
from arka.app.tools.whatweb.parser import parse_whatweb_json
from arka.app.tools.whatweb.schemas import (
    WhatWebPlugin,
    WhatWebResult,
    WhatWebScanConfig,
    WhatWebTarget,
)

__all__ = [
    "WhatWebPlugin",
    "WhatWebResult",
    "WhatWebScanConfig",
    "WhatWebTarget",
    "WhatWebToolDefinition",
    "WhatWebToolExecutor",
    "get_whatweb_tool_definition",
    "parse_whatweb_json",
    "register_whatweb_tool",
]
