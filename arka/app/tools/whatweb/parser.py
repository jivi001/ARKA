"""WhatWeb output parser for ARKA.

Parses WhatWeb JSON output into structured WhatWebResult models.
"""

from __future__ import annotations

import json
import logging

from arka.app.tools.whatweb.schemas import WhatWebPlugin, WhatWebResult, WhatWebTarget

logger = logging.getLogger(__name__)


def parse_whatweb_json(raw_output: str, target: str = "") -> WhatWebResult:
    """Parse WhatWeb JSON output into WhatWebResult."""
    clean_text = raw_output.strip()
    if not clean_text:
        return WhatWebResult(success=True, targets=[], raw_json="")

    targets: list[WhatWebTarget] = []

    try:
        data = json.loads(clean_text)
        if isinstance(data, dict):
            data = [data]
        elif not isinstance(data, list):
            data = []
    except json.JSONDecodeError:
        # Try line by line
        data = []
        for line in clean_text.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            try:
                item = json.loads(line_str)
                if isinstance(item, dict):
                    data.append(item)
            except json.JSONDecodeError:
                pass

    for entry in data:
        if not isinstance(entry, dict):
            continue
        entry_target = str(entry.get("target") or target)
        http_status = int(entry.get("http_status") or 200)
        raw_plugins = entry.get("plugins") or {}
        plugins: dict[str, WhatWebPlugin] = {}

        if isinstance(raw_plugins, dict):
            for plug_name, plug_val in raw_plugins.items():
                if not isinstance(plug_val, dict):
                    continue
                # versions
                ver_raw = plug_val.get("version") or []
                versions = (
                    [str(v) for v in ver_raw]
                    if isinstance(ver_raw, list)
                    else [str(ver_raw)]
                    if ver_raw
                    else []
                )

                # strings
                str_raw = plug_val.get("string") or []
                strings = (
                    [str(s) for s in str_raw]
                    if isinstance(str_raw, list)
                    else [str(str_raw)]
                    if str_raw
                    else []
                )

                # cpe
                cpe_raw = plug_val.get("cpe") or []
                cpes = (
                    [str(c) for c in cpe_raw]
                    if isinstance(cpe_raw, list)
                    else [str(cpe_raw)]
                    if cpe_raw
                    else []
                )

                plugins[plug_name] = WhatWebPlugin(
                    name=plug_name,
                    version=versions,
                    string=strings,
                    cpe=cpes,
                )

        targets.append(
            WhatWebTarget(
                target=entry_target,
                http_status=http_status,
                plugins=plugins,
            )
        )

    return WhatWebResult(
        success=True,
        targets=targets,
        raw_json=clean_text,
        metadata={"target_count": len(targets)},
    )
