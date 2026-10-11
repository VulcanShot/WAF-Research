#!/usr/bin/env python3
"""Placeholder resolver for CVE-2025-3248 (Langflow /api/v1/validate/code RCE).

Supplies the request-body transforms that cannot be written literally in the
traffic corpus. Each ``<<TOKEN>>`` placeholder found in a corpus body maps to one
branch of :func:`resolve`.
"""

from __future__ import annotations

import gzip

SINK_MARKER = "SINK_REACHED"


def resolve(token, context):
    """Resolves one ``<<TOKEN>>`` placeholder from the Langflow traffic corpus.

    @param token Inner text of the placeholder, without the surrounding brackets.
    @param context Runner-supplied accessor over the parsed corpus and its requests.
    @returns The replacement body: ``str`` for text tokens, ``bytes`` for binary ones.
    @raises ValueError When the token is not recognised for this vulnerability.
    """
    if token == "GZIP_OF_SINK_EXPLOIT_BODY":
        json_body = _first_sink_exploit_body(context)
        return gzip.compress(json_body.encode("utf-8"))
    raise ValueError(f"Unknown placeholder token for CVE-2025-3248: {token!r}")


def _first_sink_exploit_body(context):
    """Returns the earliest literal JSON exploit body carrying the sink marker.

    @param context Runner-supplied accessor over the corpus requests.
    @returns The raw JSON body whose execution surfaces the sink marker, so the
        compressed copy confirms the sink when the WAF lets it through.
    """
    for request in context.requests:
        if not request.is_exploit:
            continue
        if SINK_MARKER in request.body:
            return request.body
    return context.first_exploit_json_body()
