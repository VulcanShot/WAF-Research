#!/usr/bin/env python3
"""Placeholder resolver for CVE-2026-41242 (protobuf.js type-name code injection).

Supplies the request-body transforms that cannot be written literally in the
traffic corpus. Each ``<<TOKEN>>`` placeholder found in a corpus body maps to one
branch of :func:`resolve`.
"""

from __future__ import annotations

import gzip


def resolve(token, context):
    """Resolves one ``<<TOKEN>>`` placeholder from the protobuf.js traffic corpus.

    @param token Inner text of the placeholder, without the surrounding brackets.
    @param context Runner-supplied accessor over the parsed corpus and its requests.
    @returns The replacement body: ``str`` for text tokens, ``bytes`` for binary ones.
    @raises ValueError When the token is not recognised for this vulnerability.
    """
    if token == "GZIP_OF_E1_JSON_BODY":
        json_body = context.first_exploit_json_body()
        return gzip.compress(json_body.encode("utf-8"))
    raise ValueError(f"Unknown placeholder token for CVE-2026-41242: {token!r}")
