#!/usr/bin/env python3
"""Replays a traffic.yaml corpus against a target and reports WAF effectiveness.

Reads a corpus of HTTP requests (exploit and benign), resolves any ``<<TOKEN>>``
body placeholders through a per-vulnerability resolver script, sends each request
at the target, and classifies the outcome: exploits should be blocked by the WAF
and benign traffic should pass. Exit status is non-zero when any request fails
that expectation or errors.

Usage:
    python runner.py CORPUS.yaml --target http://host [--resolver PATH]
                     [--format table|markdown|json] [--output-file PATH]
                     [--filter exploit|benign|all]
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import requests
import urllib3
import yaml

from report import render

urllib3.disable_warnings()

REQUEST_TIMEOUT_SECONDS = 30
SINK_MARKER = "SINK_REACHED"
WAF_BLOCK_STATUS = 403
RESPONSE_PREVIEW_LIMIT = 300
PLACEHOLDER_PATTERN = re.compile(r"<<\s*([^<>]+?)\s*>>")
YAML_FORBIDDEN_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x84\x86-\x9f]")


@dataclass
class CorpusRequest:
    """One HTTP request drawn from a corpus flow, before placeholder resolution."""

    flow_source: str
    method: str
    route: str
    query_string: str
    headers: dict
    body: str
    is_exploit: bool


@dataclass
class ResolveContext:
    """Accessor passed to a resolver so it can read the corpus and sibling requests."""

    corpus: dict
    requests: list
    current: CorpusRequest

    def first_exploit_json_body(self):
        """Returns the body of the first JSON exploit request holding a literal body.

        @returns The raw JSON body string of the earliest exploit request whose
            Content-Type is JSON and whose body carries no placeholder.
        @raises LookupError When the corpus contains no such request.
        """
        for request in self.requests:
            if not request.is_exploit:
                continue
            content_type = _header_value(request.headers, "content-type") or ""
            if "application/json" not in content_type.lower():
                continue
            if PLACEHOLDER_PATTERN.search(request.body):
                continue
            return request.body
        raise LookupError("No literal JSON exploit request found in the corpus")


@dataclass
class RequestResult:
    """Outcome of sending one corpus request, with its WAF-effectiveness verdict."""

    request: CorpusRequest
    url: str
    status: int | None
    blocked: bool
    sink_reached: bool
    verdict: str
    classification: str
    note: str
    response_preview: str = ""

    def to_dict(self):
        """Serialises the result into the flat shape the renderers consume."""
        return {
            "flow_source": self.request.flow_source,
            "method": self.request.method,
            "route": self.request.route,
            "is_exploit": self.request.is_exploit,
            "url": self.url,
            "status": self.status,
            "blocked": self.blocked,
            "sink_reached": self.sink_reached,
            "verdict": self.verdict,
            "classification": self.classification,
            "note": self.note,
            "response_preview": self.response_preview,
        }


def _header_value(headers, name):
    """Returns a header value by case-insensitive name, or ``None`` when absent."""
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def load_corpus(path):
    """Parses a traffic corpus YAML file into its raw mapping.

    Control characters that YAML forbids in its stream are dropped before parsing,
    so a stray control byte in a comment does not reject the document; payload
    control bytes belong in bodies as escape sequences, which are plain text here.
    """
    text = YAML_FORBIDDEN_CONTROL.sub("", path.read_text(encoding="utf-8"))
    return yaml.safe_load(text)


def flatten_requests(corpus):
    """Flattens the corpus flows into an ordered list of :class:`CorpusRequest`."""
    flattened = []
    for flow in corpus.get("flows", []) or []:
        source = flow.get("source", "unknown")
        for raw in flow.get("requests", []) or []:
            flattened.append(CorpusRequest(
                flow_source=source,
                method=str(raw.get("method", "GET")).upper(),
                route=raw.get("route", "/"),
                query_string=raw.get("query_string", "") or "",
                headers=dict(raw.get("headers", {}) or {}),
                body=raw.get("body", "") or "",
                is_exploit=bool(raw.get("is_exploit", False)),
            ))
    return flattened


def default_resolver_path(corpus, base_dir):
    """Derives the resolver path from the corpus ``vuln_id`` by naming convention.

    @param corpus Parsed corpus mapping, read for its ``vuln_id``.
    @param base_dir Directory holding the ``resolvers`` package.
    @returns The resolver path when the conventional file exists, else ``None``.
    """
    vuln_id = corpus.get("vuln_id")
    if not vuln_id:
        return None
    normalized = re.sub(r"[^0-9a-z]+", "_", str(vuln_id).lower()).strip("_")
    candidate = base_dir / "resolvers" / f"{normalized}.py"
    return candidate if candidate.exists() else None


def load_resolver(resolver_path):
    """Imports a resolver script and returns its module.

    @param resolver_path Filesystem path to the resolver script.
    @returns The imported module, guaranteed to expose a ``resolve`` callable.
    @raises AttributeError When the module defines no ``resolve`` function.
    """
    spec = importlib.util.spec_from_file_location("waf_traffic_resolver", resolver_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "resolve"):
        raise AttributeError(f"Resolver {resolver_path} defines no resolve(token, context)")
    return module


def resolve_body(request, resolver, context):
    """Resolves every ``<<TOKEN>>`` placeholder in a request body.

    A body that is exactly one placeholder may resolve to ``bytes`` (needed for a
    binary payload such as gzip); an inline placeholder must resolve to ``str``.

    @param request The corpus request whose body is being resolved.
    @param resolver The resolver module, or ``None`` when no placeholders appear.
    @param context The :class:`ResolveContext` bound to this request.
    @returns The resolved body as ``str`` or ``bytes``.
    @raises RuntimeError When a placeholder is present but no resolver was supplied.
    @raises TypeError When an inline placeholder resolves to ``bytes``.
    """
    body = request.body
    matches = list(PLACEHOLDER_PATTERN.finditer(body))
    if not matches:
        return body
    if resolver is None:
        raise RuntimeError(f"Body for {request.route} needs a resolver but none was found")
    if len(matches) == 1 and matches[0].group(0) == body.strip():
        return resolver.resolve(matches[0].group(1), context)

    def substitute(match):
        value = resolver.resolve(match.group(1), context)
        if isinstance(value, bytes):
            raise TypeError("Inline placeholder resolved to bytes; only a whole-body placeholder may be binary")
        return value

    return PLACEHOLDER_PATTERN.sub(substitute, body)


def build_url(target, request):
    """Joins the target base URL, route, and query string into a full request URL."""
    url = target.rstrip("/") + request.route
    if request.query_string:
        url += "?" + request.query_string
    return url


def _apply_host_override(headers, target):
    """Returns a copy of headers with the Host set to the target netloc."""
    overridden = {key: value for key, value in headers.items() if key.lower() != "host"}
    overridden["Host"] = urlsplit(target).netloc
    return overridden


def classify(request, blocked, sink_reached, error):
    """Decides the verdict, confusion-matrix class, and note for one outcome.

    @param request The corpus request that was sent.
    @param blocked Whether the WAF blocked the request.
    @param sink_reached Whether the exploit sink marker appeared in the response.
    @param error A transport error string, or ``None`` on a completed request.
    @returns A ``(verdict, classification, note)`` tuple.
    """
    if error is not None:
        return "ERROR", "ERROR", f"request error: {error}"
    if request.is_exploit:
        if blocked:
            return "PASS", "TP", "exploit blocked by WAF"
        note = "exploit passed the WAF"
        if sink_reached:
            note += " - RCE confirmed (sink reached)"
            return "FAIL", "FN", note
        return "INVESTIGATE", "FN", note
    if blocked:
        return "FAIL", "FP", "benign request blocked (false positive)"
    return "PASS", "TN", "benign request allowed"


def send_request(target, request, body, session):
    """Sends one resolved request and classifies its WAF-effectiveness outcome.

    @param target Base URL of the target host.
    @param request The corpus request being sent.
    @param body The resolved request body, ``str`` or ``bytes``.
    @param session A :class:`requests.Session` reused across the run.
    @returns The :class:`RequestResult` for this request.
    """
    url = build_url(target, request)
    headers = _apply_host_override(request.headers, target)
    data = body.encode("utf-8") if isinstance(body, str) else body
    try:
        response = session.request(
            request.method, url, headers=headers, data=data,
            timeout=REQUEST_TIMEOUT_SECONDS, verify=False, allow_redirects=False,
        )
    except requests.RequestException as error:
        verdict, classification, note = classify(request, False, False, str(error))
        return RequestResult(request, url, None, False, False, verdict, classification, note)

    blocked = response.status_code == WAF_BLOCK_STATUS
    sink_reached = SINK_MARKER in response.text
    verdict, classification, note = classify(request, blocked, sink_reached, None)
    preview = response.text[:RESPONSE_PREVIEW_LIMIT]
    return RequestResult(request, url, response.status_code, blocked, sink_reached,
                         verdict, classification, note, preview)


def _rate(numerator, denominator):
    """Formats a count over a total as ``n/total (pp%)`` for the summary."""
    if denominator == 0:
        return "0/0 (n/a)"
    return f"{numerator}/{denominator} ({numerator / denominator:.0%})"


def build_report(corpus, target, results):
    """Assembles the structured report from the per-request results.

    @param corpus Parsed corpus mapping, read for its ``vuln_id``.
    @param target Base URL the requests were sent to.
    @param results The list of :class:`RequestResult` produced by the run.
    @returns A report mapping with ``summary`` and ``results`` keys.
    """
    counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "ERROR": 0}
    for result in results:
        counts[result.classification] += 1
    exploits = [result for result in results if result.request.is_exploit]
    benign = [result for result in results if not result.request.is_exploit]
    exploit_blocked = sum(1 for result in exploits if not result.sink_reached)
    benign_allowed = sum(1 for result in benign if not result.blocked and result.status is not None)
    overall = "PASS" if all(result.verdict == "PASS" for result in results) and results else "FAIL"

    summary = {
        "vuln_id": corpus.get("vuln_id", "unknown"),
        "target": target,
        "host_override": urlsplit(target).netloc,
        "total": len(results),
        "exploit_count": len(exploits),
        "benign_count": len(benign),
        "exploit_block_rate": _rate(exploit_blocked, len(exploits)),
        "benign_pass_rate": _rate(benign_allowed, len(benign)),
        "counts": counts,
        "overall": overall,
    }
    return {"summary": summary, "results": [result.to_dict() for result in results]}


def _select(requests_list, which):
    """Filters requests by exploit or benign, or returns all of them."""
    if which == "all":
        return requests_list
    want_exploit = which == "exploit"
    return [request for request in requests_list if request.is_exploit == want_exploit]


def run(corpus_path, target, resolver_path, selection):
    """Loads a corpus, replays the selected requests, and returns the report.

    @param corpus_path Path to the traffic corpus YAML.
    @param target Base URL of the target host.
    @param resolver_path Explicit resolver path, or ``None`` to auto-discover.
    @param selection One of ``"exploit"``, ``"benign"``, or ``"all"``.
    @returns The structured report mapping.
    """
    corpus = load_corpus(corpus_path)
    all_requests = flatten_requests(corpus)
    base_dir = Path(__file__).resolve().parent
    resolver_path = resolver_path or default_resolver_path(corpus, base_dir)
    resolver = load_resolver(resolver_path) if resolver_path else None

    session = requests.Session()
    results = []
    for request in _select(all_requests, selection):
        context = ResolveContext(corpus=corpus, requests=all_requests, current=request)
        try:
            body = resolve_body(request, resolver, context)
        except Exception as error:
            verdict, classification, note = classify(request, False, False, str(error))
            results.append(RequestResult(request, build_url(target, request), None,
                                         False, False, verdict, classification, note))
            continue
        results.append(send_request(target, request, body, session))
    return build_report(corpus, target, results)


def main(argv=None):
    """Parses arguments, runs the corpus, renders the report, and sets exit status."""
    parser = argparse.ArgumentParser(
        description="Replay a traffic.yaml corpus against a target and report WAF effectiveness.")
    parser.add_argument("corpus", type=Path, help="Path to the traffic corpus YAML file")
    parser.add_argument("--target", required=True,
                        help="Base URL of the target, e.g. http://my-alb-123.elb.amazonaws.com")
    parser.add_argument("--resolver", type=Path,
                        help="Per-vulnerability placeholder resolver script (auto-discovered by default)")
    parser.add_argument("--format", choices=["table", "markdown", "json"], default="table",
                        help="Report format for stdout and the output file (default: table)")
    parser.add_argument("--output-file", type=Path, help="Write the report to this file")
    parser.add_argument("--filter", choices=["exploit", "benign", "all"], default="all",
                        help="Which requests to send (default: all)")
    args = parser.parse_args(argv)

    report = run(args.corpus, args.target, args.resolver, args.filter)
    rendered = render(report, args.format)
    print(rendered)
    if args.output_file:
        args.output_file.write_text(rendered, encoding="utf-8")
    return 0 if report["summary"]["overall"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
