# AWS WAFv2 Rule Reference

Mechanics for writing a WAFv2 rule: statement types and their WCU, the request
components you can inspect, text transformations, body-inspection limits, and two
worked examples. Numbers here are from the AWS WAF developer guide (verified
2026-10); treat them as exact and re-check against the live docs if a rule's WCU
budget is tight.

## Contents

- [WCU per statement](#wcu-per-statement)
- [FieldToMatch — what you can inspect](#fieldtomatch--what-you-can-inspect)
- [Text transformations](#text-transformations)
- [Body inspection limits and OversizeHandling](#body-inspection-limits-and-oversizehandling)
- [Statement shapes](#statement-shapes)
- [Worked examples](#worked-examples)
- [Sources](#sources)

## WCU per statement

A rule's WCU is the sum of its statement costs (logical operators add no cost of
their own beyond their children). A Web ACL includes 1,500 WCUs in the base
price; a rule group has a fixed capacity set at creation; the hard ceiling is
5,000 WCUs.

| Statement | Base WCU | Modifiers |
| --- | --- | --- |
| Byte / string match (`ByteMatchStatement`) | 2 for `EXACTLY` / `STARTS_WITH` / `ENDS_WITH`; 10 for `CONTAINS` / `CONTAINS_WORD` | +10 per text transformation; +10 if field is `AllQueryArguments`; **cost doubles if field is `JsonBody`**; search string ≤ 200 bytes |
| Size constraint (`SizeConstraintStatement`) | 1 | +10 per text transformation |
| IP set (`IPSetReferenceStatement`) | 1 | — |
| Geo match (`GeoMatchStatement`) | 1 | — |
| Label match (`LabelMatchStatement`) | 1 | — |
| Regex match, single pattern (`RegexMatchStatement`) | 3 | +10 per text transformation; +10 if field is `AllQueryArguments`; cost doubles if field is `JsonBody` |
| Regex pattern set (`RegexPatternSetReferenceStatement`) | 25 | +10 per text transformation; +10 if field is `AllQueryArguments`; cost doubles if field is `JsonBody` |
| SQLi match (`SqliMatchStatement`) | 20 | +10 per text transformation; sensitivity `HIGH` may add cost |
| XSS match (`XssMatchStatement`) | 40 | +10 per text transformation |
| Rate-based (`RateBasedStatement`) | 2 | more with custom aggregation keys / scope-down |
| `AndStatement` / `OrStatement` / `NotStatement` | sum of nested | logical wrappers add nothing beyond their children |

Practical reading: a byte match is nearly free, a single regex is cheap, a regex
**pattern set** is the expensive building block (25 before anything else), and
inspecting the **JSON body** doubles a regex cost. Prefer a byte match or a
single `RegexMatchStatement` over a pattern set when one pattern suffices.

## FieldToMatch — what you can inspect

Each match statement names one request component in `FieldToMatch`:

| Component | JSON key | Notes |
| --- | --- | --- |
| URI path | `UriPath: {}` | path only, no query string |
| Query string | `QueryString: {}` | whole raw query string |
| Single query argument | `SingleQueryArgument: { Name }` | one named parameter |
| All query arguments | `AllQueryArguments: {}` | +10 WCU on regex statements |
| Single header | `SingleHeader: { Name }` | lowercase the name |
| All headers | `Headers: { MatchPattern, MatchScope, OversizeHandling }` | needs oversize handling |
| Cookies | `Cookies: { MatchPattern, MatchScope, OversizeHandling }` | — |
| Method | `Method: {}` | GET, POST, … |
| Body (raw) | `Body: { OversizeHandling }` | subject to body size limit |
| JSON body (parsed) | `JsonBody: { MatchPattern, MatchScope, InvalidFallbackBehavior, OversizeHandling }` | parses JSON; doubles regex WCU |

Pick the narrowest component that still contains the anchor. Matching `UriPath`
or `Method` is far cheaper and far less likely to touch benign traffic than
scanning the whole body. `JsonBody` lets you target a specific key (via
`MatchPattern`), which is both more precise and more defensible than a raw body
scan when the exploit lives in a known field.

## Text transformations

Applied to the component before inspection; each costs +10 WCU and runs in the
listed `Priority` order. Use them to collapse the attacker's free variables
(encoding, casing, whitespace) onto the canonical form your match expects — but
each one also reshapes legitimate traffic, so add only those that close a real
evasion.

Common ones: `NONE`, `LOWERCASE`, `URL_DECODE`, `URL_DECODE_UNI`, `HTML_ENTITY_DECODE`,
`JS_DECODE`, `COMPRESS_WHITE_SPACE`, `REMOVE_NULLS`, `BASE64_DECODE`,
`BASE64_DECODE_EXT`, `CMD_LINE`, `NORMALIZE_PATH`, `NORMALIZE_PATH_WIN`,
`REPLACE_COMMENTS`, `ESCAPE_SEQ_DECODE`, `UTF8_TO_UNICODE`.

A match on a body field typically needs at least `URL_DECODE` (and often
`LOWERCASE` + `COMPRESS_WHITE_SPACE`) before a literal anchor is reliable.

## Body inspection limits and OversizeHandling

WAF forwards only a bounded prefix of the request body to your rules. Anything
past the limit is invisible — a critical blind spot: an attacker who can place
the trigger after enough padding evades every body/JSON-body statement.

| Resource type | Default inspected body | Maximum (via `AssociationConfig`) |
| --- | --- | --- |
| CloudFront | 16 KB | 64 KB (16/32/48/64 KB steps) |
| API Gateway, Cognito, App Runner, Verified Access | 16 KB | 64 KB |
| Application Load Balancer, AppSync | 8 KB | 8 KB (fixed, not raisable) |

`AssociationConfig.RequestBody.<resource>.DefaultSizeInspectionLimit` takes
`KB_16`, `KB_32`, `KB_48`, or `KB_64`. Inspecting beyond 16 KB incurs extra cost.

`OversizeHandling` is **required** on `Body`, `JsonBody`, `Headers`, and
`Cookies`, and sets what happens when the component exceeds the limit:

- `CONTINUE` — inspect the available prefix, keep going.
- `MATCH` — treat the oversize component as a match (fail closed; can raise false
  positives on large legitimate bodies).
- `NO_MATCH` — treat it as a non-match (fail open; the evasion above succeeds).

Choosing between `MATCH` and `NO_MATCH` is a precision-vs-coverage decision: on a
managed ruleset, `MATCH` on a body statement can block any customer who posts a
large legitimate payload, so it needs strong justification.

## Statement shapes

Byte match:

```json
{
  "ByteMatchStatement": {
    "SearchString": "literal-anchor",
    "FieldToMatch": { "UriPath": {} },
    "TextTransformations": [{ "Priority": 0, "Type": "LOWERCASE" }],
    "PositionalConstraint": "CONTAINS"
  }
}
```

`PositionalConstraint`: `EXACTLY`, `STARTS_WITH`, `ENDS_WITH`, `CONTAINS`,
`CONTAINS_WORD`.

Regex match (single pattern, inline):

```json
{
  "RegexMatchStatement": {
    "RegexString": "\\bpattern\\b",
    "FieldToMatch": { "JsonBody": { "MatchPattern": { "All": {} }, "MatchScope": "VALUE", "OversizeHandling": "CONTINUE" } },
    "TextTransformations": [{ "Priority": 0, "Type": "NONE" }]
  }
}
```

AND of several invariants (the usual precision pattern):

```json
{
  "AndStatement": {
    "Statements": [
      { "ByteMatchStatement": { "...": "method / path anchor" } },
      { "ByteMatchStatement": { "...": "content-type anchor" } },
      { "RegexMatchStatement": { "...": "structural anchor" } }
    ]
  }
}
```

## Worked examples

**Example A — narrow, AND-gated body rule.** Block a POST to a specific route
whose JSON body carries a structural anchor, firing only on the intersection:

```json
{
  "Name": "block-cve-example-a",
  "Priority": 10,
  "Action": { "Block": {} },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "blockCveExampleA"
  },
  "Statement": {
    "AndStatement": {
      "Statements": [
        { "ByteMatchStatement": {
            "SearchString": "post",
            "FieldToMatch": { "Method": {} },
            "TextTransformations": [{ "Priority": 0, "Type": "LOWERCASE" }],
            "PositionalConstraint": "EXACTLY" } },
        { "ByteMatchStatement": {
            "SearchString": "/api/v1/vulnerable/route",
            "FieldToMatch": { "UriPath": {} },
            "TextTransformations": [{ "Priority": 0, "Type": "LOWERCASE" }],
            "PositionalConstraint": "STARTS_WITH" } },
        { "RegexMatchStatement": {
            "RegexString": "<structural-anchor-the-exploit-requires>",
            "FieldToMatch": { "JsonBody": {
              "MatchPattern": { "All": {} }, "MatchScope": "VALUE", "OversizeHandling": "CONTINUE" } },
            "TextTransformations": [{ "Priority": 0, "Type": "URL_DECODE" }, { "Priority": 1, "Type": "LOWERCASE" }] } }
      ]
    }
  }
}
```

WCU: 2 (method byte match, `EXACTLY`) + 2 (path byte match, `STARTS_WITH`) +
[3 base × 2 for JsonBody + 10 × 2 transformations = 26] = **30 WCU**. The two
byte matches do the real precision work; the regex sees the structural invariant
inside the body.

**Example B — count-first, structural-only.** When the only safe anchor is a
structural token and you are not yet sure of the false-positive rate, ship it in
`Count` to gather sampled requests before switching to `Block`:

```json
{
  "Name": "count-cve-example-b",
  "Priority": 20,
  "Action": { "Count": {} },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "countCveExampleB"
  },
  "Statement": {
    "RegexMatchStatement": {
      "RegexString": "<structural-anchor>",
      "FieldToMatch": { "Body": { "OversizeHandling": "CONTINUE" } },
      "TextTransformations": [{ "Priority": 0, "Type": "URL_DECODE" }, { "Priority": 1, "Type": "COMPRESS_WHITE_SPACE" }]
    }
  }
}
```

WCU: 3 base + 10 × 2 transformations = **23 WCU**. `OversizeHandling: CONTINUE`
accepts the body-size blind spot rather than blocking large legitimate posts.

## Sources

- [Web ACL capacity units (WCUs)](https://docs.aws.amazon.com/waf/latest/developerguide/aws-waf-capacity-units.html)
- [Using rule statements in AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statements.html) (per-statement WCU on each statement's page)
- [Regex pattern set match statement](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-regex-pattern-set-match.html)
- [Considerations for managing body inspection](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-setting-body-inspection-limit.html)
- [Oversize web request components](https://docs.aws.amazon.com/waf/latest/developerguide/waf-oversize-request-components.html)
- [Text transformations](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-transformation.html)
