---
name: waf-rule-research
description: >-
  Write a deployable AWS WAFv2 rule that blocks a known vulnerability. Use this
  whenever the task is to turn an already-understood vuln into an actual rule:
  authoring the WAFv2 JSON, choosing statement types and match fields, estimating
  WCU, keeping false positives at zero on unrelated customer traffic, deciding
  what to leave uncovered, or concluding that no safe rule exists. Trigger on
  mentions of a WAF rule, AWS WAFv2, WAFv2 JSON, Web ACL, WCU, a managed ruleset,
  blocking a CVE at the WAF layer, or "write the rule for this exploit". This
  skill covers rule writing only — it assumes the vulnerability research (root
  cause, attack surface, invariants) is already done and handed to you as input.
---

# WAF Rule Writing (AWS WAFv2)

Turn a vulnerability that is already understood into a deployable AWS WAFv2 rule.
The research — root cause, attack surface, and the exploit invariants — is the
**input** to this skill. Your job is the rule: the WAFv2 JSON, its WCU, the
reasoning behind each statement, what you leave uncovered, and an honest verdict
on whether a safe rule exists at all.

The rule ships in a **managed ruleset across many unrelated customers**. Every
statement you write runs against all traffic for every site behind the Web ACL,
not just the vulnerable app. That single fact drives most of the decisions below.

## What you are handed, and what you produce

**Input** (from the research step): the set of exploit invariants — what every
working exploit must contain, what varies freely (payload, encoding, casing,
transport), and which anchors are strong versus weak — plus the entry points and
sinks that carry attacker input.

**Output**: the AWS WAFv2 rule as JSON, an estimated WCU, a one-line explanation
of each statement, a note of anything you deliberately left out, and — if the
honest answer is that no rule can run safely — a clear statement of why, with
what you would recommend instead.

## Principles that decide the rule

**Zero false positives comes first.** A managed rule that blocks even a small
fraction of legitimate traffic on an unrelated customer's site is worse than no
rule. When coverage and precision conflict, keep precision and give up the
coverage — then write down exactly which exploit variants you left uncovered and
why. This is the single most important constraint; everything else yields to it.

**Anchor on what the attacker cannot change, not on the payload.** Matching the
payload string (`exec(`, `import os`, a known PoC literal) is the obvious first
move and usually the weakest: the attacker rewrites it freely with encoding,
casing, whitespace, and equivalent constructs. A strong anchor is a token the
exploit *structurally requires* — something the fix itself had to constrain, a
mandatory field name, a required content type, a structural character the sink
cannot do without. Build the rule around the strong anchors and treat payload
matching as at best a weak supporting signal. When a condition turns out to do no
real work, say so and consider removing it.

**Keep WCU low, but never at the expense of precision.** WCU measures cost, not
safety. Prefer the cheaper statement when it is equally precise (a byte match
over a regex, a size constraint over a scan), but never drop a condition that is
holding the false-positive rate down just to save capacity. See
`references/wafv2-reference.md` for per-statement WCU and how to estimate a rule.

**Respect what the WAF can actually see.** AWS WAF inspects only the first
16 KB of a request body by default (8 KB fixed for ALB and AppSync), raising to
at most 64 KB with `AssociationConfig`. Anything past that limit is invisible to
every statement you write — an attacker who can push the trigger beyond the
inspected window evades the rule regardless of how good the match is. Account for
body limits, encodings, and the text transformations WAF can apply before you
claim an invariant is visible. The reference file covers these limits in detail.

**"No safe rule exists" is a valid conclusion.** Some vulnerabilities cannot be
blocked at the WAF layer without either missing real exploits or blocking real
traffic — for example, when the invariant only appears in a request shape that
legitimate clients also send, or when the vulnerable input never reaches the WAF
in an inspectable form. If that is the case, say so plainly, show the reasoning,
and recommend what would actually help (virtual patch at the app, a scoped rule
the customer opts into, rate limiting, detection-only mode).

## Workflow

1. **Restate the invariants you are building on.** List the strong anchors (what
   must be present) and the free variables (what the attacker changes at will).
   The rule exists to catch the former while staying blind to nothing in the
   latter that a legitimate client also uses. If the handed-in invariants are
   thin, that is a signal the rule may not be safe — flag it rather than inventing
   an anchor.

2. **Pick the match field for each anchor.** Map each strong anchor to the
   request component WAF can inspect it in: `UriPath`, `QueryString`,
   `SingleHeader` / `Headers`, `Body`, `JsonBody`, `Method`, `AllQueryArguments`.
   Choosing the narrowest field that still sees the anchor keeps both WCU and the
   false-positive surface small. See the field-to-match guide in the reference.

3. **Choose the cheapest statement that matches precisely.** Byte match for a
   fixed string, size constraint for a length bound, regex (single pattern or a
   regex pattern set) only when the anchor genuinely varies in a way a literal
   cannot capture. Apply the minimal text transformations needed to defeat the
   evasions the free variables allow (for example `URL_DECODE`, `LOWERCASE`,
   `COMPRESS_WHITE_SPACE`) — each transformation adds WCU and can change what
   legitimate traffic looks like, so add one only when it closes a real gap.

4. **Combine with AND to raise precision.** A single broad match on a managed
   ruleset is almost always too loose. Require several independent invariants to
   hold at once with an `AndStatement` — method AND content type AND the
   structural anchor — so the rule fires only on the narrow intersection the
   exploit needs and benign traffic rarely hits. Set `OversizeHandling`
   explicitly on any body or JSON-body match.

5. **Estimate the WCU and name each statement's job.** Sum the statement costs
   (reference file has the numbers), and for every statement write one line: the
   invariant it anchors to and why it is there. If a statement is doing no real
   work — it never excludes a benign request the others admit, or never a catches
   an exploit the others miss — remove it or call it out.

6. **Write down what you left uncovered.** Every variant the rule does not catch,
   and why (precision trade-off, body-size blind spot, encoding you chose not to
   chase). This is not a weakness in the deliverable; it is the deliverable being
   honest.

## Rule output format

Deliver the rule as a single WAFv2 `Rule` JSON object (the element that goes
inside a Web ACL's or rule group's `Rules` array), using `assets/rule-skeleton.json`
as the starting shape. Alongside the JSON, give:

- **Estimated WCU**: the total and the per-statement breakdown.
- **Statement rationale**: one line per statement — which invariant, why.
- **Deliberate omissions**: variants not covered and the reason.
- **Verdict**: production-viable across unrelated customers, viable only under
  stated conditions, or not safely blockable (with the recommendation).

Use `Count` action while a rule is being validated and `Block` only once its
false-positive rate is proven; note which you are shipping and why.

## Reference

`references/wafv2-reference.md` — statement types and their WCU, the request
components you can match (`FieldToMatch`), text transformations, body-inspection
size limits and `OversizeHandling`, and two worked rule examples. Read it before
writing the JSON; the WCU numbers and body limits are exact and easy to get wrong
from memory.

`assets/rule-skeleton.json` — a minimal WAFv2 rule skeleton to be used as formatting reference.
