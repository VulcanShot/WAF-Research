# Arbitrary code execution in protobufjs - CVE-2026-41242

## Vulnerability Overview

|                                        |                  |
| -------------------------------------- | ---------------- |
| **CVSSv4**                             | 9.4              |
| **EPSS**                               | 0.0005           |
| **KEV**                                | No               |
| **Public POC / Trivially Exploitable** | Yes              |
| **Affected versions**                  | <=7.5.4, ==8.0.0 |
| **Patched versions**                   | 7.5.5, 8.0.1     |

`protobufjs` converts protobuf schemas into JS functions. These functions are ultimately generated as follows:

```js
// https://github.com/protobufjs/protobuf.js/blob/master/lib/codegen/index.js
function toString(functionNameOverride) {
  return (
    "function " +
    (functionNameOverride || functionName || "") +
    "(" +
    ((functionParams && functionParams.join(",")) || "") +
    "){\n  " +
    body.join("\n  ") +
    "\n}"
  );
}
```

Where `functionName` will come from the name of the `type`. So, an attacker can inject code via this field, with a value like the following:

```js
X(p){console.log('hi')};function $
```

Which, in the protobuf descriptor would look like:

```js
// https://github.com/Giangdurian/CVE-2026-41242/blob/main/cve_2026_41242.py
{
    "nested": {
        "X(p){console.log('hi')};function Y": {
            "fields": {
                "data": {"type": "string", "id": 1}
            }
        }
    }
}
```

If and when the server loads the descriptor AND performs an operation on the schema (schemas are lazy loaded), the injected code will be executed.

### The Fix

The fix simply ensures that the name of the `type` is a valid JS function identifier.

```js
// https://github.com/protobufjs/protobuf.js/commit/ff7b2afef8754837cc6dc64c864cd111ab477956
function Type(name, options) {
    name = name.replace(/\W/g, "");
    ...
```

## Attack Surface

The vulnerable codebase is a library, so each vulnerable web server would have its own use of protobufjs. It is quite rare for web servers to take protobuf schemas from the user, hence the low EPSS. Usually, schemas come from third-parties like the Buf Schema Registry. When these are fetched by the server, they are not visible to a WAF whatsoever.

On the other hand, there is only one format in which malicious protobuf schemas targetting this CVE can be represented: JSON descriptors. `.proto` files are benign since their parser has the necessary controls in place. JSON descriptors could be sent directly any field of a request (although a server should only accept it in the body), or as attachments (`Content-Disposition: attachment`).

There are no predefined endpoints for loading protobuf schemas from the user or for performing operations on them.

## Exploit Invariants

Each vulnerable server will expect schemas in a different endpoints/formats. Still, the rule tries to cover all feasable cases. Any exploit must include parenthesis and brackets to declare a function. Further, the type must have a `fields` child object.

## Analysis

Considering the caveats above, mainly that a WAF can only see the schemas that are sent by web clients (and not downloaded by the server) and that we are not certain on how the endpoint will behave exactly, we can inspect invariants by looking for JSON descriptors to be sent as `application/json` in the request body, or attached as files.

To minimize false positive, it has been refered to only inspect JSON keys, where the exploits should reside. If a malicious type has already been uploaded but not triggered, this rule is not capable of detecting when that type might be referenced by another type. We assume that the server is clean at the time the rule is deployed.

An endpoint guard could be implemneted to minimize false-positives, but this would put the burden on the customer. Maybe this could be facilitated by Miggo ADR.

## Rule

WCU: 68

The rule is host guarded, as there are no endpoints to look for. There is an OR statement between the `JsonBody` and the attachment statements. Each one of them ANDs the `fields` key as well as the exploit itself.

### `JsonBody`

- `InvalidFallbackBehavior: NO_MATCH` to prevent false positives, safe assuming the server does not accept invalid JSON.
- `OversizeHandling: CONTINUE` to prevent false positives, safe assuming the server does not accept huge descriptors in a single request.
- `TextTransformations: JS_DECODE (in both), REPLACE_COMMENTS (only in exploit)` to protect against bypasses using JS-specific tricks

```re
(?s)\\((?:[^\"\\\\]|\\\\.)*\\).*\\{(?:[^\"\\\\]|\\\\.)*\\}
```

Detects the parameter list and the enclosing brackets.

### Attachment

Same as above, except pretending the body is searched as plaintext rather than `JsonBody`.

```re
(?s)\"(?:[^\"\\\\]|\\\\.)*\\((?:[^\"\\\\]|\\\\.)*\\).*\\{(?:[^\"\\\\]|\\\\.)*\"\\s*:
```

## Validation Plan

```txt
       Send malicious/benign requests            =>        ALB with WAF rule         =>                     CVE Lab
  `traffic-runner` project using traffic.yaml     =>    Managed rules switched off    =>    Adapted from github.com/Giangdurian/CVE-2026-41242
```

- It is impossible to cover all variants because each server will expect different endpoints/formats (see [Exploit Invariants](#exploit-invariants))
- This also means that measuring FP is complicated. Some benign JSON requests were crafted, but is not (and cannot be) exchaustive because of the nature of the vulnerability. However, the rule was design to minimize FP, as reasoned before.
- Given the above, I believe that the most important metric during rule testing is to eliminate bypasses.
- I have modified the lab to consider the general case that I address with the rule: the server expects a certain type, on which the exploit includes a field of the malicious type, which is appended to the request. I throw an error 'SINK_REACHED' to verify exploits.

---

## Results

- Exploit block : 10/11 (91%) blocked
- Benign pass   : 4/4 (100%) allowed

However, the only exploit that bypassed the rule uses gzip compression, which is non-WAFable.

Time to complete assignment: ~8 hours
