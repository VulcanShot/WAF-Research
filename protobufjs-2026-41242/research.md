# Arbitrary code execution in protobufjs - CVE-2026-41242

## Vulnerability Overview

|  |  |
| --- | --- |
| **CVSSv4** | 9.4 |
| **EPSS** | 0.0005 |
| **KEV** | No |
| **Public POC / Trivially Exploitable** | Yes |
| **Affected versions** | <=7.5.4, ==8.0.0 |
| **Patched versions** | 7.5.5, 8.0.1 |

`protobufjs` converts protobuf schemas into JS functions. These functions are ultimately generated as follows:

```js
// https://github.com/protobufjs/protobuf.js/blob/master/lib/codegen/index.js
function toString(functionNameOverride) {
    return "function " + (functionNameOverride || functionName || "") + "(" +
        (functionParams && functionParams.join(",") || "") + "){\n  " +
        body.join("\n  ") + "\n}";
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

Any exploit must use non-alphanumeric (or underscore) characters in the name of the type, just as the patch addressed. In particular, it must include parenthesis and brackets to declare a function. Further, the type must have a `fields` child object.

If the server calls [`protobufjs.Root.fromJSON`](https://github.com/protobufjs/protobuf.js/blob/master/src/root.js) on the schema sent by the user, then the type must be inside a `nested` object. However, if the server calls [`protobufjs.Type.FromJSON`](https://github.com/protobufjs/protobuf.js/blob/master/src/type.js) instead, then there would be no `nested` object.

Each vulnerable server will expect schemas in a different endpoints/formats.

## Analysis

The invariant can be seen as long as the schema can be recognized in a request. This last part is particularly difficult, and no generic (not tailored to a specific server) WAF rule can be both highly effective and false-positive safe. Nevertheless, there are certain options:

- Safest: Inspect schemas sent in the request body or in an attached JSON files.
- Expensive (WCU and FP): Try to parse every part of the request as a schema, even if it is not valid json. Could also detect malicious type names in `type` field.
- Endpoint guard: Minimize false-positives, but put the burden on the customer. Maybe this could be facilitated by Miggo ADR.

I will implement the first alternative, precisely because it is the less risky. Given the low probability of exploitation of this vulnerability, I believe it is better to minimize WCU and FP.

## Rule

- `InvalidFallbackBehavior: NO_MATCH` to prevent false positives, safe assuming the server does not accept invalid JSON.
- `OversizeHandling: CONTINUE` to prevent false positives, safe assuming the server does not accept huge descriptors in a single request.
