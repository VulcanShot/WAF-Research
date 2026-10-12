# Remote code execution in Langflow - CVE-2025-3248

## Vulnerability Overview

|                                        |                  |
| -------------------------------------- | ---------------- |
| **CVSSv4**                             | 9.8              |
| **EPSS**                               | 0.99             |
| **KEV**                                | Yes              |
| **Public POC / Trivially Exploitable** | Yes              |
| **Affected versions**                  | <=1.2.0          |
| **Patched versions**                   | 1.3.0            |

Langflow has an unauthenticated endpoint which allows code execution. The user-supplied code is not directly run, but is parsed using the `ast` Python library. The function definitions in the code are imported to the current execution environment. Therefore, exploits rely on using one of following approaches to actually run the code:

1. Expressions as function decorators

```python
@exec("id")
def foo():
    pass
```

2. Default arguments

```python
def foo(x=exec("id")):
    pass
```

3. A parameter or return annotation that calls (not present in public research, own finding)

```python
def foo(x: exec("id"))
def foo() -> exec("id")
```

Note that they all require top-level synchronous (i.e. not `async def`) functions.

### The Fix

The patch introduces authentication for the endpoint.

## Attack Surface

The vulnerable endpoint is `POST /api/v1/validate/code`. It expects a JSON body with a string `code` where the python code should be written.

## Exploit Invariants

The strongest anchors are the decorators, the default arguments, and annotations since either is requiered in a working exploit.

## Analysis

The anchors can be detected by a WAF, however if a blocklist it would be possible for attackers to find bypasses. Instead, all decorators, default arguments, and annotations that call functions are blocked. This does introduce a false-positive problem, which I assess is overweighted by the severity and EPSS of the vulnerability.

Still, given the amount of features in Python, it may be possible to bypass the rules. Still, the vast majority of attacks will be blocked. For example, all payloads recorded by [TrendMicro](https://www.trendmicro.com/en_us/research/25/f/langflow-vulnerability-flodric-botnet.html) are.

## Rule

WCU: 40

### Endpoint Gate

- Method: `POST`
- UriPath: CONTAINS `/api/v1/validate/code`

### Anchors

- `JsonBody` is used to parse the request body, invalid formats are ignored as they would be by Langflow.
- `OversizeHandling` is set to `CONTINUE` to prevent FP, but this could be changed.
- `IncludedPaths` is used to specify that we are only looking into the value of `.code`.
- `JS_DECODE_EXT`: to block bypass attempts via unicode escape sequences (\uHHHH)

#### Decorator

```re
(?m)^@[^\n]*\(
```

Any line beginning with `@` that contains a `(`. Also considers the indirect decorator `@(exec('...'))`

#### Default Argument / Parameter Annotation

```re
(?m)^def[ \t]+NAME[ \t]*\([^)]*[=:]\s*(?:NAME|\(\s*NAME\s*\))\s*\(\s*[^\s)]
```

`NAME` above is a python identifier (`[A-Za-z_]\w*` for the def name and `[A-Za-z_][\w.]*` for a
possibly-dotted callee)

A top-level `def` whose parameter list has a `=` (default) or `:` (annotation) followed by a call. The callee alternation covers the direct form (`=exec(`), the parenthesized-callee indirect form (`=(exec)(`), and the gap `[ \t\r\n]*` covers the newline-split form (`=exec\n(`). Dotted callees (`=os.system(`) and dict-embedded calls (`={1:exec()}`) are covered by `[\w.]`/`[^)]`.

#### Return Annotation

```re
(?m)^def[ \t]+NAME[ \t]*\([^)]*\)[ \t]*->[ \t]*(?:NAME|\(\s*NAME\s*\))\s*\(\s*[^\s)]
```

A top-level `def` with a `->` after the parameter close. The annotation must make a call to match.

## Validation Plan

```txt
       Send malicious/benign requests            =>        ALB with WAF rule         =>                        CVE Lab
  `traffic-runner` project using traffic.yaml     =>    Managed rules switched off    =>    Image from Docker Hub langflowai/langflow:1.2.0
```

- Throw an error 'SINK_REACHED' to verify exploits.

---

## Results

- Exploit block : 15/15 (100%) blocked
- Benign pass   : 6/11 (55%) allowed

As expected, some FPs are unavoidable. These are all the benign decorators, annotations, and default arguemnts that make calls to any function. Further, it would be hard and risky to try and identify if they are inside a multiline comment, so in those cases they are also blocked. Again, due to the likelihood and severity of the vulnerability I believe this is justifiable until the server is patched.

Time to complete assignment: ~5 hours
