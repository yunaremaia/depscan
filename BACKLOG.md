# depscan backlog

Design decisions deliberately **not** taken in a bugfix PR. Each entry states the
question, why guessing would be wrong, and what a decision would have to cover.

## `--typosquat` / `--no-typosquat` is a declared no-op (tracks #226, #57)

`cli.scan()` declares `--typosquat/--no-typosquat` (default on), binds it to the
`typosquat` parameter, and then never reads it. Typosquat detection always runs,
so `--no-typosquat` changes neither the report nor the exit code:

```console
$ depscan scan --fail-on typosquat reqests-project/            # exit=1, typosquat reported
$ depscan scan --fail-on typosquat --no-typosquat reqests-project/   # exit=1, typosquat reported
$ depscan scan --fail-on typosquat --typosquat reqests-project/      # exit=1, typosquat reported
```

The three outputs are byte-identical; `--fail-on typosquat` is used above
because plain `scan` exits 0 regardless and would hide the difference.

This was found and confirmed while fixing the allowlist-ordering defect in
`check_typosquat` (the two live in the same function's call path). It is
**deliberately left unfixed** here because the correct semantics are a design
decision, not a bug:

- Does `--no-typosquat` suppress only the *report*, or also detection?
- Should it suppress the exit code under `--fail-on typosquat` / `--fail-on any`?
  A user who disables typosquat checking arguably still wants a *critical*
  typosquat to fail the build.
- Should `depscan ci` grow the same flag? It currently has only `--allow-known`,
  which suppresses vulnerabilities but never typosquats.

Picking any one of those silently changes when a CI gate goes red. That is a
contract change and belongs in its own PR with its own tests.

## Vulnerability data source is still missing

`scan_and_check` never populates `results["vulnerable"]`, so
`--fail-on vulnerable` and the `vulnerable` list in JSON/Markdown/SARIF output are
structurally always empty. `Dependency.known_vulnerabilities` is populated only by
tests. The plumbing (`filters.py`, `sarif.py`, `formatter.py`, `ci --allow-known`)
is all present and correct; what is missing is the advisory feed. Deciding
between OSV, a vendored snapshot, or a user-supplied cache is a design decision.
