# Wiz OPA Assessment – Agent Context

Implementation guide for coding agents changing this repo. Product pitch: [`README.md`](README.md).

---

## Orientation

| Question | Answer |
| -------- | ------ |
| What is this? | OPA/Rego policies + Python `unittest` harness for AWS EC2 security-group JSON |
| Policies | `scripts/` (`script1.rego`, `script2.rego`, `script2_extra.rego`) |
| Fixtures | `inputs/`, `inputs/extra/` |
| Tests | `tests/` — stdlib `unittest` calling `opa eval` (not pytest) |
| Packaging | None — no `pyproject.toml` / installable package |
| Toolchain | [OPA](https://www.openpolicyagent.org/) CLI + Python 3 |
| Secrets | Never commit AWS keys, tokens, or live account data |

```text
.
├── .github/          # CODEOWNERS, dependabot, thin CI/semver orchestrators
├── scripts/          # Rego policies
├── inputs/           # script2 fixtures (+ extra/ for script2_extra)
├── tests/            # unittest + OPA subprocess helper
├── README.md         # Marketing / user docs
└── *.pdf             # Assignment brief + report (do not treat as source of truth for code)
```

Shared CI/CD: [`danielnachumdev/actions`](https://github.com/danielnachumdev/actions) (`@latest` floating tag in this repo). How to adopt: [`HOW-TO-USE.md`](https://github.com/danielnachumdev/actions/blob/v1/HOW-TO-USE.md).

---

## Develop

### Prerequisites

1. Install the **OPA** binary and put it on `PATH` (or note its absolute path).
2. Point tests at that binary: `tests/base.py` hardcodes `OPA_PATH = r'C:\tools\OPA\opa.exe'` (Windows demo path). Change it locally for Linux/macOS before running tests — do not commit machine-specific paths unless intentionally updating the documented default.

### Evaluate a policy manually

```bash
opa eval -i inputs/tcp_22.json -d scripts/script2.rego 'data.scripts.match' --format pretty
opa eval -i inputs/extra/case1.json -d scripts/script2_extra.rego 'data.scripts.match' --format pretty
opa eval -i <imds-json> -d scripts/script1.rego 'data.ec2policy.match' --format pretty
```

Semantics for `script2` / `script2_extra`: **`match == true` means unsafe** (policy fires). For `script1`, `match` is true when `HttpTokens` is `"optional"`.

### Run tests

Run from the **repo root** so `./inputs/...` and `./scripts/...` resolve, and so `discover -s tests` puts `tests/` on `sys.path` for `from base import ...`:

```bash
python -m unittest discover -s tests -p 'test_*.py' -v
```

Target one module:

```bash
python -m unittest tests.test_script2 -v
python -m unittest tests.test_script2_extra -v
```

(`tests/test_script2.py` exercises `script2.rego`; `tests/test_script2_extra.py` exercises `script2_extra.rego`. There is no automated suite for `script1.rego`.)

### Domain notes

- Fixture shape mirrors AWS EC2 `SecurityGroups` / `IpPermissions` / `IpPermissionsEgress` JSON (see any file under `inputs/`).
- Prefer adding a **new fixture + unittest method** when tightening Rego, so the failure mode stays encoded.
- `script2_extra.rego` encodes three mutually exclusive “safe” SG shapes (`case1` / `case2` / `case3`); naming of some helpers follows the assignment cases — read the Rego before renaming.
- Do not delete `tests/` or empty out fixtures to silence failures.

---

## PRs, CI, and releases

1. Branch off `main`; open a PR into `main`.
2. Attach **exactly one** semver label: `noBump` | `bumpPatch` | `bumpMinor` | `bumpMajor`.
3. **CI** — thin `.github/workflows/ci.yml` → `danielnachumdev/actions` `ci.yml@latest` + `semver-ci.yml@latest`. Prefer required checks **`CI / CI`** and **`Semver / Semver`**.
4. This repo passes `allow-empty: true` to shared CI (no installable Python package / no default pytest project). Local OPA + unittest is the real verification for policy changes.
5. Dependabot PRs stay on `noBump` (GitHub Actions ecosystem only today).
6. Change shared CI/semver behavior in **`danielnachumdev/actions`**, not by re-vendoring here.

There is **no PyPI publish / CD bump** path for this assessment repo; prefer `noBump` unless a release process is added later.

### Repo gates

- `.github/CODEOWNERS` — `@danielnachumdev`
- Dependabot: weekly `github-actions`, labels `dependencies` + `noBump`

---

## Sensitive / ignored

Do not commit: AWS credentials, API keys, `.pem` files, live account IDs, or regenerated cloud inventory. Assignment PDFs may stay; do not add new secrets. Respect `.gitignore`.
