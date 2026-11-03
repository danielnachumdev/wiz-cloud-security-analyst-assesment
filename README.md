# Wiz Cloud Security Analyst Assessment

**OPA/Rego policies that flag unsafe AWS EC2 security-group configurations** — protocol/port allowlists and tighter “safe shape” cases, driven by JSON fixtures and a small Python test harness.

[![CI](https://github.com/danielnachumdev/wiz-cloud-security-analyst-assesment/actions/workflows/ci.yml/badge.svg)](https://github.com/danielnachumdev/wiz-cloud-security-analyst-assesment/actions/workflows/ci.yml)

Educational demo from a Wiz Technical Security Analyst interview assignment. Live cloud resources used for the write-up have been deleted; this repo is for learning and demonstration only.

## Why this repo?

Cloud misconfigurations often hide in security-group rules. This project shows how **Open Policy Agent (OPA)** and **Rego** encode those checks as policy-as-code you can evaluate locally against AWS-shaped JSON.

- **`scripts/script2.rego`** — inbound rules: ICMP or TCP on an allowlisted privileged port (below 1024); anything else is unsafe (`match = true`)
- **`scripts/script2_extra.rego`** — three explicit “safe” SG shapes (restricted SMB ingress, IMAPS+LDAP ingress, open-egress-only); everything else is unsafe
- **`scripts/script1.rego`** — simple IMDS `HttpTokens == "optional"` detector
- **Fixture-backed tests** under `tests/` that shell out to `opa eval` against `inputs/` and `inputs/extra/`

## Quick start

Install [OPA](https://www.openpolicyagent.org/docs/latest/#running-opa), then evaluate a policy against a fixture:

```bash
opa eval -i inputs/tcp_22.json -d scripts/script2.rego 'data.scripts.match' --format pretty
# false → inbound rules considered safe for this policy

opa eval -i inputs/tcp_23.json -d scripts/script2.rego 'data.scripts.match' --format pretty
# true → unsafe
```

Extra “safe shape” policy:

```bash
opa eval -i inputs/extra/case1.json -d scripts/script2_extra.rego 'data.scripts.match' --format pretty
```

## What you get

| Path | Role |
| ---- | ---- |
| `scripts/*.rego` | Rego policies (`package scripts` / `ec2policy`) |
| `inputs/` | Fixtures for the inbound allowlist policy |
| `inputs/extra/` | Fixtures for the three safe-shape cases |
| `tests/` | `unittest` harness wrapping `opa eval` |
| Assignment / report PDFs | Original brief and submitted write-up |

## Assignment materials

- Brief: `Wiz_-_Technical_Security_Analyst__E2_80_93_Interview_Assignment.pdf`
- Report: `Wiz Technical Security Analyst – Interview Assignment.pdf`

## Contributing & development

OPA path, how to run tests, CI/semver labels, and agent notes: [`AGENTS.md`](./AGENTS.md).
