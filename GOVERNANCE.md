# Governance

Kavach is a small project with a lightweight, maintainer-led model.

## Maintainers
| Maintainer | Areas |
|---|---|
| [@Srizdebnath](https://github.com/Srizdebnath) | everything (project lead) |

Maintainers review and merge pull requests, triage issues, cut releases, handle security
reports (see [SECURITY.md](SECURITY.md)) and enforce the [Code of Conduct](CODE_OF_CONDUCT.md).
Code ownership is recorded in [.github/CODEOWNERS](.github/CODEOWNERS).

## Decision making
- Day-to-day changes are decided in pull requests: one approving maintainer review and green
  CI are required to merge.
- Larger changes (kernel ABI, policy language, security model, new kernel hooks, dependencies
  with a large footprint) start as an issue or discussion so the design can be agreed before
  code is written.
- Maintainers seek consensus. If it cannot be reached, the project lead decides and records
  the reasoning in the issue or PR.

## Becoming a maintainer
Contributors who have made sustained, high-quality contributions (code, reviews, triage or
docs) over several months, and who understand the project's safety rules, may be invited by
the existing maintainers. You can also ask: open a discussion or contact a maintainer. A new
maintainer is added by agreement of the existing maintainers, starting with ownership of
specific areas in CODEOWNERS. Maintainers who become inactive for six months may be moved to
emeritus status and can return at any time.

## Changes to this document
Changes to governance are made by pull request and need approval from the project lead.
