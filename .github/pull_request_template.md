<!-- PR title must be a conventional commit (e.g. `fix(bpf): ...`); PRs are squash-merged. -->

## What and why

<!-- What does this change, and why? Link issues with "Fixes #123". -->

## Testing

<!-- How did you test it? Paste relevant output. -->

## Checklist
- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets` and `cargo test --workspace` pass
- [ ] `cargo xtask codegen --check` passes
- [ ] `scripts/priv-test.sh` passes (required if `bpf/` or `crates/kavachd` changed)
- [ ] Kernel ABI changed: `kavach_abi.h` regenerated and `ABI_VERSION` bumped if map layouts changed
- [ ] Evaluation semantics changed: both `kavach_eval.h` and `kavach-core` updated
- [ ] New parser of untrusted input: written in Rust, with tests and a fuzz target
- [ ] Docs updated for user-visible changes
- [ ] Every commit is signed off (`git commit -s`, see CONTRIBUTING.md)
