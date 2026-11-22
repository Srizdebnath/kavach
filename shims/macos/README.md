# macOS shim (v0.5, planned)

* **Hook:** a Network Extension using `NEFilterDataProvider` (a content filter). Kernel
  extensions are not an option on current macOS.
* **Engine:** the provider is a Swift wrapper around `kavach-core`, built as a static library
  for aarch64 and x86_64 Apple targets.
* **Identity:**
  * `NEFilterFlow.sourceAppAuditToken` provides the pid/uid/code-signing identity.
  * `who = { binary = … }` maps to the code-signing designated requirement or the cdhash, which
    is stronger than a file hash.
* **Policy:** bundles are verified the same way (`kavach-policy`). Apply is atomic at the level
  of the provider's in-memory table swap.
