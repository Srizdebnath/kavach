# FreeBSD shim (v0.5, planned)

* **Hook:** a `pfil(9)` hook on the inet and inet6 heads, for both in and out, packaged as a
  kernel module.
* **Engine:** links `kavach-common` and `kavach-core` (`no_std`) through a small C ↔ Rust FFI
  layer.
* **Tables:**
  * Policy tables use the same `#[repr(C)]` layouts as Linux. `kavachd-bsd` writes them over
    `ioctl` on `/dev/kavach`, and the A/B slots are swapped under an `epoch(9)` section, the
    analogue of `synchronize_rcu`.
  * Identity comes from `ucred` (uid, jail id) and from the socket's credentials on output.
* **Not supported:** XDP has no equivalent here, so blocklist and rate limit run in the pfil
  hook at a lower packet rate.
