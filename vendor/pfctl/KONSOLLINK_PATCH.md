# Audited M0 vendor of pfctl 0.7.0

Upstream: https://github.com/mullvad/pfctl-rs, crates.io `pfctl` **0.7.0**.
Original crate archive SHA-256:
`944d2c073758b6bda57f517cff54cf69d74eae3593fe1e9aa9918666543456a9`.
MIT OR Apache-2.0; both upstream license texts are retained. No executable or
DPI engine is vendored. Root workspace uses an explicit Cargo source patch.

Source changes:

- `State::gateway_address()` exposes initialized `gwy`/`af_gwy` fields through
  the existing address parser, so cleanup checks original console source AND
  translated host address. It does not use a mutable anchor rule index as proof
  of state ownership.
- `setup_pfioc_state_kill`: exact address masks (upstream left them zero),
  direction-correct source/destination, exact TCP/UDP ports. XNU's
  [PF state-kill implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pf_ioctl.c)
  uses `PF_MATCHA` on these masks and `pf_match_xport` on the ports. Zero masks
  are wildcard matches. Regression test verifies both directions and masks/ports.
- `PoolAddrList`: final heap allocation before linking; links point into retained
  storage, not stack copies; heap-owned list head remains stable across owner
  moves. Regression covers empty, one-element and multi-element lists.
- NAT rule installation in `lib.rs`/`transaction.rs` retains the pool owner until
  after the synchronous ioctl, instead of dropping it inside the `if` block.
- State snapshots respect the kernel-returned byte length, retry boundedly if
  full, reject malformed sizes and cap allocation. Zero-filled unused capacity
  is never returned as a real state.
- Read-only `anchor_exists`, `has_console_nat`, and exact TCP redirect rule
  inspection support helper health checks.
- Rustfmt applied to modified source. Manifest removes upstream root-mutating
  examples/integration tests and their unused dev dependencies. The upstream
  unit tests and new pure regression tests remain runnable without root.

Validation:

```
CARGO_TARGET_DIR=target/pfctl-tests cargo test --manifest-path vendor/pfctl/Cargo.toml --locked --lib
```

20 unit tests pass locally on macOS. Native ioctl ABI and forwarding correctness
still require the first-device test. These patches are not represented as an
upstream release or complete third-party security audit.
