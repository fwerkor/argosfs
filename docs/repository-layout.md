# Repository Layout

ArgosFS keeps implementation, integration assets, validation harnesses, and research artifacts in separate top-level areas:

- `src/` contains the Rust library and CLI implementation.
  - `src/volume/` is split by responsibility: namespace operations, data-plane encode/decode I/O, maintenance/repair, autopilot state, shared helpers, and tests.
  - `src/cli/` separates clap command definitions from tree import/export helpers and command dispatch.
- `tests/` contains Rust integration tests. `tests/integration.rs` holds shared fixtures and loads feature-grouped modules from `tests/integration/`.
- `scripts/ci/` contains reusable CI setup and logging helpers.
- `scripts/tests/host/` contains host-side validation scripts that can run without a prepared QEMU image.
- `scripts/qemu/` contains CapOS image build helpers and QEMU boot/runtime test harnesses.
- `scripts/compat/` contains mounted-FUSE and optional POSIX compatibility checks.
- `scripts/experiments/` contains artifact-evaluation experiment drivers.
- `scripts/validation/` contains retained end-to-end validation workflows.
- `integrations/` contains initramfs and systemd templates for generic Linux and CapOS.
- `website/` contains the static project website.

The intent is to keep large files bounded by subsystem and make future changes land near the code or harness they affect.
