# Durable state for long editorial tasks

The execution layer stores source captures, revisions, evidence and pending
obligations as content-addressed records. A checkpoint binds the exact root,
external grant, runtime implementation and repository identity. A resumed
process validates those bindings before it reads or changes state.

```text
source capture -> immutable objects -> versioned state root
                                          |
                         prepare intent + journal
                                          |
                            compare-and-swap ref
                                          |
                         durable namespace fence
                                          |
                            checkpoint / restart
```

## Code map

| Concern | Implementation |
| --- | --- |
| Persistent map and exact dependencies | `core/merkle_map.py`, `core/durable_proofs.py` |
| Native source records and incremental updates | `core/native/source_adapter.py`, `source_decode.py`, `kernel_streaming.py` |
| Pending obligations, revisions and restart | `core/native_pending.py` |
| Bounded host admission and queries | `host_checkpoint.py` |
| File publication, locking, limits and process cleanup | `platform_api.py` |
| Execution identity | `BUNDLE.json`, `derive_expected_roots.py` |

The cold admission path checks the full selected storage boundary. Subsequent
queries use an authenticated host receipt and bounded metadata checks; they do
not enumerate the whole object store. Ordinary reads leave the optional
diagnostic query cache unopened and unchanged.

A crash before publication leaves the prior root authoritative. A crash after
the compare-and-swap is recovered against the recorded intent and exact parent;
recovery still re-establishes the durability fence. Stale roots, changed runtime
bytes, changed grants, redirected paths and incomplete identities are rejected.

## Reproduction

Run `python -B verify_versioned_runtime.py` from the repository root on Linux
with Python 3.11+ and Git. It copies the implementation to a temporary directory,
creates synthetic local bare repositories and runs the original focused tests.
It does not use an API key, model service, private Git remote, novel or translation.

The tests exercise changed and missing inputs, compare-and-swap conflicts,
failure before and after publication, fresh-process restoration, bounded query
access, cache growth policy, independent lock contention/crash release, and
subprocess cleanup. The included synthetic captures are test fixtures, not
accepted literary output.

`--probe-only` observes available storage/process primitives without claiming a
full runtime pass. Native Windows currently lacks some primitives used by the
bundled provider; full execution fails explicitly there. A successful Linux
test does not certify every filesystem, power-loss survival or uninterrupted
service. Process groups and cooperating locks are not a hostile-user sandbox.

## Source and publication boundary

This is an extraction of the November runtime, not a reimplementation for the
demo. The 13 core files retain the byte identities in `BUNDLE.json`; the platform
provider, host and original five test files are also retained byte-for-byte.
The wrapper and this guide are public packaging additions. The original
`PLATFORM_API.md` discusses source-workspace result files; those historical
observations are not shipped or asserted as results of this public checkout.

The source workflow separately records production, critique and adjudication.
The runtime proves bindings and mechanical transitions. A completed process,
valid checkpoint or satisfied schema does not judge translation quality or
declare an entire editorial milestone accepted.
