# Finite worker and source-packet runtime

`runtime/finite_worker.py` preserves the working pipeline's actual subprocess lifecycle, cancellation, atomic receipts, real task-identity extraction, timeout behavior and failure checks. Public adapters supply caller-owned scope and prompts instead of private editorial rules. `source_packets.py` retains the anchored SQLite window reader with read-only connections.

`python -m runtime.cli --help` documents the opt-in interface. Model, executable, owner, scope, prompts and a fresh output directory must be supplied. Default execution is a dry run; the permission default is read-only. Write access is explicit and restricted to the CLI workspace sandbox. There is no unrestricted-access option in this distribution. Your CLI version must support the listed arguments; live account integration is not part of the offline tests.

Completion needs one actual `thread.started` identity, a completed turn, no error event and a non-empty final artifact. A zero exit code alone is insufficient. API-key environment fallbacks are removed. Timed-out children are stopped and no automatic retries are scheduled. Cross-process global concurrency is not guaranteed by this single-controller helper.

The current source workflow separates proposal, independent checking and acceptance and preserves frozen versions through revisions. These runtime receipts establish execution provenance, not translation quality. No novel, original research cards, real account transcripts or completed-translation claim is included.
