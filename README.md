# Versioned State and Traceable Text Workflows

Storage, recovery and review provenance for long-running text work. The implementation comes from a long-form literary translation project and keeps content originals, editorial decisions and derived runtime state distinct.

## Main components

| Layer | Mechanism | Start here |
| --- | --- | --- |
| Durable runtime | Content-addressed objects, transaction journals, compare-and-swap, verifiable checkpoints and bounded queries | [Versioned runtime](docs/versioned-runtime.md) |
| Corpus and revision | Stable units, exact source hashes, constrained patches, dependency checks and rebuildable SQLite search | `translation_core/corpus.py` |
| Review lineage | Bound tasks, upstream versions and distinct production/review/adjudication evidence | `translation_core/governance.py` |
| Finite execution | Bounded workers, cancellation, execution receipts and immutable reading packets | [Execution guide](docs/finite-workers.md) |

A local revision should preserve still-valid work without silently inheriting judgments whose source or dependencies changed. Source documents and accepted editorial evidence remain authoritative; restoring a runtime database does not itself install an editorial revision.

## Reproduce

Python 3.10+ and SQLite with FTS5 trigram support:

```sh
python -B -m unittest discover -s tests -v
python -B demo.py --out demo-output
```

The demo uses original synthetic text with repeated chapter numbers, merged headings and exact patches. Inspect `build/case.json`, `paragraphs.jsonl` and `corpus.sqlite3`. Display chapter numbers may repeat while stable unit identities remain unique.

The versioned runtime also requires Git. Its full durability suite runs on a capable POSIX filesystem:

```sh
python -B verify_versioned_runtime.py
# Capability observation, including on Windows:
python -B verify_versioned_runtime.py --probe-only
```

The [runtime guide](docs/versioned-runtime.md) explains cold admission, selected access, recovery and the source integration's scope. Full production adoption and native Windows execution remain separate from the bounded integration checks represented here.

## Source and review boundaries

[Engineering cases](docs/engineering-cases.md) explain stable keys, immutable originals and version-bound review. [Source provenance](docs/source-provenance.md) distinguishes retained implementation from public adapters.

The code checks identity, dependency and structural consistency. Literary judgments require actual review. Original novels, full translations and private research records are outside this distribution; synthetic receipts are test data rather than historical approvals.

## License

[MIT](LICENSE) covers repository code, documentation and original fixtures. Python, SQLite and Git retain their own terms.
