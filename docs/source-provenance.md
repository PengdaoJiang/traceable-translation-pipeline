# Preserved implementation, explicit release boundary

`translation_core/corpus.py` contains the original definitions needed for baseline validation, patches, segmentation, structural signatures, review scopes and SQLite search. Definitions and their top-level dependency closure were selected from the existing pipeline with Python AST boundaries; function bodies were not rewritten into a demonstration implementation. The module header and workspace-root binding are portability scaffolding.

`translation_core/governance.py` retains the original editorial receipt validator. The public entry point, original short test text, test cases and CI are new release support. Their purpose is to run the original implementation without the private full-book corpus or its staging directories.

The broader project also contains nomenclature research, milestone production, artifact assembly and whole-book workflows. They are outside this public subsystem and are not implied to be finished by passing the public tests. Original worktree changes are not reset, and historical completion labels are not republished as current acceptance.

A private source mapping records original file hashes, selected definitions and released-file hashes. Public Git history starts with the actual release; no older dates or fictional contributors are inserted.

The source receipt format accepts canonical task paths and lowercase UUIDs, matching the current source project's real task-identity formats. Checking syntax and distinctness does not authenticate a task execution. Real users must retain external execution evidence. Public fixtures use fabricated test identities and synthetic records, not historical approvals.
