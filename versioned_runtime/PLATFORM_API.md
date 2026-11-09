# Semantic platform boundary

The domain/transport code calls operations rather than dispatching on OS names.
The bundled standard-library provider attempts the needed primitives. Missing
strong semantics fail with `CapabilityUnavailable(capability, reason)`; there is
no copy-and-replace, unlocked, no-sync, or unlimited-worker fallback.

## Contract

- `open_exclusive(path, buffering=-1)` returns a binary writer, creates mode 0600,
  and rejects existing final-component files and symlinks.
- `write_exclusive(path, data)` checks the complete write and syncs the file.
  The caller separately syncs the parent directory for namespace durability.
- `open_read(path)` refuses a final-component symlink and non-regular files.
- `sync_file(file_or_fd)` flushes buffered handles before fsync.
- `sync_directory(path)` verifies the opened object is a directory then fsyncs it.
  O_DIRECTORY is an optional strengthening, not an import prerequisite.
- `publish_noreplace(src, dst)` atomically publishes a hard link without replacing
  an occupied name. **It retains src.** The caller controls cleanup and directory
  sync. Cross-filesystem publication fails explicitly.
- `atomic_replace(src, dst)` uses the runtime's replace primitive. The caller
  syncs affected directories. Cross-filesystem replacement fails explicitly.
- `repository_lock(path, timeout=30.0)` uses a SQLite BEGIN EXCLUSIVE transaction
  in `path + '.sqlite3'`, ignoring the old flock file. Final-component lock DB
  symlinks are rejected. Contention raises TimeoutError. Crash releases the lock.
- `set_worker_limits(memory_bytes, cpu_seconds, file_bytes)` installs address-space,
  CPU-time, and file-size limits and checks exact readback. All must be positive
  integers. Limits can be partially installed before an error, so use only in
  a disposable worker. The CLI `--exec-limited MEMORY CPU FILE COMMAND...` exits
  on any failure before exec and preserves the specific error on stderr.
- `resource_snapshot()` returns self user/system CPU seconds, native max RSS,
  and explicitly unspecified RSS units. It does not guess units from OS names.
- `spawn_supervised(command, **Popen_kwargs)` returns Popen in a fresh session.
  Session/preexec/process_group overrides are rejected.
- `terminate_and_reap(proc, timeout=5.0)` kills its process group even when its
  leader already exited, then waits for the leader. It does not drain pipes.

## Explicit admission

`probe(directory, required=())` creates temporary files on the target filesystem,
checks file/symlink collisions without changing existing contents, file/directory
sync, mkdir/rmdir namespace sync, link publication, replacement readback, actual
independent-process SQLite contention and crash release, disposable-child resource
limit readback, resource accounting, and session/group termination. Results are
JSON-compatible. Missing required capabilities raise CapabilityUnavailable with
`.report`, `.capability`, and `.reason`.

Capability names: exclusive_create, nofollow_read, file_sync, directory_sync,
publish_noreplace, atomic_replace, repository_lock, worker_limits,
resource_snapshot, process_group_supervision.

Import alone does not require fcntl, resource, sqlite3, O_DIRECTORY, O_NOFOLLOW,
killpg, setsid, or getpgid. An unavailable strong operation is a capability
failure, not an unsupported OS-name rejection.

## Provider identity and scope

`provider_identity()` reports the bundled source SHA-256. Production substitution
uses `configure_provider('stdlib', expected_sha256=...)`, a closed source-local
registry, not external imports or plugins. Additional providers must be vendored
and included in a new execution pin. The domain's execution identity must include
platform_api.py bytes. Tests may monkeypatch primitives for failure injection.

A successful probe observes this runtime and this filesystem only. It does not
certify another machine, filesystem mount, network filesystem, storage hardware,
or survival of power loss. No power-failure testing was performed. SQLite locks
coordinate cooperating callers; hostile directory ancestors/name replacement are
outside this API's contract. The nofollow test needs test-symlink creation rights.
Process supervision covers a new process group, not descendants that deliberately
escape their group/session; it is not a security sandbox. Limit probes establish
kernel acceptance/readback, not all-workload enforcement. No broader platform
coverage is claimed by these local tests.

## Focused verification

Run `python -m unittest -v test_platform_api` from this directory. The checked-in
PLATFORM_TEST_REPORT.txt records the local run. PLATFORM_PROBE_REPORT.json is an
observation from this candidate directory, not portable certification. Test
coverage includes import with absent optional primitives, exact short-write
rejection, symlink/collision preservation, fail-closed missing capability tests,
independent-process lock exclusion and crash release, exec limit inheritance,
and inherited-pipe closure after the leader exits.

Probe child lifecycle is now owned by a common cleanup context: on success,
timeout, ordinary exception, or assertion failure, it kills a still-running
fixture, independently waits/reaps without retrying communicate, and closes all
pipes in nested finally blocks. Fault-injection tests exercise communicate timeout
and ordinary exception at each of the three lock/limit child positions, checking
real subprocess return codes and closed streams. Normal completion is also tested.

Production capability observations use explicit conditional failures, never Python
assert statements. A subprocess regression injects a replacement provider that
returns success without replacing anything and verifies both reported failure and
required-capability rejection under `python -O` and `PYTHONOPTIMIZE=2`.
