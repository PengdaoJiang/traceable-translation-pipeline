#!/usr/bin/env python3
"""Capability-driven host gate for the platform-adapted experimental core.

Only external expected roots/grant + completed public admission may create a
host receipt. This is a cooperative local host contract, NOT a signature,
anti-rollback service, literary approval, or authorization to process real data.
No network, content revision, pack import/export, or repository publication API.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import types

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
BUNDLE_SHA256 = 'df427171e4e1d086072ba4b1f73803f80c8a0a4d15949b915fff3f735af16ffe'
PLATFORM_SHA256 = '3fbb60873fd6ae59f3129362a958e186e5689fca036df4a0bb7434c43ae2d3e0'
OID = re.compile(r'[0-9a-f]{40}\Z')
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
TARGET = re.compile(r'SU-[0-9]{6}-T[0-9]{4}\Z')
PINS = ('compound_pin', 'native_pin', 'schema_pin', 'native_schema_pin')
STATUS = 'EXPERIMENTAL_CANDIDATE_NOT_FORMAL_APPROVAL'
TRUST = ('Local trusted host, cooperative single writer, append-only objects and coordinated GC. '
         'No signature, malicious same-UID protection, independent latest oracle or literary approval. '
         'Caller must retain and authenticate expected latest and host hash outside this directory.')


class Rejected(Exception):
    pass


def need(condition, code):
    if not condition:
        raise Rejected(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def no_symlink(path):
    path = Path(os.path.abspath(path))
    for item in (path, *path.parents):
        need(not item.is_symlink(), 'SYMLINK_PATH')
    return path


def _load_platform_api():
    path = no_symlink(HERE / 'platform_api.py')
    raw = path.read_bytes()
    need(sha(raw) == PLATFORM_SHA256, 'PLATFORM_EXECUTION_PIN')
    module = types.ModuleType('host_semantic_platform_api')
    module.__file__ = str(path)
    sys.modules[module.__name__] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


platform = _load_platform_api()  # Import is pure; capabilities are requested by operations.


def read_bytes(path, maximum=65536, expected=None):
    path = no_symlink(path)
    with platform.open_read(path) as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, 'INPUT_TYPE_SIZE')
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'INPUT_CHANGED')
    need(len(raw) == before.st_size, 'INPUT_LENGTH')
    if expected is not None:
        need(DIGEST.fullmatch(expected) and sha(raw) == expected, 'EXTERNAL_EXACT_HASH')
    return raw


def read_json(path, maximum=65536, expected=None):
    def unique(items):
        result = {}
        for key, value in items:
            need(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    return json.loads(read_bytes(path, maximum, expected), object_pairs_hook=unique)


def syncdir(path):
    platform.sync_directory(path)


def write_new(path, raw):
    """No overwrite, mode 0600, byte fsync + parent fsync + exact readback."""
    path = no_symlink(path)
    with platform.open_exclusive(path) as stream:
        need(stream.write(raw) == len(raw), 'SHORT_WRITE')
        stream.flush()
        platform.sync_file(stream)
    syncdir(path.parent)
    need(read_bytes(path, max(len(raw), 65536)) == raw, 'SAVE_READBACK')


def put(path, value):
    write_new(path, canonical(value))


def runtime_pin():
    return sha(read_bytes(HERE / 'host_checkpoint.py', 1024 * 1024))


def verify_bundle():
    manifest = read_json(HERE / 'BUNDLE.json', expected=BUNDLE_SHA256)
    need(manifest['module_count'] == len(manifest['files']) == 13, 'BUNDLE_MEMBERSHIP')
    need(manifest['platform_api']['sha256'] == PLATFORM_SHA256 and
         sha(read_bytes(HERE / 'platform_api.py', 1024 * 1024)) == PLATFORM_SHA256, 'BUNDLE_PLATFORM_PIN')
    for name, expected in manifest['files'].items():
        raw = read_bytes(HERE / 'core' / name, 1024 * 1024, expected['sha256'])
        need(len(raw) == expected['bytes'], 'BUNDLE_LENGTH')
    # Frozen modules use importlib in places. Forbid an alternate .pyc execution
    # path; dont_write_bytecode keeps subsequent imports source-only as well.
    need(not list((HERE / 'core').rglob('*.pyc')), 'BYTECODE_NOT_ALLOWED')
    return manifest


def load_core():
    manifest = verify_bundle()
    path = HERE / 'core/native_pending.py'
    module = types.ModuleType('portable_v42_native_pending')
    module.__file__ = str(path)
    sys.modules[module.__name__] = module
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    need((module.PIN, module.native.PIN, module.SCHEMA_PIN, module.k.SCHEMA_PIN) ==
         tuple(manifest[key] for key in PINS), 'EXECUTED_CORE_PINS')
    return module


def git_environment():
    # No inherited alternate object paths, config injection, hooks, prompts,
    # credentials, or Git network protocols. All supported operations are local.
    return {'PATH': os.environ.get('PATH', os.defpath), 'LANG': 'C.UTF-8',
            'LC_ALL': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1',
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
            'GIT_TERMINAL_PROMPT': '0', 'GIT_ALLOW_PROTOCOL': ''}


@contextlib.contextmanager
def local_environment():
    original = dict(os.environ)
    os.environ.clear()
    os.environ.update(git_environment_from(original))
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(original)


def git_environment_from(original):
    env = git_environment()
    env['PATH'] = original.get('PATH', os.defpath)
    return env


def repository_identity(path):
    path = no_symlink(path)
    no_symlink(path / 'objects')
    a, b = path.stat(), (path / 'objects').stat()
    return {'path': str(path), 'repo_device': a.st_dev, 'repo_inode': a.st_ino,
            'objects_device': b.st_dev, 'objects_inode': b.st_ino}


def repository_gate(path):
    path = no_symlink(path)
    need(path.is_dir() and (path / 'objects').is_dir(), 'DEDICATED_BARE_REPOSITORY_REQUIRED')
    for name in ('objects/info/alternates', 'objects/info/http-alternates', 'shallow', 'info/grafts'):
        need(not (path / name).exists(), 'EXTERNAL_OR_PARTIAL_OBJECT_STORAGE')
    for name in ('objects', 'refs'):
        for parent, dirs, files in os.walk(path / name):
            for entry in dirs + files:
                need(not (Path(parent) / entry).is_symlink(), 'REPOSITORY_SYMLINK')
    cmd = ['git', '--git-dir=' + str(path)]
    bare = subprocess.run(cmd + ['rev-parse', '--is-bare-repository'], env=git_environment(), capture_output=True)
    need(bare.returncode == 0 and bare.stdout.strip() == b'true', 'BARE_REPOSITORY_REQUIRED')
    refs = subprocess.run(cmd + ['for-each-ref', '--format=%(refname)', 'refs/replace'], env=git_environment(), capture_output=True)
    need(refs.returncode == 0 and not refs.stdout, 'REPLACEMENT_REFS')
    config = subprocess.run(cmd + ['config', '--local', '--get-regexp', r'^(include|includeIf|extensions\.partialclone|remote\..*\.promisor)'], env=git_environment(), capture_output=True)
    need(config.returncode in (0, 1) and not config.stdout, 'REPOSITORY_CONFIG_EXTERNAL_DEPENDENCY')
    return repository_identity(path)


def repository_hot_gate(path, authenticated_identity):
    """Bounded metadata-only gate AFTER external host hash authentication.

    Prior cold storage admission is inherited within the exact same local
    instance and cooperative append-only model. Never enumerate objects/refs.
    Actual touched objects remain verified by the pinned core. This deliberately
    does not detect malicious untargeted same-UID filesystem changes.
    """
    path = no_symlink(path)
    identity = repository_identity(path)
    need(identity == authenticated_identity, 'HOT_REPOSITORY_INSTANCE')
    for name in ('objects/info', 'objects/pack', 'refs', 'refs/heads',
                 'refs/heads/main', 'config', 'packed-refs', 'refs/replace'):
        no_symlink(path / name)
    for name in ('objects/info/alternates', 'objects/info/http-alternates',
                 'shallow', 'info/grafts', 'commondir', 'config.worktree'):
        need(not os.path.lexists(path / name), 'HOT_EXTERNAL_OR_PARTIAL_STORAGE')
    replacement_dir = path / 'refs/replace'
    if replacement_dir.exists():
        need(replacement_dir.is_dir(), 'HOT_REPLACEMENT_REF_TYPE')
        with os.scandir(replacement_dir) as entries:
            need(next(entries, None) is None, 'HOT_REPLACEMENT_REFS')
    packed = path / 'packed-refs'
    if packed.exists():
        raw = read_bytes(packed, 1024 * 1024)
        need(all(not line.split(maxsplit=1)[-1].startswith(b'refs/replace/')
                 for line in raw.splitlines() if line and not line.startswith((b'#', b'^'))),
             'HOT_PACKED_REPLACEMENT_REFS')
    # Small, pinned-format local config read avoids includes/alternate backends.
    # Do not invoke Git on unbounded metadata or config include indirections.
    read_bytes(path / 'config', 65536)
    command = ['git', '--git-dir=' + str(path)]
    config = subprocess.run(command + ['config', '--no-includes', '--local', '--get-regexp',
                            r'^(include|includeIf|extensions\.(partialclone|refstorage)|remote\..*\.promisor)'],
                            env=git_environment(), capture_output=True)
    need(config.returncode in (0, 1) and not config.stdout, 'HOT_CONFIG_EXTERNAL_DEPENDENCY')
    bare = subprocess.run(command + ['rev-parse', '--is-bare-repository'],
                          env=git_environment(), capture_output=True)
    need(bare.returncode == 0 and bare.stdout.strip() == b'true', 'HOT_BARE_REPOSITORY_REQUIRED')
    return identity


def current_ref(path):
    result = subprocess.run(['git', '--git-dir=' + str(path), 'rev-parse', '--verify', 'refs/heads/main'], env=git_environment(), capture_output=True)
    need(result.returncode == 0, 'CURRENT_LATEST_MISSING')
    value = result.stdout.strip().decode('ascii')
    need(OID.fullmatch(value), 'CURRENT_LATEST_FORMAT')
    return value


def input_contract(repository, native_baseline, baseline, expected_latest, grant, grant_sha256, allow_derived=False):
    need(all(type(value) is str and OID.fullmatch(value) for value in (native_baseline, baseline, expected_latest)), 'EXTERNAL_ROOTS_REQUIRED')
    need(type(grant_sha256) is str and DIGEST.fullmatch(grant_sha256), 'EXTERNAL_GRANT_HASH_REQUIRED')
    need(type(allow_derived) is bool, 'CLEAN_MODE_BOOLEAN')
    if not allow_derived:
        need(expected_latest == baseline, 'CLEAN_LATEST_MUST_EQUAL_M')
    path = no_symlink(repository)
    external_grant = read_json(grant, 16384, grant_sha256)
    return {'repository': str(path), 'native_baseline': native_baseline, 'baseline': baseline,
            'expected_latest': expected_latest, 'grant': external_grant,
            'grant_file_sha256': grant_sha256, 'allow_derived': allow_derived,
            'bundle_sha256': BUNDLE_SHA256, 'runtime_sha256': runtime_pin()}


def check_contract(contract):
    need(type(contract) is dict and set(contract) == {'repository', 'native_baseline', 'baseline', 'expected_latest', 'grant', 'grant_file_sha256', 'allow_derived', 'bundle_sha256', 'runtime_sha256'}, 'EXACT_CONTRACT_FIELDS')
    need(all(type(contract[key]) is str and OID.fullmatch(contract[key]) for key in ('native_baseline', 'baseline', 'expected_latest')), 'EXTERNAL_ROOTS_REQUIRED')
    need(type(contract['allow_derived']) is bool, 'CLEAN_MODE_BOOLEAN')
    need(contract['allow_derived'] or contract['expected_latest'] == contract['baseline'], 'CLEAN_LATEST_MUST_EQUAL_M')
    need(contract['bundle_sha256'] == BUNDLE_SHA256 and contract['runtime_sha256'] == runtime_pin(), 'HOST_EXECUTION_PINS')
    need(DIGEST.fullmatch(contract['grant_file_sha256']), 'GRANT_HASH_FORMAT')
    return Path(contract['repository'])


def query_summary(core, repo, session, target, latest):
    need(type(target) is str and TARGET.fullmatch(target), 'TARGET_ID')
    answer = core.query_native(repo, session, {'commit': latest, 'id': target})
    need(answer['commit'] == latest and answer['target'] == target, 'QUERY_IDENTITY')
    need(answer['global_clearance'] == 'UNKNOWN' and answer['responsibility']['status'] == 'UNKNOWN', 'UNKNOWN_PRESERVED')
    return {'target': target, 'root': latest, 'version': answer['version'],
            'result_sha256': sha(canonical(answer)), 'global_clearance': 'UNKNOWN',
            'responsibility': 'UNKNOWN', 'known_obligations': len(answer['known_obligations']),
            'body_logged': False}


def admission_worker(output, contract_sha256, target):
    contract = read_json(output / 'REQUEST.json', expected=contract_sha256)
    repository = check_contract(contract)
    identity = repository_gate(repository)
    latest = contract['expected_latest']
    need(current_ref(repository) == latest, 'CURRENT_LATEST_MISMATCH')
    core = load_core()
    core.k._grant_contract(contract['grant'])
    repo = core.Repo(repository)
    start = time.monotonic()
    try:
        session, report = core.restore(repo, contract['native_baseline'], contract['baseline'], latest, contract['grant'], publish=False)
        need(session.root == latest == repo.ref(), 'ADMISSION_LATEST_CHANGED')
        if not contract['allow_derived']:
            need(session.root == session.baseline and all(session.state[key] == 0 for key in ('seen_count', 'active_count', 'target_count', 'transitions')), 'CLEAN_N0_M_REQUIRED')
        raw = core.export(repo, session)
        write_new(output / 'checkpoint.json', raw)
        query = query_summary(core, repo, session, target, latest)
        need(current_ref(repository) == latest and repository_identity(repository) == identity, 'ADMISSION_POST_FENCE')
        receipt = {'format': 'completed-public-admission/v42', 'contract_sha256': contract_sha256,
                   'repository': identity, 'root': latest, 'state': session.state,
                   'checkpoint': {'sha256': sha(raw), 'bytes': len(raw)}, 'query': query,
                   'report': report, 'restore_calls': 1, 'export_calls': 1, 'publish': False,
                   'worker_pid': os.getpid(), 'wall_seconds': time.monotonic() - start,
                   'status': STATUS}
    finally:
        repo.close()
    receipt['repo_closed'] = True
    try:
        receipt['resources'] = platform.resource_snapshot()
    except platform.CapabilityUnavailable as error:
        receipt['resources'] = {'available': False, 'required_capability': error.capability, 'reason': error.reason}
    put(output / 'ADMISSION.json', receipt)


def run_admit(contract, output, target, timeout=900):
    """Public API. Worker restore/export -> actual exit -> host exact-byte gate."""
    repository = check_contract(contract)
    verify_bundle()
    need(type(target) is str and TARGET.fullmatch(target), 'TARGET_ID')
    need(type(timeout) is int and 1 <= timeout <= 86400, 'BOUNDED_TIMEOUT')
    identity = repository_gate(repository)
    need(current_ref(repository) == contract['expected_latest'], 'CURRENT_LATEST_MISMATCH')
    output = no_symlink(output)
    output.mkdir(mode=0o700)
    syncdir(output.parent)
    request = canonical(contract)
    put(output / 'REQUEST.json', contract)
    command = [sys.executable, '-B', str(HERE / 'host_checkpoint.py'), '_admit-worker',
               '--output', str(output), '--request-sha256', sha(request), '--target', target]
    platform.probe(output, required=('worker_limits', 'process_group_supervision'))
    command = [sys.executable, '-B', str(HERE / 'platform_api.py'), '--exec-limited',
               str(512 * 1024**2), str(timeout), str(1024**3), *command]
    process = platform.spawn_supervised(command, env=git_environment(),
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        platform.terminate_and_reap(process)
        put(output / 'WORKER_EXIT.json', {'exit_code': process.returncode, 'worker_reaped': True, 'timed_out': True})
        raise Rejected('ADMISSION_TIMEOUT_NO_HOST')
    exitrow = {'exit_code': code, 'worker_reaped': True, 'timed_out': False, 'worker_pid': process.pid}
    put(output / 'WORKER_EXIT.json', exitrow)
    need(code == 0, 'ADMISSION_WORKER_FAILED_NO_HOST')
    admission_raw = read_bytes(output / 'ADMISSION.json', 262144)
    admission = read_json(output / 'ADMISSION.json', 262144)
    need(admission['format'] == 'completed-public-admission/v42' and admission['contract_sha256'] == sha(request), 'ADMISSION_RECEIPT')
    need(admission['worker_pid'] == process.pid and admission['repo_closed'] is True and admission['publish'] is False and admission['restore_calls'] == admission['export_calls'] == 1, 'COMPLETED_PUBLIC_ADMISSION')
    raw = read_bytes(output / 'checkpoint.json', 16384, admission['checkpoint']['sha256'])
    checkpoint = json.loads(raw)
    need(len(raw) == admission['checkpoint']['bytes'], 'CHECKPOINT_SIZE')
    need(checkpoint['repository'] == admission['repository'] == identity == repository_identity(repository), 'HOST_REPOSITORY_INSTANCE')
    need(checkpoint['root'] == admission['root'] == contract['expected_latest'] == current_ref(repository), 'HOST_EXTERNAL_LATEST')
    need(checkpoint['native_baseline'] == contract['native_baseline'] and checkpoint['baseline'] == contract['baseline'] and checkpoint['grant'] == contract['grant'] and checkpoint['state'] == admission['state'], 'HOST_EXTERNAL_BASELINES_GRANT_STATE')
    manifest = verify_bundle()
    need(checkpoint['code'] == manifest['compound_pin'] and checkpoint['schema'] == manifest['schema_pin'], 'HOST_CHECKPOINT_PINS')
    need(admission['query']['target'] == target and admission['query']['root'] == contract['expected_latest'] and admission['query']['global_clearance'] == admission['query']['responsibility'] == 'UNKNOWN', 'HOST_QUERY_BINDING')
    host = {'format': 'local-host-checkpoint/v42', 'status': STATUS, 'trust_boundary': TRUST,
            'contract': contract, 'repository': identity, 'checkpoint_file': 'checkpoint.json',
            'checkpoint': admission['checkpoint'], 'state': admission['state'],
            'admission_sha256': sha(admission_raw), 'worker_exit_sha256': sha(read_bytes(output / 'WORKER_EXIT.json')),
            'query': admission['query'], 'core': {key: manifest[key] for key in PINS},
            'worker_exit_verified': True, 'restart_ready': True}
    put(output / 'HOST.json', host)
    return {'status': 'PASS_LOCAL_HOST_CHECKPOINT_SAVED', 'experimental_status': STATUS,
            'host_sha256': sha(canonical(host)), 'checkpoint_sha256': admission['checkpoint']['sha256'],
            'root': contract['expected_latest'], 'query': admission['query'], 'restart_ready': True}


def run_query(contract, checkpoint_dir, host_sha256, target):
    """Public API. No inference of latest or trust from repo/host/checkpoint."""
    repository = check_contract(contract)
    verify_bundle()
    checkpoint_dir = no_symlink(checkpoint_dir)
    host = read_json(checkpoint_dir / 'HOST.json', expected=host_sha256)
    need(host['format'] == 'local-host-checkpoint/v42' and host['status'] == STATUS, 'HOST_FORMAT')
    need(host['contract'] == contract, 'EXTERNAL_HOST_CONTRACT_MISMATCH')
    need(host['checkpoint_file'] == 'checkpoint.json', 'HOST_CHECKPOINT_PATH')
    need(host['restart_ready'] is True and host['worker_exit_verified'] is True, 'HOST_NOT_READY')
    identity = repository_hot_gate(repository, host['repository'])
    need(identity == host['repository'], 'HOST_REPOSITORY_INSTANCE')
    latest = contract['expected_latest']
    need(current_ref(repository) == latest, 'CURRENT_LATEST_MISMATCH')
    need(sha(read_bytes(checkpoint_dir / 'ADMISSION.json', 262144)) == host['admission_sha256'], 'HOST_ADMISSION_HASH')
    exitrow = read_json(checkpoint_dir / 'WORKER_EXIT.json', expected=host['worker_exit_sha256'])
    need(exitrow['exit_code'] == 0 and exitrow['worker_reaped'] is True and exitrow['timed_out'] is False, 'HOST_WORKER_INCOMPLETE')
    raw = read_bytes(checkpoint_dir / 'checkpoint.json', 16384, host['checkpoint']['sha256'])
    need(len(raw) == host['checkpoint']['bytes'], 'CHECKPOINT_SIZE')
    core = load_core()
    need(host['core'] == {key: verify_bundle()[key] for key in PINS}, 'HOST_CORE_PINS')
    repo = core.Repo(repository)
    start = time.monotonic()
    try:
        session = core.lazy_restore(repo, raw, host['checkpoint']['sha256'], latest)
        need(session.native_baseline == contract['native_baseline'] and session.baseline == contract['baseline'] and session.grant == contract['grant'] and session.state == host['state'], 'REOPEN_EXTERNAL_STATE')
        if not contract['allow_derived']:
            need(session.root == session.baseline and all(session.state[key] == 0 for key in ('seen_count', 'active_count', 'target_count', 'transitions')), 'CLEAN_N0_M_REQUIRED')
        query = query_summary(core, repo, session, target, latest)
        if target == host['query']['target']:
            need(query == host['query'], 'REOPEN_QUERY_CHANGED')
        need(current_ref(repository) == latest and repository_identity(repository) == identity, 'REOPEN_POST_FENCE')
    finally:
        repo.close()
    return {'status': 'PASS_SAME_INSTANCE_CHECKPOINT_QUERY', 'experimental_status': STATUS,
            'root': latest, 'query': query, 'restore_calls': 0, 'lazy_restore_calls': 1,
            'process_id': os.getpid(), 'admit_process_id': exitrow['worker_pid'],
            'new_process_from_admission': os.getpid() != exitrow['worker_pid'],
            'wall_seconds': time.monotonic() - start, 'body_logged': False}


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest='command', required=True)
    commands.add_parser('verify-bundle')
    capabilities = commands.add_parser('capabilities')
    capabilities.add_argument('--directory', required=True)
    capabilities.add_argument('--require', action='append', default=[])
    for operation in ('admit', 'query'):
        cmd = commands.add_parser(operation)
        for name in ('repository', 'native-baseline', 'baseline', 'expected-latest', 'grant', 'grant-sha256', 'target'):
            cmd.add_argument('--' + name, required=True)
        cmd.add_argument('--allow-derived', action='store_true', help='Explicitly permit proven nonempty native transition history; default requires clean N0/M.')
        if operation == 'admit':
            cmd.add_argument('--output', required=True)
            cmd.add_argument('--timeout', type=int, default=900)
        else:
            cmd.add_argument('--checkpoint-dir', required=True)
            cmd.add_argument('--host-sha256', required=True)
    worker = commands.add_parser('_admit-worker', help=argparse.SUPPRESS)
    for name in ('output', 'request-sha256', 'target'):
        worker.add_argument('--' + name, required=True)
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    with local_environment():
        if args.command == 'verify-bundle':
            manifest = verify_bundle()
            load_core()
            result = {'status': 'PASS_BUNDLE_EXACT_13_MODULES', 'experimental_status': STATUS,
                      'bundle_sha256': BUNDLE_SHA256, 'runtime_sha256': runtime_pin(),
                      **{key: manifest[key] for key in PINS}}
        elif args.command == 'capabilities':
            result = platform.probe(args.directory, required=args.require)
        elif args.command == '_admit-worker':
            admission_worker(no_symlink(args.output), args.request_sha256, args.target)
            return 0
        else:
            contract = input_contract(args.repository, args.native_baseline, args.baseline, args.expected_latest,
                                      args.grant, args.grant_sha256, args.allow_derived)
            if args.command == 'admit':
                result = run_admit(contract, args.output, args.target, args.timeout)
            else:
                result = run_query(contract, args.checkpoint_dir, args.host_sha256, args.target)
        print(canonical(result).decode())
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        # Do not echo arbitrary kernel exceptions: they can contain paths/body.
        safe = str(error) if isinstance(error, Rejected) else type(error).__name__
        print(json.dumps({'status': 'REJECTED', 'code': safe, 'restart_ready': False}), file=sys.stderr)
        raise SystemExit(1)
