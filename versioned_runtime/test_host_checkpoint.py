#!/usr/bin/env python3
"""Self-contained synthetic acceptance/negative tests; never reads real corpus."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('host_checkpoint', HERE / 'host_checkpoint.py')
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


def run_tests():
    started = time.monotonic()
    rows = []
    def passed(name, **values):
        rows.append({'case': name, 'pass': True, **values})
    def reject(name, operation, exceptions=(h.Rejected,)):
        try:
            operation()
        except exceptions as error:
            passed(name, rejected_type=type(error).__name__, safe_code=str(error) if isinstance(error, h.Rejected) else type(error).__name__)
            return
        raise AssertionError(name + ' accepted')
    def init(path):
        subprocess.run(['git', 'init', '--bare', '--quiet', '--initial-branch=main', str(path)], check=True, env=h.git_environment())
    def call_cli(args, script=None, expect=True):
        result = subprocess.run([sys.executable, '-B', str(script or HERE / 'host_checkpoint.py'), *args], env=h.git_environment(), capture_output=True)
        if expect:
            assert result.returncode == 0, result.stderr.decode()
            return json.loads(result.stdout)
        assert result.returncode != 0, result.stdout.decode()
        return result

    source_before = {name: h.sha((HERE / 'core' / name).read_bytes()) for name in h.verify_bundle()['files']}
    with tempfile.TemporaryDirectory(prefix='portable-v42-test-') as temporary:
        work = Path(temporary)
        repo = work / 'clean.git'
        init(repo)
        p = h.load_core()
        r = p.Repo(repo)
        captures = [p.synthetic_fixtures.capture(n, 4) for n in (1, 2)]
        inventory = {x['owner']: p.k.sha(p.k.canonical(p.native.capture_receipt(x))) for x in captures}
        built, session = p.build_initial_pending_session(r, captures, expected_inventory=inventory, mode='synthetic_scale_only')
        n0, m, grant = session.native_baseline, session.baseline, session.grant
        r.close()
        grant_path = work / 'external-grant.json'
        grant_path.write_bytes(h.canonical(grant))
        grant_hash = h.sha(grant_path.read_bytes())
        c = h.input_contract(repo, n0, m, m, grant_path, grant_hash)
        common = ['--repository', str(repo), '--native-baseline', n0, '--baseline', m,
                  '--expected-latest', m, '--grant', str(grant_path), '--grant-sha256', grant_hash,
                  '--target', 'SU-000001-T0001']
        out = work / 'host-clean'
        admitted = call_cli(['admit', *common, '--output', str(out)])
        assert admitted['restart_ready'] and admitted['query']['known_obligations'] == 0
        a = json.loads((out / 'ADMISSION.json').read_bytes())
        assert a['report']['native_audit_basis']['native_cold_calls'] == 1
        assert a['report']['empty_baseline'] and a['state']['transitions'] == 0
        passed('clean_N0_M_single_public_restore_export_after_worker_exit', cold_calls=1, root=m)
        queried = call_cli(['query', *common, '--checkpoint-dir', str(out), '--host-sha256', admitted['host_sha256']])
        assert queried['new_process_from_admission'] and queried['query'] == admitted['query']
        passed('new_process_same_instance_lazy_restore_exact_query', restore_calls=queried['restore_calls'])
        assert queried['query']['global_clearance'] == queried['query']['responsibility'] == 'UNKNOWN'
        assert queried['query']['body_logged'] is False
        passed('native_UNKNOWN_preserved_no_body_logged')
        assert h.run_query(c, out, admitted['host_sha256'], 'SU-000002-T0001')['query']['target'] == 'SU-000002-T0001'
        passed('general_query_other_member_target')
        # Runtime bundle can move without changing its execution identity.
        moved = work / 'relocated-runtime'
        shutil.copytree(HERE, moved, ignore=shutil.ignore_patterns('TEST_RESULTS.json', '__pycache__', '*.pyc'))
        verified = call_cli(['verify-bundle'], moved / 'host_checkpoint.py')
        assert verified['compound_pin'] == p.PIN
        q = call_cli(['query', *common, '--checkpoint-dir', str(out), '--host-sha256', admitted['host_sha256']], moved / 'host_checkpoint.py')
        assert q['query'] == admitted['query']
        passed('relocated_13_module_bundle_and_host_entry_no_historical_path_dependency')
        # The receipt directory itself is portable; it does not redefine repo identity.
        moved_receipt = work / 'relocated-receipt'
        shutil.copytree(out, moved_receipt)
        assert h.run_query(c, moved_receipt, admitted['host_sha256'], 'SU-000001-T0001')['query'] == admitted['query']
        passed('checkpoint_directory_relocation_same_repository')
        reject('external_grant_hash_required', lambda: h.input_contract(repo, n0, m, m, grant_path, '0' * 64))
        reject('external_latest_required', lambda: h.input_contract(repo, n0, m, None, grant_path, grant_hash))
        reject('wrong_N0_rejected_before_host', lambda: h.run_admit({**c, 'native_baseline': '0' * 40}, work / 'wrong-n0', 'SU-000001-T0001'))
        assert not (work / 'wrong-n0/HOST.json').exists()
        reject('wrong_M_clean_latest_rejected', lambda: h.run_admit({**c, 'baseline': '0' * 40}, work / 'wrong-m', 'SU-000001-T0001'))
        reject('wrong_host_hash', lambda: h.run_query(c, out, '0' * 64, 'SU-000001-T0001'))
        reject('duplicate_admit_output_never_overwrites', lambda: h.run_admit(c, out, 'SU-000001-T0001'), (FileExistsError,))
        bad = work / 'tampered-checkpoint'; shutil.copytree(out, bad)
        with (bad / 'checkpoint.json').open('ab') as stream: stream.write(b' ')
        reject('modified_checkpoint_bytes', lambda: h.run_query(c, bad, admitted['host_sha256'], 'SU-000001-T0001'))
        bad = work / 'tampered-host'; shutil.copytree(out, bad)
        with (bad / 'HOST.json').open('ab') as stream: stream.write(b' ')
        reject('modified_host_bytes', lambda: h.run_query(c, bad, admitted['host_sha256'], 'SU-000001-T0001'))
        bad = work / 'forged-stale-host'; shutil.copytree(out, bad)
        host = json.loads((bad / 'HOST.json').read_bytes()); host['contract']['expected_latest'] = n0
        (bad / 'HOST.json').write_bytes(h.canonical(host))
        reject('host_self_reported_latest_even_matching_hash', lambda: h.run_query(c, bad, h.sha(h.canonical(host)), 'SU-000001-T0001'))
        bad = work / 'bad-worker-exit'; shutil.copytree(out, bad)
        (bad / 'WORKER_EXIT.json').write_bytes(b'{}')
        reject('modified_completed_worker_receipt', lambda: h.run_query(c, bad, admitted['host_sha256'], 'SU-000001-T0001'))
        cross = work / 'cross-instance.git'; shutil.copytree(repo, cross)
        cross_contract = h.input_contract(cross, n0, m, m, grant_path, grant_hash)
        reject('cross_instance_host_rejected', lambda: h.run_query(cross_contract, out, admitted['host_sha256'], 'SU-000001-T0001'))
        rr = p.Repo(cross)
        try:
            reject('cross_instance_core_checkpoint_rejected', lambda: p.lazy_restore(rr, (out / 'checkpoint.json').read_bytes(), admitted['checkpoint_sha256'], m), (p.k.Rejected,))
        finally: rr.close()
        new = h.run_admit(cross_contract, work / 'cross-fresh-host', 'SU-000001-T0001')
        assert new['checkpoint_sha256'] != admitted['checkpoint_sha256']
        passed('copied_storage_requires_and_accepts_fresh_public_admission')
        # Failure after successful checkpoint export cannot mint host authority.
        fail = work / 'unknown-target'
        reject('query_failure_after_export_no_host', lambda: h.run_admit(c, fail, 'SU-000001-T9999'))
        assert (fail / 'checkpoint.json').exists() and not (fail / 'HOST.json').exists()
        assert json.loads((fail / 'WORKER_EXIT.json').read_bytes())['worker_reaped'] is True
        # Private worker never creates HOST, even if invoked without the coordinator.
        fail = work / 'checkpoint-save-failure'; fail.mkdir()
        (fail / 'REQUEST.json').write_bytes(h.canonical(c))
        (fail / 'checkpoint.json').write_bytes(b'preexisting')
        call_cli(['_admit-worker', '--output', str(fail), '--request-sha256', h.sha(h.canonical(c)), '--target', 'SU-000001-T0001'], expect=False)
        assert not (fail / 'ADMISSION.json').exists() and not (fail / 'HOST.json').exists() and (fail / 'checkpoint.json').read_bytes() == b'preexisting'
        passed('checkpoint_O_EXCL_failure_no_admission_or_host')
        alias = work / 'symlink.git'; alias.symlink_to(repo)
        reject('repository_symlink', lambda: h.input_contract(alias, n0, m, m, grant_path, grant_hash))
        alt = work / 'alternates.git'; shutil.copytree(repo, alt)
        (alt / 'objects/info/alternates').write_text(str(repo / 'objects') + '\n')
        reject('external_object_store_alternates', lambda: h.repository_gate(alt))
        changed = moved / 'core/merkle_map.py'
        with changed.open('ab') as stream: stream.write(b'\n# tamper\n')
        call_cli(['verify-bundle'], moved / 'host_checkpoint.py', expect=False)
        passed('changed_core_module_rejected')
        # The old clean receipt is not usable after a real native transition.
        r = p.Repo(repo)
        s = p.lazy_restore(r, (out / 'checkpoint.json').read_bytes(), admitted['checkpoint_sha256'], m)
        applied = p.apply(r, s, {'op': 'revise_text', 'id': 'SU-000001-P0001', 'expected_version': 0,
                                'text': 'Synthetic revised source only.', 'reason': 'local_technical_revision'})
        head = s.root; r.close()
        assert head != m
        reject('stale_checkpoint_current_ref_advanced', lambda: h.run_query(c, out, admitted['host_sha256'], 'SU-000001-T0001'))
        reject('clean_mode_rejects_derived_H', lambda: h.input_contract(repo, n0, m, head, grant_path, grant_hash))
        derived = h.input_contract(repo, n0, m, head, grant_path, grant_hash, True)
        dh = h.run_admit(derived, work / 'derived-host', 'SU-000001-T0001')
        dq = h.run_query(derived, work / 'derived-host', dh['host_sha256'], 'SU-000001-T0001')
        assert dq['query']['known_obligations'] > 0 and dq['query'] == dh['query']
        passed('explicit_derived_restore_replay_then_checkpoint_query', known_obligations=dq['query']['known_obligations'])
        # Current expected H cannot reuse M receipt even if caller updates input.
        reject('old_checkpoint_with_new_external_latest', lambda: h.run_query(derived, out, admitted['host_sha256'], 'SU-000001-T0001'))
        assert not list(repo.glob('query-cache.sqlite*'))
        passed('ordinary_host_admit_query_derived_reopen_never_persist_query_results')
        # Runtime path contains no archived driver dependency.
        for entry in ('/workspace/', 'v41-receiver-checkpoint-reentry/', 'v40-fullpack-hot-receive/'):
            assert entry not in (HERE / 'host_checkpoint.py').read_text()
        passed('no_absolute_historical_runtime_dependency')
    assert source_before == {name: h.sha((HERE / 'core' / name).read_bytes()) for name in source_before}
    return {'status': 'PASS', 'cases': rows, 'case_count': len(rows), 'synthetic_only': True,
            'real_corpus_reads': 0, 'literary_edits': 0, 'remote_calls': 0,
            'candidate_core_unchanged_during_tests': True, 'bundle_sha256': h.BUNDLE_SHA256,
            'runtime_sha256': h.runtime_pin(), 'wall_seconds': time.monotonic() - started,
            'limits': 'Focused host tests, not exhaustive core regression, hostile same-UID protection, concurrent race stress or power-loss proof.'}


if __name__ == '__main__':
    with h.local_environment():
        result = run_tests()
    destination = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / 'TEST_RESULTS.json'
    destination.write_bytes(h.canonical(result))
    print(json.dumps({'status': result['status'], 'cases': result['case_count'], 'wall_seconds': result['wall_seconds']}))
