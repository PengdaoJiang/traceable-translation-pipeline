"""Focused provider contract tests; run with python -m unittest -v test_platform_api."""
import builtins
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import platform_api as p


class PlatformAPIContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_probe_actual_operations_and_required_capabilities(self):
        report = p.probe(self.root, required=p.CAPABILITIES)
        self.assertTrue(all(v['available'] for v in report['capabilities'].values()))
        self.assertEqual(len(report['provider']['source_sha256']), 64)
        self.assertEqual(json.loads(json.dumps(report)), report)

    def test_import_without_posix_only_primitives(self):
        code = '''
import builtins, os, importlib.util, sys
real_import = builtins.__import__
def limited_import(name, *args, **kwargs):
    if name in ('fcntl', 'resource'):
        raise ImportError('deliberately unavailable')
    return real_import(name, *args, **kwargs)
builtins.__import__ = limited_import
for name in ('O_DIRECTORY','O_NOFOLLOW','killpg','setsid','getpgid'):
    if hasattr(os, name): delattr(os,name)
spec=importlib.util.spec_from_file_location('independent',sys.argv[1])
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
print('import-ok')
'''
        result = subprocess.run([sys.executable, '-c', code, p.__file__],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'import-ok')

    def test_exclusive_preserves_file_and_symlink(self):
        target = self.root / 'existing'
        p.write_exclusive(target, b'original')
        with self.assertRaises(FileExistsError):
            p.write_exclusive(target, b'overwrite')
        link = self.root / 'symlink'
        link.symlink_to(target)
        with self.assertRaises(FileExistsError):
            p.write_exclusive(link, b'overwrite')
        with self.assertRaises(OSError):
            p.open_read(link)
        self.assertEqual(target.read_bytes(), b'original')

    def test_publish_retains_source_and_preserves_collisions(self):
        source, dest, link = [self.root / n for n in ('source', 'dest', 'link')]
        p.write_exclusive(source, b'content')
        p.publish_noreplace(source, dest)
        self.assertEqual(source.read_bytes(), b'content')
        self.assertEqual(dest.read_bytes(), b'content')
        link.symlink_to(dest)
        for occupied in (dest, link):
            with self.assertRaises(FileExistsError):
                p.publish_noreplace(source, occupied)
        self.assertTrue(link.is_symlink())
        self.assertEqual(dest.read_bytes(), b'content')

    def test_missing_sync_is_explicit_and_probe_fails_closed(self):
        with mock.patch.object(os, 'fsync', None):
            with self.assertRaises(p.CapabilityUnavailable) as caught:
                p.probe(self.root, required=['directory_sync'])
        self.assertEqual(caught.exception.capability, 'directory_sync')
        self.assertFalse(caught.exception.report['capabilities']['file_sync']['available'])

    def test_directory_flag_not_required(self):
        with mock.patch.object(os, 'O_DIRECTORY', 0):
            p.sync_directory(self.root)
        regular = self.root / 'regular'
        regular.write_bytes(b'not a directory')
        with mock.patch.object(os, 'O_DIRECTORY', 0):
            with self.assertRaises(p.CapabilityUnavailable):
                p.sync_directory(regular)

    def test_missing_nofollow_fails_closed(self):
        target = self.root / 'target'
        target.write_bytes(b'content')
        with mock.patch.object(os, 'O_NOFOLLOW', None):
            with self.assertRaises(p.CapabilityUnavailable) as caught:
                p.open_read(target)
        self.assertEqual(caught.exception.capability, 'nofollow_read')

    def test_limits_rejection_prevents_command_execution(self):
        marker = self.root / 'must-not-run'
        result = subprocess.run([sys.executable, p.__file__, '--exec-limited',
                                 '0', '30', '1048576', sys.executable, '-c',
                                 f'open({str(marker)!r},"w").close()'],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists())
        self.assertIn('memory_limit', result.stderr)

    def test_limit_exec_readback(self):
        code = ('import resource,json;print(json.dumps([resource.getrlimit(k) '
                'for k in (resource.RLIMIT_AS,resource.RLIMIT_CPU,resource.RLIMIT_FSIZE)]))')
        result = subprocess.run([sys.executable, p.__file__, '--exec-limited',
                                 '1073741824', '30', '1048576', sys.executable, '-c', code],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [[1073741824]*2, [30]*2, [1048576]*2])

    def test_group_kill_closes_grandchild_pipe_after_leader_exit(self):
        code = ('import subprocess,sys; subprocess.Popen([sys.executable,"-c",'
                '"import time;time.sleep(60)"]); print("ready",flush=True)')
        proc = p.spawn_supervised([sys.executable, '-c', code], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
        try:
            proc.wait(timeout=10)  # leader exits while grandchild keeps pipes open
            p.terminate_and_reap(proc)
            out, err = proc.communicate(timeout=10)
            self.assertEqual(out.strip(), b'ready')
        finally:
            if proc.poll() is None:
                p.terminate_and_reap(proc)
            proc.stdout.close(); proc.stderr.close()

    def test_missing_supervision_fails_before_spawn(self):
        with mock.patch.object(os, 'killpg', None), mock.patch.object(subprocess, 'Popen') as spawn:
            with self.assertRaises(p.CapabilityUnavailable) as caught:
                p.spawn_supervised([sys.executable, '-c', 'pass'])
            spawn.assert_not_called()
        self.assertEqual(caught.exception.capability, 'process_group_supervision')

    def test_unpinned_provider_rejected(self):
        with self.assertRaises(p.CapabilityUnavailable):
            p.configure_provider(p.StdlibProvider(), expected_sha256='wrong')

    def test_short_write_rejected_before_sync(self):
        handle = mock.MagicMock()
        handle.__enter__.return_value = handle
        handle.write.return_value = 1
        with mock.patch.object(p._provider, 'open_exclusive', return_value=handle), \
             mock.patch.object(p._provider, 'sync_file') as sync:
            with self.assertRaisesRegex(OSError, 'SHORT_WRITE'):
                p.write_exclusive(self.root / 'short', b'long')
            sync.assert_not_called()

    def test_lock_database_symlink_rejected(self):
        other = self.root / 'unrelated'
        other.write_bytes(b'untouched')
        Path(str(self.root / 'lock') + '.sqlite3').symlink_to(other)
        with self.assertRaises(p.CapabilityUnavailable) as caught:
            with p.repository_lock(self.root / 'lock'):
                pass
        self.assertEqual(caught.exception.capability, 'repository_lock')
        self.assertEqual(other.read_bytes(), b'untouched')

    def test_probe_children_reaped_and_pipes_closed_on_communicate_failure(self):
        original_child = p._child
        original_supervised = p.spawn_supervised
        # Positions: lock contender, crash-release lock holder, limit reader.
        for position in range(3):
            for failure in ('timeout', 'exception'):
                with self.subTest(position=position, failure=failure):
                    children, supervised = [], []
                    def child(*args):
                        index = len(children)
                        if index == position:
                            proc = subprocess.Popen(
                                [sys.executable, '-c', 'import time; time.sleep(60)'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            error = (subprocess.TimeoutExpired(proc.args, 10)
                                     if failure == 'timeout' else RuntimeError('injected communicate failure'))
                            proc.communicate = mock.Mock(side_effect=error)
                        else:
                            proc = original_child(*args)
                        children.append(proc)
                        return proc
                    def supervised_child(*args, **kwargs):
                        proc = original_supervised(*args, **kwargs)
                        supervised.append(proc)
                        return proc
                    try:
                        with mock.patch.object(p, '_child', side_effect=child), \
                             mock.patch.object(p, 'spawn_supervised', side_effect=supervised_child):
                            report = p.probe(self.root)
                        self.assertGreater(len(children), position)
                        capability = 'worker_limits' if position == 2 else 'repository_lock'
                        self.assertFalse(report['capabilities'][capability]['available'])
                        for proc in children + supervised:
                            self.assertIsNotNone(proc.returncode, 'probe did not reap child')
                            self.assertTrue(proc.stdout.closed)
                            self.assertTrue(proc.stderr.closed)
                            if hasattr(proc.communicate, 'call_count'):
                                self.assertEqual(proc.communicate.call_count, 1,
                                                 'cleanup must not retry broken communicate')
                    finally:
                        for proc in children + supervised:
                            if proc.poll() is None:
                                proc.kill()
                            proc.wait(timeout=10)
                            proc.stdout.close()
                            proc.stderr.close()

    def test_probe_normal_children_close_pipes(self):
        children = []
        original = p._child
        def child(*args):
            proc = original(*args)
            children.append(proc)
            return proc
        with mock.patch.object(p, '_child', side_effect=child):
            p.probe(self.root, required=p.CAPABILITIES)
        self.assertEqual(len(children), 3)
        for proc in children:
            self.assertIsNotNone(proc.returncode)
            self.assertTrue(proc.stdout.closed)
            self.assertTrue(proc.stderr.closed)

    def test_optimized_python_rejects_broken_provider_semantics(self):
        code = """
import json, pathlib, sys
sys.path.insert(0, sys.argv[1])
import platform_api as p
# Replacement falsely returns success without changing either path.
p._provider.atomic_replace = lambda src, dst: None
report = p.probe(sys.argv[2])
if report['capabilities']['atomic_replace']['available']:
    raise SystemExit('broken replacement incorrectly admitted under optimization')
try:
    p.probe(sys.argv[2], required=['atomic_replace'])
except p.CapabilityUnavailable as exc:
    if exc.capability != 'atomic_replace':
        raise SystemExit('wrong required capability failure')
else:
    raise SystemExit('required broken capability was admitted')
print('optimized-checks-active')
"""
        for flags, env in ((['-O'], os.environ.copy()),
                           ([], dict(os.environ, PYTHONOPTIMIZE='2'))):
            with self.subTest(flags=flags, optimize=env.get('PYTHONOPTIMIZE')):
                result = subprocess.run([sys.executable, *flags, '-c', code,
                                         str(Path(p.__file__).parent), str(self.root)],
                                        capture_output=True, text=True, timeout=20, env=env)
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                self.assertEqual(result.stdout.strip(), 'optimized-checks-active')

    def test_snapshot_does_not_guess_rss_units(self):
        snap = p.resource_snapshot()
        self.assertEqual(snap['max_rss_unit'], 'provider_native_unspecified')
        self.assertGreaterEqual(snap['user_seconds'], 0)


if __name__ == '__main__':
    unittest.main()
