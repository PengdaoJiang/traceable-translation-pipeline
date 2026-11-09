"""Operation-capability boundary; no OS-name dispatch and no weak fallbacks.

Storage operations require a trusted parent directory (not hostile path ancestors).
Sync calls attest an accepted fsync, not empirical survival of a power failure.
SQLite locking coordinates cooperating callers only. Process supervision covers a
new process group, not descendants that deliberately escape their group/session.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


class CapabilityUnavailable(RuntimeError):
    def __init__(self, capability, reason):
        self.capability = capability
        self.reason = str(reason)
        super().__init__(f"required capability {capability!r} unavailable: {reason}")


def _require(obj, name, capability):
    value = getattr(obj, name, None)
    if value is None:
        raise CapabilityUnavailable(capability, f"missing primitive {name}")
    return value


def _verify(condition, capability, reason):
    # Admission checks must remain active under -O and PYTHONOPTIMIZE.
    if not condition:
        raise CapabilityUnavailable(capability, reason)


def _resource(capability):
    try:
        return importlib.import_module('resource')
    except ImportError as exc:
        raise CapabilityUnavailable(capability, 'resource provider not installed') from exc


class StdlibProvider:
    """Bundled provider. Each operation attempts its required strong primitive."""
    def open_exclusive(self, path, buffering=-1):
        # O_EXCL|O_CREAT refuses an existing final-component symlink too.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0)
        fd = os.open(path, flags, 0o600)
        try:
            return os.fdopen(fd, 'wb', buffering=buffering)
        except BaseException:
            os.close(fd)
            raise

    def write_exclusive(self, path, data):
        with self.open_exclusive(path) as handle:
            written = handle.write(data)
            if written != len(data):
                raise OSError(f'SHORT_WRITE: expected {len(data)} bytes, wrote {written}')
            self.sync_file(handle)

    def open_read(self, path):
        flag = _require(os, 'O_NOFOLLOW', 'nofollow_read')
        fd = os.open(path, os.O_RDONLY | flag | getattr(os, 'O_BINARY', 0) |
                     getattr(os, 'O_NONBLOCK', 0))
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise CapabilityUnavailable('nofollow_read', 'target is not a regular file')
            return os.fdopen(fd, 'rb')
        except BaseException:
            os.close(fd)
            raise

    def sync_file(self, handle_or_fd):
        fn = _require(os, 'fsync', 'file_sync')
        if hasattr(handle_or_fd, 'fileno'):
            handle_or_fd.flush()
            fd = handle_or_fd.fileno()
        else:
            fd = handle_or_fd
        try:
            fn(fd)
        except OSError as exc:
            raise CapabilityUnavailable('file_sync', exc) from exc

    def sync_directory(self, path):
        nofollow = _require(os, 'O_NOFOLLOW', 'directory_sync')
        fn = _require(os, 'fsync', 'directory_sync')
        try:
            fd = os.open(path, os.O_RDONLY | nofollow | getattr(os, 'O_DIRECTORY', 0))
            try:
                if not stat.S_ISDIR(os.fstat(fd).st_mode):
                    raise CapabilityUnavailable('directory_sync', 'target is not a directory')
                fn(fd)
            finally:
                os.close(fd)
        except OSError as exc:
            raise CapabilityUnavailable('directory_sync', exc) from exc

    def publish_noreplace(self, src, dst):
        fn = _require(os, 'link', 'publish_noreplace')
        try:
            # Both paths must be in trusted directories; never replace dst.
            if not stat.S_ISREG(os.lstat(src).st_mode):
                raise CapabilityUnavailable('publish_noreplace', 'source is not a regular file')
            fn(src, dst, follow_symlinks=False)
        except FileExistsError:
            raise
        except (OSError, NotImplementedError, TypeError) as exc:
            raise CapabilityUnavailable('publish_noreplace', exc) from exc
        # Source lifetime belongs to the caller; publication retains evidence.

    def atomic_replace(self, src, dst):
        try:
            _require(os, 'replace', 'atomic_replace')(src, dst)
        except OSError as exc:
            raise CapabilityUnavailable('atomic_replace', exc) from exc

    @contextlib.contextmanager
    def repository_lock(self, path, timeout=30.0):
        try:
            sqlite3 = importlib.import_module('sqlite3')
        except ImportError as exc:
            raise CapabilityUnavailable('repository_lock', 'sqlite3 unavailable') from exc
        connection = None
        try:
            # Dedicated database; do not interpret a legacy flock file as SQLite.
            database = Path(str(path) + '.sqlite3')
            if database.is_symlink():
                raise CapabilityUnavailable('repository_lock', 'lock database is a symlink')
            connection = sqlite3.connect(str(database), timeout=timeout,
                                         isolation_level=None)
            connection.execute('PRAGMA locking_mode=NORMAL')
            connection.execute('BEGIN EXCLUSIVE')
        except sqlite3.Error as exc:
            if connection is not None:
                connection.close()
            if 'locked' in str(exc).lower() or 'busy' in str(exc).lower():
                raise TimeoutError(f'repository lock busy: {path}') from exc
            raise CapabilityUnavailable('repository_lock', exc) from exc
        try:
            yield
        finally:
            try:
                connection.rollback()
            finally:
                connection.close()

    def set_worker_limits(self, memory_bytes, cpu_seconds, file_bytes):
        resource = _resource('worker_limits')
        settings = [('RLIMIT_AS', memory_bytes, 'memory_limit'),
                    ('RLIMIT_CPU', cpu_seconds, 'cpu_limit'),
                    ('RLIMIT_FSIZE', file_bytes, 'file_limit')]
        setter = _require(resource, 'setrlimit', 'worker_limits')
        getter = _require(resource, 'getrlimit', 'worker_limits')
        resolved = []
        for name, amount, capability in settings:
            if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
                raise ValueError(f'{capability} must be a positive integer')
            resolved.append((_require(resource, name, capability), amount, capability))
        for key, amount, capability in resolved:
            try:
                setter(key, (amount, amount))
                if getter(key) != (amount, amount):
                    raise CapabilityUnavailable(capability, 'readback differs from requested limit')
            except (OSError, ValueError) as exc:
                raise CapabilityUnavailable(capability, exc) from exc
        values = {'memory_bytes': memory_bytes, 'cpu_seconds': cpu_seconds,
                  'file_bytes': file_bytes}
        return {'requested': values, 'observed': dict(values),
                'scope': 'per-process inherited limits, not aggregate tree/cgroup',
                'evidence': 'setrlimit succeeded and exact getrlimit readback matched'}

    def resource_snapshot(self):
        resource = _resource('resource_snapshot')
        try:
            usage = resource.getrusage(resource.RUSAGE_SELF)
        except (AttributeError, OSError) as exc:
            raise CapabilityUnavailable('resource_snapshot', exc) from exc
        return {'user_seconds': usage.ru_utime, 'system_seconds': usage.ru_stime,
                'max_rss_native': usage.ru_maxrss, 'max_rss_unit': 'provider_native_unspecified',
                'scope': 'self', 'provider': 'stdlib.resource.getrusage'}

    def spawn_supervised(self, command, **kwargs):
        _require(os, 'killpg', 'process_group_supervision')
        _require(os, 'getpgid', 'process_group_supervision')
        _require(os, 'setsid', 'process_group_supervision')
        if 'start_new_session' in kwargs or 'preexec_fn' in kwargs or 'process_group' in kwargs:
            raise ValueError('session and process group are owned by the supervisor')
        try:
            proc = subprocess.Popen(command, start_new_session=True, **kwargs)
        except (ValueError, NotImplementedError) as exc:
            raise CapabilityUnavailable('process_group_supervision', exc) from exc
        # Popen's exec handshake completes after setsid. The child can exit before
        # getpgid is queried, so its PID is the recorded session/group identifier.
        proc._platform_supervision = ('stdlib.new_session', proc.pid)
        return proc

    def terminate_and_reap(self, process, timeout=5.0):
        marker = getattr(process, '_platform_supervision', None)
        if marker != ('stdlib.new_session', process.pid):
            raise CapabilityUnavailable('process_group_supervision', 'process was not spawned by this provider')
        import signal
        kill = _require(os, 'killpg', 'process_group_supervision')
        # Kill the group even if its leader exited, to close inherited pipes.
        try:
            kill(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as exc:
            raise CapabilityUnavailable('process_group_supervision', exc) from exc
        return process.wait(timeout=timeout)


_provider = StdlibProvider()


def provider_identity():
    cls = type(_provider)
    path = inspect.getsourcefile(cls)
    if not path:
        raise CapabilityUnavailable('provider_identity', 'provider source is not inspectable')
    return {'provider': cls.__module__ + '.' + cls.__qualname__,
            'source_sha256': hashlib.sha256(Path(path).read_bytes()).hexdigest(),
            'process_scope': 'new process group; escaped descendants excluded',
            'durability_scope': 'fsync accepted by current filesystem; hardware not certified'}


def configure_provider(name, *, expected_sha256):
    """Select a bundled provider by name; new providers must be vendored and pinned.

    No caller-supplied objects, imports, entry points, or plugins are accepted.
    """
    registry = {'stdlib': StdlibProvider}
    if not isinstance(name, str) or name not in registry:
        raise CapabilityUnavailable('provider_identity', 'provider is not in the bundled registry')
    digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    if digest != expected_sha256:
        raise CapabilityUnavailable('provider_identity', 'bundled provider digest mismatch')
    global _provider
    _provider = registry[name]()


def open_exclusive(path, buffering=-1):
    return _provider.open_exclusive(path, buffering=buffering)


def write_exclusive(path, data):
    return _provider.write_exclusive(path, data)


def open_read(path):
    return _provider.open_read(path)


def sync_file(handle_or_fd):
    return _provider.sync_file(handle_or_fd)


def sync_directory(path):
    return _provider.sync_directory(path)


def publish_noreplace(src, dst):
    return _provider.publish_noreplace(src, dst)


def atomic_replace(src, dst):
    return _provider.atomic_replace(src, dst)


def repository_lock(path, timeout=30.0):
    return _provider.repository_lock(path, timeout=timeout)


def set_worker_limits(memory_bytes, cpu_seconds, file_bytes):
    return _provider.set_worker_limits(memory_bytes, cpu_seconds, file_bytes)


def resource_snapshot():
    return _provider.resource_snapshot()


def spawn_supervised(command, **kwargs):
    return _provider.spawn_supervised(command, **kwargs)


def terminate_and_reap(process, timeout=5.0):
    return _provider.terminate_and_reap(process, timeout=timeout)


STORAGE_CAPABILITIES = ('exclusive_create', 'nofollow_read', 'file_sync',
                        'directory_sync', 'publish_noreplace', 'atomic_replace',
                        'repository_lock')
CAPABILITIES = STORAGE_CAPABILITIES + ('worker_limits', 'resource_snapshot',
                                      'process_group_supervision')


def _child(code, *args):
    # Probe the bundled code, never a module found incidentally on sys.path.
    prefix = ('import importlib.util,sys; '
              's=importlib.util.spec_from_file_location("probe_platform",sys.argv[1]); '
              'p=importlib.util.module_from_spec(s); s.loader.exec_module(p); ')
    return subprocess.Popen([sys.executable, '-c', prefix + code, str(Path(__file__).resolve()),
                             *map(str, args)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)


@contextlib.contextmanager
def _probe_process(process):
    """Own every probe child through reap and pipe closure, even on exceptions.

    Cleanup deliberately uses wait, not communicate: the failed operation may be
    communicate itself. Probe fixtures do not spawn descendants or emit unbounded
    output. Nested finally blocks still close pipes if termination/reaping fails.
    """
    try:
        yield process
    finally:
        try:
            try:
                if process.poll() is None:
                    process.kill()
            finally:
                process.wait(timeout=10)
        finally:
            with contextlib.ExitStack() as cleanup:
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        cleanup.callback(stream.close)


def probe(directory, required=()):
    """Observe operations on this filesystem. Raises with .report for required failures.

    Tests process/resource capabilities in disposable children. Observations apply
    only to this provider/runtime/filesystem, not every machine or power-loss case.
    """
    unknown = set(required) - set(CAPABILITIES)
    if unknown:
        raise ValueError(f'unknown capabilities: {sorted(unknown)}')
    report = {'provider': provider_identity(), 'directory': str(Path(directory).resolve()),
              'capabilities': {}, 'limitations': [
                  'No power-loss or hardware-cache durability certification.',
                  'SQLite lock is cooperative and filesystem-local; distributed locking is not certified.',
                  'Process supervision excludes descendants that escape their process group.',
                  'Resource limit probe verifies kernel acceptance/readback, not every workload enforcement.',
                  'Path ancestors must be trusted; no hostile-directory traversal guarantee.',
                  'nofollow_read probe requires permission to create a test symlink.']}
    def observe(name, operation):
        try:
            operation()
        except Exception as exc:
            report['capabilities'][name] = {'available': False, 'reason': str(exc)}
        else:
            report['capabilities'][name] = {'available': True, 'evidence': 'observed operation succeeded'}
    with tempfile.TemporaryDirectory(prefix='.platform-probe-', dir=directory) as temp:
        root = Path(temp)
        def exclusive():
            target = root / 'exclusive'
            with open_exclusive(target) as f:
                f.write(b'one')
            try:
                with open_exclusive(target):
                    pass
            except FileExistsError:
                pass
            else:
                raise CapabilityUnavailable('exclusive_create', 'existing target was overwritten')
            _verify(target.read_bytes() == b'one', 'exclusive_create', 'collision changed existing content')
        observe('exclusive_create', exclusive)
        def read():
            target = root / 'read'
            target.write_bytes(b'read')
            with open_read(target) as f:
                _verify(f.read() == b'read', 'nofollow_read', 'readback content differs')
            link = root / 'symlink'
            os.symlink(target, link)
            try:
                with open_read(link):
                    pass
            except OSError:
                pass
            else:
                raise CapabilityUnavailable('nofollow_read', 'symlink followed')
        observe('nofollow_read', read)
        def file_sync():
            with open(root / 'sync', 'wb') as f:
                f.write(b'sync')
                sync_file(f)
        observe('file_sync', file_sync)
        def directory_sync():
            child_dir = root / 'namespace'
            child_dir.mkdir()
            sync_directory(child_dir)
            sync_directory(root)
            child_dir.rmdir()
            sync_directory(root)
        observe('directory_sync', directory_sync)
        def publish():
            src, dst, other = (root / name for name in ('src', 'dst', 'other'))
            src.write_bytes(b'first')
            publish_noreplace(src, dst)
            _verify(src.read_bytes() == b'first' and dst.read_bytes() == b'first',
                    'publish_noreplace', 'publication changed source or destination bytes')
            other.write_bytes(b'second')
            try:
                publish_noreplace(other, dst)
            except FileExistsError:
                pass
            else:
                raise CapabilityUnavailable('publish_noreplace', 'existing destination replaced')
            _verify(dst.read_bytes() == b'first' and other.read_bytes() == b'second',
                    'publish_noreplace', 'collision changed source or destination bytes')
        observe('publish_noreplace', publish)
        def replace():
            src, dst = root / 'replace-src', root / 'replace-dst'
            src.write_bytes(b'new'); dst.write_bytes(b'old')
            atomic_replace(src, dst)
            _verify(not src.exists() and dst.read_bytes() == b'new',
                    'atomic_replace', 'replacement did not move source and publish new bytes')
        observe('atomic_replace', replace)
        def lock():
            if type(_provider) is not StdlibProvider:
                raise CapabilityUnavailable('repository_lock', 'custom provider needs its own independent-process probe')
            path = root / 'lock'
            script = ('\nwith p.repository_lock(sys.argv[2], timeout=0.1):\n'
                      ' print("locked",flush=True)\n')
            with repository_lock(path):
                with _probe_process(_child(script, path)) as child:
                    out, err = child.communicate(timeout=10)
                    _verify(child.returncode != 0 and b'TimeoutError' in err,
                            'repository_lock', f'contender was not excluded: {out!r} {err!r}')
            with _probe_process(_child('import time;\nwith p.repository_lock(sys.argv[2]):\n print("locked",flush=True)\n time.sleep(60)', path)) as child:
                # communicate timeout proves readiness without unbounded readline.
                try:
                    out, err = child.communicate(timeout=0.5)
                except subprocess.TimeoutExpired as exc:
                    _verify(b'locked' in (exc.output or b''), 'repository_lock', 'lock child not ready')
                else:
                    raise CapabilityUnavailable('repository_lock', f'lock holder exited early: {out!r} {err!r}')
            with repository_lock(path, timeout=0.2):
                pass
        observe('repository_lock', lock)
        def limits():
            if type(_provider) is not StdlibProvider:
                raise CapabilityUnavailable('worker_limits', 'custom provider needs its own isolated probe')
            with _probe_process(_child('p.set_worker_limits(1073741824,30,1048576); print("limits-readback-ok")')) as child:
                out, err = child.communicate(timeout=10)
                _verify(child.returncode == 0 and b'limits-readback-ok' in out,
                        'worker_limits', f'limit readback failed: {err.decode(errors="replace")}')
        observe('worker_limits', limits)
        observe('resource_snapshot', resource_snapshot)
        def supervision():
            with _probe_process(spawn_supervised(
                    [sys.executable, '-c', 'import time; time.sleep(60)'],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)) as proc:
                _verify(os.getpgid(proc.pid) == proc.pid, 'process_group_supervision',
                        'child did not enter its own process group')
                terminate_and_reap(proc)
                _verify(proc.returncode is not None, 'process_group_supervision',
                        'terminated child was not reaped')
        observe('process_group_supervision', supervision)
    missing = [name for name in required if not report['capabilities'][name]['available']]
    if missing:
        exc = CapabilityUnavailable(missing[0], report['capabilities'][missing[0]]['reason'])
        exc.report = report
        raise exc
    return report


def _main():
    if len(sys.argv) >= 6 and sys.argv[1] == '--exec-limited':
        # Missing primitives or rejected limits stop here, before command exec.
        execute = _require(os, 'execvpe', 'limited_exec')
        set_worker_limits(*map(int, sys.argv[2:5]))
        execute(sys.argv[5], sys.argv[5:], os.environ.copy())
    elif len(sys.argv) == 3 and sys.argv[1] == '--probe':
        print(json.dumps(probe(sys.argv[2]), indent=2, sort_keys=True))
    else:
        raise SystemExit('usage: platform_api.py --probe DIRECTORY | --exec-limited MEMORY CPU FILE COMMAND...')


if __name__ == '__main__':
    _main()
