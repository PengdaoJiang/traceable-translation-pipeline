"""Bounded scratch indices for a live cooperative immutable-storage epoch.

These are not semantic admission or publication authority. Repositories must hold
an integrity operation, and must invalidate their service at every GC/import
barrier. MACs protect scratch rows, not against hostile live process memory.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import tempfile
import time


class RunBudget:
    """Execution limits, deliberately independent of semantic event limits."""
    def __init__(self, *, max_visits=10_000_000, max_bytes=1 << 40,
                 max_seconds=3600):
        if (type(max_visits) is not int or max_visits < 1 or
                type(max_bytes) is not int or max_bytes < 0 or
                not isinstance(max_seconds, (int, float)) or
                not 0 < max_seconds < float('inf')):
            raise ValueError('invalid explicit run budget')
        self.max_visits, self.max_bytes = max_visits, max_bytes
        self.max_seconds = max_seconds
        self.visits = self.bytes = 0
        self.started = time.monotonic()

    def check(self, k):
        k.need(time.monotonic() - self.started <= self.max_seconds,
               'run wall budget exhausted (not semantic event limit)')

    def charge(self, k, size):
        self.check(k)
        self.visits += 1
        self.bytes += size
        k.need(self.visits <= self.max_visits and self.bytes <= self.max_bytes,
               'run traversal/byte budget exhausted (not semantic event limit)')


class _Scratch:
    def __init__(self, k, r, directory, budget):
        k.need(r.epoch is not None, 'proof requires live integrity epoch')
        self.k, self.r, self.epoch = k, r, r.epoch
        self.service = k._service_key(r.service_key)  # strong ref: no id reuse
        self.repo_path, self.service_key = str(r.path), r.service_key
        self.budget = budget or RunBudget()
        self.key = secrets.token_bytes(32)
        fd, name = tempfile.mkstemp(prefix='v26-proof-', suffix='.sqlite', dir=directory)
        os.close(fd)
        self.path = Path(name)
        self.db = sqlite3.connect(name)
        self.db.execute('PRAGMA cache_size=-1024')
        self.db.execute('PRAGMA temp_store=FILE')
        self.closed = False

    def check(self):
        self.k.need(not self.closed and self.key is not None and
                    self.r.epoch is self.epoch and self.epoch is not None and
                    str(self.r.path) == self.repo_path and
                    self.r.service_key == self.service_key and
                    self.k._service_key(self.r.service_key) is self.service,
                    'proof closed or repository/epoch/service barrier changed')
        self.budget.check(self.k)

    def mac(self, fields):
        return hmac.new(self.key, json.dumps(fields, separators=(',', ':')).encode(),
                        hashlib.sha256).hexdigest()

    def load(self, oid, kind):
        self.check()
        self.k.need(isinstance(oid, str) and self.k.OID.fullmatch(oid), 'proof object OID')
        self.k.need(self.budget.visits < self.budget.max_visits, 'run traversal budget exhausted')
        actual, raw = self.r._load(oid, kind, 'durable_proof')
        self.check()
        self.k.need(actual == kind and type(raw) is bytes and
                    len(raw) <= self.k.SCHEMA['object_bytes_max'] and
                    self.k.oid(kind, raw) == oid, 'durable object type/length/identity')
        self.budget.charge(self.k, len(raw))
        # Never flush: reconstructed missing objects must remain missing.
        if len(self.r.operation_admitted) >= 512:
            self.k.need(self.r.batch_enabled and self.r.batch_readonly,
                        'proof rollover requires readonly object batch')
            self.r.release_batch()
        return raw

    def close(self):
        if not self.closed:
            self.closed = True
            self.key = None
            self.db.close()
            self.path.unlink(missing_ok=True)
            for suffix in ('-journal', '-wal', '-shm'):
                Path(str(self.path) + suffix).unlink(missing_ok=True)

    def __del__(self):
        if getattr(self, 'closed', True) is False:
            self.close()

    def __enter__(self):
        self.check()
        return self

    def __exit__(self, *args):
        self.close()


def _header(k, raw):
    header = raw.split(b'\n\n', 1)[0].splitlines()
    k.need(header and header[0].startswith(b'tree '), 'commit tree header')
    try:
        trees = [x[5:].decode('ascii') for x in header if x.startswith(b'tree ')]
        parents = [x[7:].decode('ascii') for x in header if x.startswith(b'parent ')]
    except UnicodeError:
        raise k.Rejected('commit header encoding') from None
    k.need(len(trees) == 1 and len(parents) <= 1 and
           all(k.OID.fullmatch(x) for x in trees + parents), 'single-parent commit header')
    return trees[0], parents[0] if parents else None


class DiskAncestry(_Scratch):
    """Newest-first disk index; stop is included and must be reachable if given."""
    def __init__(self, k, r, root, directory=None, budget=None, stop=None):
        super().__init__(k, r, directory, budget)
        self.db.execute('CREATE TABLE chain (seq INTEGER PRIMARY KEY, oid TEXT UNIQUE, tree TEXT, parent TEXT, digest TEXT, mac TEXT)')
        self.count = 0
        self.root = root
        try:
            head = root
            while head:
                self.check()
                k.need(not self.db.execute('SELECT 1 FROM chain WHERE oid=?', (head,)).fetchone(), 'ancestry cycle')
                raw = self.load(head, 'commit')
                tree, parent = _header(k, raw)
                fields = [self.count, head, tree, parent, hashlib.sha256(raw).hexdigest()]
                self.db.execute('INSERT INTO chain VALUES (?,?,?,?,?,?)', (*fields, self.mac(fields)))
                self.count += 1
                del raw
                if head == stop:
                    break
                head = parent
            k.need(stop is None or head == stop, 'ancestry stop not reachable')
            self.db.commit()
        except BaseException:
            self.close()
            raise

    def __len__(self):
        self.check()
        return self.count

    def __contains__(self, oid):
        self.check()
        row = self.db.execute('SELECT * FROM chain WHERE oid=?', (oid,)).fetchone()
        if row is None:
            return False
        self.k.need(isinstance(row[-1], str) and hmac.compare_digest(row[-1], self.mac(list(row[:-1]))), 'ancestry row authentication')
        return True

    def rows(self, oldest=False):
        self.check()
        expected = self.count - 1 if oldest else 0
        for row in self.db.execute('SELECT * FROM chain ORDER BY seq ' + ('DESC' if oldest else 'ASC')):
            self.check()
            self.k.need(row[0] == expected and isinstance(row[-1], str) and
                        hmac.compare_digest(row[-1], self.mac(list(row[:-1]))), 'ancestry row authentication/order')
            yield row[1:5]
            expected += -1 if oldest else 1
        self.k.need(expected == (-1 if oldest else self.count), 'ancestry rows missing')

    def newest(self):
        return (row[0] for row in self.rows())

    def oldest(self):
        return (row[0] for row in self.rows(True))

    def __iter__(self):
        return self.newest()


class DurableClosure(_Scratch):
    """Disk-deduplicated complete closure; no tokens and no semantic shortcuts."""
    def __init__(self, k, r, directory=None, budget=None):
        super().__init__(k, r, directory, budget)
        self.db.execute('CREATE TABLE proofs (oid TEXT PRIMARY KEY, kind TEXT, bytes INTEGER, digest TEXT, complete INTEGER, height INTEGER, mac TEXT) WITHOUT ROWID')
        self.counts = dict.fromkeys(('commit', 'tree', 'blob'), 0)
        self.payload_bytes = 0
        self.rolling = hashlib.sha256()

    def proved(self, oid, kind, depth=0):
        self.check()
        row = self.db.execute('SELECT * FROM proofs WHERE oid=?', (oid,)).fetchone()
        if row is None:
            return False
        self.k.need(isinstance(row[-1], str) and
                    hmac.compare_digest(row[-1], self.mac(list(row[:-1]))) and
                    row[1] == kind and row[4] == 1 and type(row[5]) is int and
                    row[5] >= 0 and (kind == 'commit' or depth + row[5] <= 100),
                    'closure proof row authentication/type/completion/depth')
        return True

    def record(self, oid, kind, size, digest, height=0):
        self.check()
        fields = [oid, kind, size, digest, 1, height]
        self.db.execute('INSERT OR REPLACE INTO proofs VALUES (?,?,?,?,?,?,?)', (*fields, self.mac(fields)))
        self.counts[kind] += 1
        self.payload_bytes += size
        self.rolling.update(json.dumps(fields, separators=(',', ':')).encode() + b'\n')

    def tree(self, root):
        # At most 101 frames, each holding at most 200 child descriptors, no raw
        # ancestor bytes or global visited set. Completed DAG nodes live on disk.
        active = set()
        def visit(oid, kind, depth):
            self.check()
            self.k.need(depth <= 100, 'durable closure depth limit')
            self.k.need(oid not in active, 'durable closure cycle')
            if self.proved(oid, kind, depth):
                return self.db.execute('SELECT height FROM proofs WHERE oid=?', (oid,)).fetchone()[0]
            raw = self.load(oid, kind)
            size, digest = len(raw), hashlib.sha256(raw).hexdigest()
            children = self.k.parse_tree(raw) if kind == 'tree' else {}
            self.k.need(len(children) <= 200, 'durable closure fanout limit')
            del raw
            active.add(oid)
            try:
                height = 0
                for mode, child in children.values():
                    self.k.need(mode in ('40000', '100644'), 'durable closure child mode')
                    height = max(height, 1 + visit(child, 'tree' if mode == '40000' else 'blob', depth + 1))
                self.record(oid, kind, size, digest, height)
                return height
            finally:
                active.remove(oid)
        visit(root, 'tree', 0)

    def verify(self, root):
        self.check()
        self.k.need(not self.r.staged and self.r.batch_enabled and self.r.batch_readonly,
                    'closure requires flushed readonly batch')
        with DiskAncestry(self.k, self.r, root, self.path.parent, self.budget) as ancestry:
            for commit, tree, parent, digest in ancestry.rows(oldest=True):
                if self.proved(commit, 'commit'):
                    continue
                raw = self.load(commit, 'commit')
                self.k.need(_header(self.k, raw) == (tree, parent) and
                            hashlib.sha256(raw).hexdigest() == digest, 'ancestry bytes changed')
                size = len(raw)
                del raw
                self.tree(tree)
                self.k.need(parent is None or self.proved(parent, 'commit'), 'parent closure incomplete')
                self.record(commit, 'commit', size, digest)
            self.check()
            row = next(ancestry.rows())
            result = {'commit': root, 'tree': row[1], 'commit_sha256': row[3],
                      'ancestor_commits': len(ancestry), 'object_counts': dict(self.counts),
                      'object_visits': sum(self.counts.values()), 'payload_bytes': self.payload_bytes,
                      'closure_sha256': self.rolling.hexdigest(), 'run_loads': self.budget.visits,
                      'run_bytes': self.budget.bytes}
        self.db.commit()
        return result
