"""Immutable, bounded Git radix map. No authority or publication semantics.

Keys are one or two strings, encoded as canonical UTF-8 JSON. Iteration order
is (SHA256(key), canonical key). Branches are not collapsed on deletion, so
valid historical shapes need not equal the deterministic fresh bulk shape.
All references are real Git tree edges, including tree-valued map entries.
The caller owns Repo batching/epochs and durable publication.
"""
import hashlib
import json
import re
from collections import deque, OrderedDict

MAX_COUNT = 2**63 - 1
MAX_KEY = 512
MAX_LEAF = 32
MAX_DESCRIPTOR = 8192
KEY_MEMO_BYTES = 512 * 1024
KEY_MEMO_ENTRIES = 2048
KEY_MEMO_FIXED_CHARGE = 192
HEX = '0123456789abcdef'
OID = re.compile(r'[0-9a-f]{40}\Z')


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


class MerkleMap:
    def __init__(self, k, repo, hash_key=None):
        self.k, self.r = k, repo
        self.hash_key = hash_key or (lambda b: hashlib.sha256(b).hexdigest())
        # Pure immutable key encoding/hash memo, never map or admission state.
        # The supplied hash function must be pure and fixed for this instance.
        self._key_memo = OrderedDict()
        self._key_memo_bytes = 0
        self.counters = {'reads': 0, 'stages': 0, 'pathdepth': 0, 'nodes': 0,
                         'key_memo_hits': 0, 'key_memo_misses': 0,
                         'key_memo_evictions': 0, 'key_memo_bytes': 0,
                         'key_memo_entries': 0}

    def need(self, condition, message):
        self.k.need(condition, 'merkle map: ' + message)

    def key(self, key):
        self.need(type(key) is list and len(key) in (1, 2) and all(type(s) is str for s in key), 'exact key')
        # Bound tuple hashing too, before looking up a potentially giant string.
        self.need(all(len(s) <= MAX_KEY for s in key), 'key bytes')
        exact = tuple(key)
        cached = self._key_memo.get(exact)
        if cached is not None:
            self._key_memo.move_to_end(exact)
            self.counters['key_memo_hits'] += 1
            return cached[0]
        self.counters['key_memo_misses'] += 1
        try:
            b = canonical(key)
        except (ValueError, UnicodeError):
            self.need(False, 'key encoding')
        self.need(len(b) <= MAX_KEY, 'key bytes')
        h = self.hash_key(b)
        self.need(type(h) is str and re.fullmatch('[0-9a-f]{64}', h) is not None, 'key hash')
        result = (h, b)
        charge = len(b) + sum(len(s.encode('utf-8')) for s in exact) + KEY_MEMO_FIXED_CHARGE
        while self._key_memo and (len(self._key_memo) >= KEY_MEMO_ENTRIES or
                                  self._key_memo_bytes + charge > KEY_MEMO_BYTES):
            _, (_, old_charge) = self._key_memo.popitem(last=False)
            self._key_memo_bytes -= old_charge
            self.counters['key_memo_evictions'] += 1
        self.need(charge <= KEY_MEMO_BYTES, 'key memo entry charge')
        self._key_memo[exact] = (result, charge)
        self._key_memo_bytes += charge
        self.counters['key_memo_bytes'] = self._key_memo_bytes
        self.counters['key_memo_entries'] = len(self._key_memo)
        return result

    def _get(self, oid, kind):
        self.counters['reads'] += 1
        return self.r.get(oid, kind)

    def _stage(self, kind, data):
        self.counters['stages'] += 1
        return self.r.stage(kind, data)

    def _count(self, n):
        self.need(type(n) is int and 0 <= n <= MAX_COUNT, 'count')

    def _value(self, kind, oid, read=False):
        self.need(kind in ('blob', 'tree') and type(oid) is str and OID.fullmatch(oid) is not None, 'typed value')
        if read:
            self._get(oid, kind)

    def _load(self, root, prefix):
        self.need(len(prefix) <= 64 and all(c in HEX for c in prefix), 'prefix')
        self.counters['pathdepth'] = max(self.counters['pathdepth'], len(prefix))
        tree = self.k.parse_tree(self._get(root, 'tree'))
        self.need('meta' in tree and tree['meta'][0] == '100644', 'descriptor edge')
        raw = self._get(tree['meta'][1], 'blob')
        self.need(len(raw) <= MAX_DESCRIPTOR, 'descriptor bytes')
        try:
            m = json.loads(raw)
            self.need(canonical(m) == raw, 'canonical descriptor')
        except (ValueError, UnicodeError, TypeError):
            self.need(False, 'descriptor encoding')
        self.need(type(m) is dict and set(m) == {'v', 'type', 'prefix', 'count', 'items'}, 'descriptor fields')
        self.need(type(m['v']) is int and m['v'] == 1 and m['prefix'] == prefix, 'version/prefix')
        self._count(m['count'])
        self.need(type(m['items']) is list, 'items')
        if m['type'] == 'leaf':
            self.need(len(m['items']) <= MAX_LEAF and len(m['items']) == m['count'], 'leaf count')
            expected = {'meta'}
            previous = None
            for i, item in enumerate(m['items']):
                self.need(type(item) is dict and set(item) == {'key', 'kind'}, 'leaf fields')
                h, b = self.key(item['key'])
                self.need(h.startswith(prefix), 'leaf hash prefix')
                self.need(previous is None or previous[0] < h, 'duplicate key/hash collision/order')
                previous = (h, b)
                name = 'v%04d' % i
                expected.add(name)
                self.need(name in tree, 'value edge absent')
                mode, oid = tree[name]
                self._value(item['kind'], oid)
                self.need(mode == ('40000' if item['kind'] == 'tree' else '100644'), 'value edge type')
            self.need(set(tree) == expected, 'extra leaf edges')
        else:
            self.need(m['type'] == 'branch' and len(prefix) < 64 and 1 <= len(m['items']) <= 16, 'branch shape')
            expected, total, previous = {'meta'}, 0, ''
            for item in m['items']:
                self.need(type(item) is list and len(item) == 2, 'branch item')
                digit, count = item
                self.need(type(digit) is str and len(digit) == 1 and digit in HEX and digit > previous, 'branch order')
                self._count(count)
                self.need(count > 0, 'empty branch child')
                total += count
                previous = digit
                expected.add(digit)
                self.need(digit in tree and tree[digit][0] == '40000', 'branch edge')
            self.need(set(tree) == expected and total == m['count'], 'branch count/extra edges')
        return m, tree

    def _write(self, prefix, typ, items, edges, count):
        self.counters['pathdepth'] = max(self.counters['pathdepth'], len(prefix))
        self._count(count)
        meta = canonical(dict(v=1, type=typ, prefix=prefix, count=count, items=items))
        self.need(len(meta) <= MAX_DESCRIPTOR, 'descriptor overflow')
        edges = dict(edges)
        edges['meta'] = ('100644', self._stage('blob', meta))
        return self._stage('tree', self.k.tree_bytes(edges)), count

    def _leaf_data(self, prefix, rows):
        return canonical(dict(v=1, type='leaf', prefix=prefix, count=len(rows), items=[{'key': key, 'kind': kind} for key, kind, oid in rows]))

    def _fits(self, prefix, rows):
        return len(rows) <= MAX_LEAF and len(self._leaf_data(prefix, rows)) <= MAX_DESCRIPTOR

    def _leaf(self, prefix, rows):
        return self._write(prefix, 'leaf', [{'key': key, 'kind': kind} for key, kind, oid in rows], {'v%04d' % i: ('40000' if kind == 'tree' else '100644', oid) for i, (key, kind, oid) in enumerate(rows)}, len(rows))

    def _branch(self, prefix, children):
        children = {d: pair for d, pair in children.items() if pair[1]}
        if not children:
            return self._leaf(prefix, [])
        return self._write(prefix, 'branch', [[d, children[d][1]] for d in sorted(children)], {d: ('40000', pair[0]) for d, pair in children.items()}, sum(pair[1] for pair in children.values()))

    def empty(self):
        return self._leaf('', [])

    def count(self, root):
        return self._load(root, '')[0]['count']

    def _rows(self, m, tree):
        return [(item['key'], item['kind'], tree['v%04d' % i][1]) for i, item in enumerate(m['items'])]

    def lookup(self, root, key):
        h, b = self.key(key)
        prefix, expected = '', None
        while True:
            m, tree = self._load(root, prefix)
            self.need(expected is None or expected == m['count'], 'child count')
            if m['type'] == 'leaf':
                for stored, kind, oid in self._rows(m, tree):
                    sh, sb = self.key(stored)
                    self.need(sh != h or sb == b, 'full hash collision')
                    if sb == b:
                        self._value(kind, oid, True)
                        return kind, oid
                return None
            digit = h[len(prefix)]
            counts = dict(m['items'])
            if digit not in counts:
                return None
            root, expected, prefix = tree[digit][1], counts[digit], prefix + digit

    def insert(self, root, key, kind, oid):
        self.key(key)
        self._value(kind, oid, True)
        return self._update(root, '', key, (kind, oid))

    def delete(self, root, key):
        self.key(key)
        return self._update(root, '', key, None)

    def _update(self, root, prefix, key, value, expected=None):
        h, b = self.key(key)
        m, tree = self._load(root, prefix)
        self.need(expected is None or m['count'] == expected, 'child count')
        if m['type'] == 'leaf':
            rows = self._rows(m, tree)
            for stored, kind, oid in rows:
                sh, sb = self.key(stored)
                self.need(sh != h or sb == b, 'full hash collision')
            rows = [row for row in rows if canonical(row[0]) != b]
            if value is not None:
                rows.append((key, value[0], value[1]))
            rows.sort(key=lambda row: self.key(row[0]))
            return self._build_small(prefix, rows)
        digit = h[len(prefix)]
        children = {d: (tree[d][1], n) for d, n in m['items']}
        if digit not in children:
            if value is None:
                return root, m['count']
            children[digit] = self._leaf(prefix + digit, [(key, *value)])
        else:
            old, count = children[digit]
            children[digit] = self._update(old, prefix + digit, key, value, count)
        return self._branch(prefix, children)

    def _build_small(self, prefix, rows):
        if self._fits(prefix, rows):
            return self._leaf(prefix, rows)
        self.need(len(prefix) < 64, 'full hash collision/oversize leaf')
        children = {}
        for digit in HEX:
            group = [row for row in rows if self.key(row[0])[0][len(prefix)] == digit]
            if group:
                children[digit] = self._build_small(prefix + digit, group)
        return self._branch(prefix, children)

    def iter_items(self, root):
        """Fully validate traversed map and typed value objects while yielding rows.

        Exhaust this iterator to validate the complete map. Each recursion frame
        holds at most one bounded node. No global visited set or payload cache.
        """
        yield from self._iter(root, '', None)

    def _iter(self, root, prefix, expected):
        m, tree = self._load(root, prefix)
        self.counters['nodes'] += 1
        self.need(expected is None or m['count'] == expected, 'child count')
        if m['type'] == 'leaf':
            for row in self._rows(m, tree):
                self._value(row[1], row[2], True)
                yield row
        else:
            for digit, count in m['items']:
                yield from self._iter(tree[digit][1], prefix + digit, count)

    def iter_from(self, root, after_hash=None, limit=64):
        """Seek strictly after a hash in an already-admitted map, yielding a page.

        Application page sizes are 1..256; 257 permits a one-row lookahead for
        the largest page. Skipped subtrees are not validated here. A cursor is
        an exclusive ordering position, not a membership or authority proof.
        """
        self.need(after_hash is None or (type(after_hash) is str and
                  re.fullmatch('[0-9a-f]{64}', after_hash) is not None), 'cursor hash')
        self.need(type(limit) is int and 1 <= limit <= 257, 'cursor limit')
        remaining = limit
        def walk(oid, prefix, expected):
            nonlocal remaining
            if not remaining or (after_hash is not None and
                                 prefix + 'f' * (64 - len(prefix)) <= after_hash):
                return
            m, tree = self._load(oid, prefix)
            self.counters['nodes'] += 1
            self.need(expected is None or m['count'] == expected, 'child count')
            if m['type'] == 'leaf':
                for row in self._rows(m, tree):
                    if after_hash is not None and self.key(row[0])[0] <= after_hash:
                        continue
                    self._value(row[1], row[2], True)
                    remaining -= 1
                    yield row
                    if not remaining:
                        return
            else:
                for digit, count in m['items']:
                    yield from walk(tree[digit][1], prefix + digit, count)
                    if not remaining:
                        return
        return walk(root, '', None)

    def validate(self, root):
        count = sum(1 for _ in self.iter_items(root))
        self.need(count == self.count(root), 'total count')
        return count

    def bulk_build(self, rows):
        """Build from externally sorted (key, kind, oid) rows, in hash/key order.

        Single pass, <=33 buffered rows plus <=64 bounded prefix frames. Values
        are checked one at a time. Duplicate keys and SHA collisions reject.
        """
        source, pending = iter(rows), deque()
        previous, ended = None, False
        def peek():
            nonlocal previous, ended
            if not pending and not ended:
                try:
                    row = next(source)
                except StopIteration:
                    ended = True
                    return None
                self.need(type(row) in (tuple, list) and len(row) == 3, 'bulk row')
                h, b = self.key(row[0])
                self.need(previous is None or previous[0] < h, 'bulk order/duplicate/hash collision')
                previous = (h, b)
                self._value(row[1], row[2], True)
                pending.append((h, (row[0], row[1], row[2])))
            return pending[0] if pending else None
        def build(prefix):
            collected = []
            while peek() is not None and peek()[0].startswith(prefix):
                collected.append(pending.popleft())
                if not self._fits(prefix, [row for h, row in collected]):
                    break
            if self._fits(prefix, [row for h, row in collected]):
                return self._leaf(prefix, [row for h, row in collected])
            self.need(len(prefix) < 64, 'bulk depth')
            pending.extendleft(reversed(collected))
            collected.clear()
            children = {}
            while peek() is not None and peek()[0].startswith(prefix):
                digit = peek()[0][len(prefix)]
                children[digit] = build(prefix + digit)
            return self._branch(prefix, children)
        result = build('')
        self.need(peek() is None, 'bulk unconsumed')
        return result
