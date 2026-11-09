#!/usr/bin/env python3
"""Synthetic multi-root reads never persist full query results by default."""
import hashlib, importlib.util, json, pathlib, sqlite3, subprocess, sys, tempfile
from unittest.mock import patch
sys.dont_write_bytecode = True
HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('cache_policy_host', HERE / 'host_checkpoint.py')
h = importlib.util.module_from_spec(spec); sys.modules[spec.name] = h; spec.loader.exec_module(h)
rows = []
def passed(name, **values): rows.append({'case': name, 'pass': True, **values})
def snapshots(repo):
    return {f.name: {'size': f.stat().st_size, 'sha256': h.sha(f.read_bytes()), 'mtime_ns': f.stat().st_mtime_ns}
            for f in repo.glob('query-cache.sqlite*')}
with tempfile.TemporaryDirectory(prefix='no-default-query-cache-') as temp:
    base = pathlib.Path(temp); repo = base / 'repo.git'
    subprocess.run(['git', 'init', '--bare', '--quiet', '--initial-branch=main', str(repo)], check=True, env=h.git_environment())
    p = h.load_core(); r = p.Repo(repo)
    captures = [p.synthetic_fixtures.capture(n, 4) for n in (1, 2)]
    inventory = {x['owner']: p.k.sha(p.k.canonical(p.native.capture_receipt(x))) for x in captures}
    _, s = p.build_initial_pending_session(r, captures, expected_inventory=inventory, mode='synthetic_scale_only')
    targets = [f'SU-{owner:06d}-T{index:04d}' for owner in (1, 2) for index in range(1, 5)]
    roots = []; query_count = 0; real_connect = sqlite3.connect
    def no_cache_connect(database, *args, **kwargs):
        if pathlib.Path(database).name.startswith('query-cache.sqlite'):
            raise AssertionError('ordinary query attempted persistent result cache')
        return real_connect(database, *args, **kwargs)
    def ordinary_round():
        global query_count
        with patch.object(sqlite3, 'connect', side_effect=no_cache_connect):
            for target in targets:
                one = p.query_native(r, s, {'commit': s.root, 'id': target})
                two = p.query_native(r, s, {'commit': s.root, 'id': target})
                assert one == two and one['responsibility']['status'] == 'UNKNOWN'
                query_count += 2
        roots.append(s.root)
    # Ordinary reads on distinct roots and targets must not even open the database.
    for index in range(4):
        if index:
            p.apply(r, s, {'op': 'revise_text', 'id': targets[index-1], 'expected_version': 0,
                          'text': f'Synthetic query policy {index}.', 'reason': 'local_technical_revision'})
        ordinary_round(); assert snapshots(repo) == {}
        raw = p.export(r, s); root = s.root; r.close(); r = p.Repo(repo)
        s = p.lazy_restore(r, raw, h.sha(raw), root)
    assert len(set(roots)) == 4
    passed('default_native_multi_root_multi_target_never_opens_or_creates_query_cache', roots=4, targets=8, queries=query_count)
    # Explicit diagnostic cache=True remains optional and does not change answers.
    request = {'commit': s.root, 'id': targets[0]}
    previous = getattr(r, '_lazy_validate', False); r._lazy_validate = True; r._lazy_owner_reports = {}
    try:
        with r.native_view():
            default = p.k.query(r, request, s.root, p.k.code_pin(), p.k.SCHEMA_PIN, session=s)
            explicit_false = p.k.query(r, request, s.root, p.k.code_pin(), p.k.SCHEMA_PIN, cache=False, session=s)
            diagnostic = p.k.query(r, request, s.root, p.k.code_pin(), p.k.SCHEMA_PIN, cache=True, session=s)
    finally: r._lazy_validate = previous
    assert default == explicit_false == diagnostic
    before = snapshots(repo); assert set(before) == {'query-cache.sqlite'}
    with sqlite3.connect(repo / 'query-cache.sqlite') as db:
        assert db.execute('SELECT COUNT(*) FROM query').fetchone()[0] == 1
    passed('explicit_diagnostic_cache_is_opt_in_and_answer_equivalent', bytes=before['query-cache.sqlite']['size'])
    # Pre-existing diagnostic rows are untouched, not read, cleared, or extended.
    for index in range(4, 8):
        p.apply(r, s, {'op': 'revise_text', 'id': targets[index-1], 'expected_version': 0,
                      'text': f'Synthetic existing-cache policy {index}.', 'reason': 'local_technical_revision'})
        ordinary_round(); assert snapshots(repo) == before
    passed('default_reads_do_not_open_or_grow_existing_cache_across_new_roots', roots=4, targets=8, queries=64)
    raw = p.export(r, s); checkpoint = base / 'checkpoint.json'; checkpoint.write_bytes(raw); r.close()
    code = '''import importlib.util,pathlib,sys
s=importlib.util.spec_from_file_location('fresh_host',sys.argv[1]);h=importlib.util.module_from_spec(s);s.loader.exec_module(h)
p=h.load_core();r=p.Repo(pathlib.Path(sys.argv[2]));raw=pathlib.Path(sys.argv[3]).read_bytes();s=p.lazy_restore(r,raw,h.sha(raw),sys.argv[4])
for owner in (1,2):
 for index in range(1,5):
  p.query_native(r,s,{'commit':s.root,'id':f'SU-{owner:06d}-T{index:04d}'})
r.close()
'''
    subprocess.run([sys.executable, '-B', '-c', code, str(HERE / 'host_checkpoint.py'), str(repo), str(checkpoint), s.root], check=True, env=h.git_environment())
    assert snapshots(repo) == before
    passed('fresh_process_lazy_restore_queries_do_not_grow_existing_cache', targets=8)
report = {'status': 'PASS', 'case_count': len(rows), 'cases': rows, 'synthetic_only': True,
          'real_body_reads': 0, 'fullbook_builds': 0, 'runtime_sha256': h.runtime_pin(),
          'bundle_sha256': h.BUNDLE_SHA256, 'platform_sha256': h.PLATFORM_SHA256,
          'ordinary_query_count': query_count + 8, 'distinct_roots': len(set(roots)),
          'policy': 'Default cache=False; explicit cache=True is diagnostic-only, remains unbounded and is never used by ordinary host/native query paths. Existing files are left untouched.'}
(HERE / 'QUERY_CACHE_POLICY_RESULTS.json').write_bytes(h.canonical(report))
print(json.dumps({'status': 'PASS', 'cases': len(rows), 'ordinary_queries': report['ordinary_query_count']}))
