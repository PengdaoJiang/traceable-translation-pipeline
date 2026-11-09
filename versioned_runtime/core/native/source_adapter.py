"""Pinned pure R0 byte adapter. No source database I/O at import or derivation.
A capture is a candidate, never external authority. Consumers must pin the
source receipt separately and replace all zero locators with real anchor OIDs.
"""
import ast
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
V24 = HERE
PINS = {'target_size.py': 'af43f05a87a2dee76f7de7400a30597c29ae1403faa306525fb2e7e82b4d59d0',
        'source_decode.py': 'c52d1d6c7f7b8f169cb80b718e873ccf34429cf6f9a2a968eec3643250dd51ce'}
ROOT = '1c3795a3064ca69cb43a3615107bc9cfc89143c5fdc700c9848defd86f4caf51'
STATE = 'fixed-fullbook-readonly/v1:' + ROOT
STAGE_REPORT = '1eb4efefafcfa05977928be8740b27ce1479f2e029fb7cbdf071a800aa4bcbe1'
V24_REPORT = '054eaffde22685b8286b5f76eeea635ee54c672115f546a916bf61132601facf'
sha = lambda b: hashlib.sha256(b).hexdigest()
canonical = lambda x: json.dumps(x, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _load(name):
    raw = (V24 / name).read_bytes()
    if sha(raw) != PINS[name]: raise ValueError('DEPENDENCY_PIN')
    ns = {'__name__': 'pinned_' + name[:-3]}
    exec(compile(raw, str(V24 / name), 'exec'), ns)
    return raw, ns


def _encoder():
    raw, ns = _load('target_size.py')
    tree = ast.parse(raw)
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'measure_owner')
    body = next(n for n in fn.body if isinstance(n, ast.Try)).body
    stop = next(i for i,n in enumerate(body) if isinstance(n, ast.Assign) and any(isinstance(t,ast.Name) and t.id=='grant_bytes' for t in n.targets))
    body[stop:] = ast.parse('return {"owner": owner, "origin": origin, "member_grant": member, "models": records, "originals": projections}').body
    for node in ast.walk(fn):
        if isinstance(node, ast.Constant) and node.value == 'host-authenticated-r0-fullbook-owner/v24': node.value = 'host-authenticated-r0-owner/v25'
    ns['ORIGIN_FORMAT'] = 'native-complete-su-origin/r0-stream-v25'
    exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])), '<pinned-encoder-return-extraction>', 'exec'), ns)
    return ns


def derive_capture(owner, source_raw, target_raw, provenance, retained=None):
    """Pure deterministic owner-local bytes -> capture, without live-source reads.

    provenance is the v24 source provenance mapping, with optional
    stage_owner_receipt: the exact externally pinned Stage-A owner row.
    retained is None or {'raw': bytes, 'metadata': {...}}. Identity is checked.
    This function verifies bytes, not external grant authority.
    """
    if provenance['root'] != ROOT or provenance['state'] != STATE or provenance['report_sha256'] != STAGE_REPORT:
        raise ValueError('PURE_R0_BINDING')
    for kind, raw in [('source_owner', source_raw), ('native_target', target_raw)]:
        if type(raw) is not bytes or len(raw) != provenance[kind+'_bytes'] or sha(raw) != provenance[kind+'_sha256']:
            raise ValueError('RAW_IDENTITY')
    _, dec = _load('source_decode.py')
    source, target = dec['strict_json'](source_raw), dec['strict_json'](target_raw)
    row = provenance.get('stage_owner_receipt')
    if row is not None:
        if sha(canonical(row)) != provenance['owner_receipt_sha256']: raise ValueError('OWNER_RECEIPT')
        expanded = dec['source_decode'](source, row)
        if expanded['expanded_source_sha256'] != provenance['expanded_source_sha256']: raise ValueError('EXPANSION_IDENTITY')
        dec['target_decode'](target, row, expanded, 'current')
    _, sizes = _load('target_size.py')
    measured = sizes['measure_owner'](owner, source, target, provenance)
    if measured['status'] != 'measured': raise ValueError('TYPED_ENCODING_REJECTED')
    cap = _encoder()['measure_owner'](owner, source, target, provenance)
    if 'origin' not in cap: raise ValueError('DERIVATION_REJECTED')
    if len(canonical(cap['origin'])) > 262144: raise ValueError('ORIGIN_CAP')
    cap['archives'] = {'source_owner': source_raw, 'native_target': target_raw}
    cap['retained'] = []
    if retained is not None:
        m, raw = retained['metadata'], retained['raw']
        if sha(raw) != m['raw_sha256'] or len(raw) != m['raw_byte_length']: raise ValueError('PRIOR_IDENTITY')
        if m['native_owner'] != cap['origin']['selection']['native_owner']: raise ValueError('PRIOR_OWNER')
        if m['disposition'] != 'ARCHIVAL_ONLY_NO_CURRENT_APPROVAL': raise ValueError('PRIOR_DISPOSITION')
        cap['retained'].append({'raw': raw, 'metadata': dict(m)})
    return cap


def iter_fixture_captures(directory, expected_receipt_sha256):
    """One owner at a time from private captures, externally pinned receipt."""
    directory = Path(directory)
    raw = (directory/'receipt.json').read_bytes()
    if sha(raw) != expected_receipt_sha256: raise ValueError('FIXTURE_RECEIPT_PIN')
    receipt = json.loads(raw)
    if receipt['v24_report_sha256'] != V24_REPORT: raise ValueError('V24_REPORT_PIN')
    for item in receipt['owners']:
        owner = item['owner']
        if not __import__('re').fullmatch(r'SU-[0-9]{6}', owner): raise ValueError('OWNER_PATH')
        sub = directory/owner
        retained = None
        if item['retained'] is not None:
            retained = {'raw': (sub/'previous.raw.json').read_bytes(), 'metadata':item['retained']}
        yield derive_capture(owner, (sub/'source.raw.json').read_bytes(), (sub/'current.raw.json').read_bytes(), item['provenance'], retained)
