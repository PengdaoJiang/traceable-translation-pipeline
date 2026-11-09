"""Pure deterministic *synthetic* owner-count fixtures, never real book content.

The deliberately tiny fixture has one source, target and structural coverage
record per owner, no notes and no dependencies. Historical raw encoding names
are parser compatibility tags, not claims about any native database provenance.
Only run_trial.py's measured launch or small development tests may call prepare.
"""
import hashlib
import json


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


ROOT = digest(b'bounded-su-git-v21-synthetic-scale-only')
STATE = 'synthetic-scale-only/v1:' + ROOT
SCOPE = 'SYNTHETIC_SCALE_ONLY_NO_NATIVE_PROVENANCE'
DOMAINS = ('actual_use', 'hold', 'approval', 'migration', 'source_alignment')


def prepare(count, meter=None):
    if type(count) is not int or not 1 <= count <= 2079:
        raise ValueError('SYNTHETIC_OWNER_COUNT')
    result = {'mode': 'synthetic', 'scope': [], 'models': {}, 'originals': {},
              'archives': {}, 'origins': {}, 'owner_grants': {}, 'source_pins': {},
              'label': 'SYNTHETIC_OWNER_COUNT_ONLY_NOT_REAL_FULLBOOK'}
    for number in range(1, count + 1):
        owner, uid = f'SU{number:02d}', f'SU-{number:06d}'
        source_id, target_id = uid + '-P0001', uid + '-T0001'
        source_text = f'Synthetic source fixture {number:06d}.'
        target_text = f'Synthetic target fixture {number:06d}.'
        heading = f'SYNTHETIC owner {number:06d}'
        basis = digest((heading + '\n' + source_text).encode()).upper()
        compact = {
            'domain': 'fixed-fullbook-readonly/v1', 'kind': 'compact-source',
            'encoding': 'rows:[source_line,critical,diplomatic_or_null_same,patch_ids,split_part];record_index=trim_start+position;paragraph_id=SU-P+nonblank_ordinal',
            'shell': {'domain': 'fixed-independent-source-owner/v1',
                      'certificate_contract': 'fixed-independent-source-certificate/v1',
                      'source_unit': {'source_unit_id': uid, 'paragraph_count': 1,
                                      'critical_sha256': basis},
                      'span': {'trim_start': 0, 'trim_end': 1},
                      'heading': {'critical': heading}},
            'rows': [[1, source_text, None, [], 0]],
        }
        target = {'schema_version': 1, 'source_unit_id': uid,
                  'source_critical_sha256': basis, 'status': 'SYNTHETIC_ONLY',
                  'segments': [{'target_segment_id': target_id, 'en': target_text,
                                'source_paragraph_ids': [source_id]}]}
        archives = {'source_owner': canonical(compact), 'native_target': canonical(target)}
        provenance = {key: digest(f'SYNTHETIC/{owner}/{key}'.encode()) for key in (
            'manifest_sha256', 'launcher_sha256', 'reader_sha256', 'decoder_sha256',
            'inventory_report_sha256', 'field_census_sha256', 'expanded_source_sha256',
            'directory_sha256', 'authenticated_directory_entry_sha256')}
        provenance.update(root=ROOT, state=STATE, source_basis_sha256=basis,
                          source_owner_sha256=digest(archives['source_owner']),
                          native_target_sha256=digest(archives['native_target']),
                          native_status_exact_old_document='SYNTHETIC_ONLY')
        origin = {'format': 'synthetic-scale-su-origin/v1', 'source': provenance,
                  'selection': {'native_owner': uid, 'owner': owner,
                                'source_ids': [source_id], 'target_ids': [target_id],
                                'scope': SCOPE}, 'archives': {}, 'records': {},
                  'coverage': [{'target_id': target_id, 'source_ids': [source_id]}],
                  'notes': {target_id: {'presence': 'absent', 'type': 'missing',
                                        'json_pointer': '/segments/0/notes'}},
                  'owner_note': {'presence': 'absent', 'type': 'missing',
                                 'json_pointer': '/notes'}}
        for kind, body in archives.items():
            origin['archives'][kind] = {
                'kind': kind, 'path': f'archives/{owner}/{kind}.raw.json',
                'sha256': digest(body), 'byte_length': len(body),
                'media_type': 'application/json',
                'representation': ('authenticated_source_compact_cas' if kind == 'source_owner'
                                   else 'authenticated_native_target_cas')}
        records, nodes, originals = [], {}, {}
        for kind, ident, value in (('source', source_id, source_text),
                                   ('target', target_id, target_text)):
            h = digest(value.encode())
            locator = {'representation': 'authenticated_expanded_source' if kind == 'source' else 'native_target_json',
                       'json_pointer': '/source_paragraphs/0/critical' if kind == 'source' else '/segments/0/en',
                       'record_index': 0}
            if kind == 'source':
                locator.update(compact_json_pointer='/rows/0/1', source_line_json_pointer='/rows/0/0',
                               diplomatic_json_pointer='/rows/0/2', patch_ids_json_pointer='/rows/0/3',
                               split_part_json_pointer='/rows/0/4')
            origin['records'][ident] = {'kind': kind, 'text_sha256': h,
                'text_utf8_bytes': len(value.encode()), 'original_span': [0, len(value)],
                'native_locator': locator}
            node = {'id': ident, 'kind': kind, 'slot': 1, 'order': 0, 'live': True,
                    'version': 0, 'text': value, 'digest': h,
                    'original': {'ref': kind, 'span': [0, len(value)], 'version': 0,
                                 'current_alignment': 'EXACT_SYNTHETIC_ARCHIVE_FIELD_BYTES'},
                    'prior': None, 'responsibility': {'for_version': 0, 'status': 'UNKNOWN', 'claims': []},
                    'lineage': []}
            if kind == 'target':
                node.update(facts={d: {'status': 'UNKNOWN', 'reason': 'no_verified_fact'} for d in DOMAINS}, obligations=[])
            nodes[ident] = node
            records.append(node)
            originals[kind] = (value + '\n').encode()
        def ref(ident):
            n = nodes[ident]
            return {'id': ident, 'kind': n['kind'], 'version': 0, 'digest': n['digest'],
                    'start': 0, 'end': len(n['text'])}
        records.append({'id': owner + ':coverage:0001', 'kind': 'coverage', 'slot': 1,
                        'mode': 'native_structural', 'sources': [ref(source_id)], 'targets': [ref(target_id)],
                        'source_alignment': 'UNKNOWN', 'claim': 'native_structural_only_not_actual_use'})
        grant = {'format': 'synthetic-scale-single-owner-origin/v1', 'root': ROOT, 'state': STATE,
                 'native_owner': uid, 'owner': owner, 'source_count': 1, 'target_count': 1,
                 'coverage_count': 1, 'edge_count': 1, 'note_count': 0,
                 'target_note_count': 0, 'owner_note_count': 0,
                 'report_sha256': provenance['inventory_report_sha256'],
                 'origin_sha256': digest(canonical(origin))}
        result['scope'].append(owner)
        for field, value in (('models', records), ('originals', originals), ('archives', archives),
                             ('origins', origin), ('owner_grants', grant)):
            result[field][owner] = value
        if meter:
            meter(len(canonical({'origin': origin, 'grant': grant, 'records': records})) +
                  sum(map(len, archives.values())) + sum(map(len, originals.values())),
                  'synthetic_constructed_payload_bytes')
    return result
