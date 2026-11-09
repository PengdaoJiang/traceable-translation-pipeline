"""Pure prospective R0 encoder census. No IO, kernel imports, or object writes.

Not an admission implementation. Caller authenticates and decodes exact raw
archives independently; their lengths/digests are supplied, never reserialized.
Unknown metadata stays in those archives. Hash placeholders have fixed widths
and permit exact sizes, NOT object identities or a candidate Git graph.
"""
import copy
import hashlib
import json
import re

FORMAT = 'bounded-su-git-fullbook-r0-prospective-v24'
ORIGIN_FORMAT = 'native-complete-su-origin/r0-census-v24'
DOMAINS = ('actual_use', 'hold', 'approval', 'migration', 'source_alignment')
FACTS = {d: {'status': 'UNKNOWN', 'reason': 'no_verified_fact'} for d in DOMAINS}
TEMPLATES = {'facts_unknown_v1': FACTS,
             'responsibility_unknown_v1': {'status': 'UNKNOWN', 'claims': []}}
LIMITS = {'expanded_record_bytes': 8192, 'page_bytes': 16384, 'manifest_bytes': 16384,
          'origin_bytes': 262144, 'raw_bytes': 1048576, 'projection_bytes': 1048576,
          'pages': 128, 'page_records': 32, 'source_rows': 4096, 'sources': 256,
          'targets': 256, 'notes': 256, 'coverage_sources': 256,
          'tree_bytes': 16384, 'tree_fanout': 200}
FILL = 12288
H40, H64 = '0' * 40, '0' * 64
ENCODING = 'rows:[source_line,critical,diplomatic_or_null_same,patch_ids,split_part];record_index=trim_start+position;paragraph_id=SU-P+nonblank_ordinal'

class Unsupported(ValueError):
    pass


def canonical(value):
    def check(v):
        if isinstance(v, dict):
            if not all(type(k) is str for k in v):
                raise Unsupported('CANONICAL_KEY')
            for child in v.values():
                check(child)
        elif isinstance(v, list):
            for child in v:
                check(child)
        elif v is not None and type(v) not in (str, int, bool):
            raise Unsupported('CANONICAL_SCALAR')
    check(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def require(ok, code):
    if not ok:
        raise Unsupported(code)


def radix(owner):
    require(isinstance(owner, str) and re.fullmatch(r'SU(?:[0-9]{2}|[1-9][0-9]{2,31})', owner), 'OWNER_SYNTAX')
    ds = owner[2:]
    ds = ('0' if len(ds) % 2 else '') + ds
    chunks = [ds[i:i + 2] for i in range(0, len(ds), 2)]
    return '/'.join(chunks[:-1] + ['u' + chunks[-1]])


def refs(record):
    if record['kind'] == 'coverage':
        return record['sources'] + record['targets']
    if record['kind'] == 'note' and record['about']['kind'] == 'target':
        return [record['about']]
    return []


def compact(record):
    v = copy.deepcopy(record)
    kind = v.pop('kind')
    v.pop('slot')
    if kind in ('source', 'target'):
        v.pop('responsibility')
        v['responsibility_ref'] = 'responsibility_unknown_v1'
        if kind == 'target':
            v.pop('facts')
            v['facts_ref'] = 'facts_unknown_v1'
            v['facts_overrides'] = {}
    rs = v['sources'] + v['targets'] if kind == 'coverage' else [v['about']] if kind == 'note' and v['about']['kind'] == 'target' else []
    for ref in rs:
        loc = ref.pop('locator')
        ref['location'] = {'anchor': 0, 'page': loc['page'], 'record': loc['record_sha256']}
    return v


def partition(owner, records, encode=canonical):
    """Kernel v22 initial compact partition, including decimal page-ID growth."""
    groups, routes = [], []
    for space, kinds in (('node', ('source', 'target')), ('relation', ('coverage',)), ('note', ('note',))):
        current, low, packed_bytes = [], None, 0
        for record in sorted((r for r in records if r['kind'] in kinds), key=lambda r: r['id']):
            item = encode(compact(record))
            # Empty array envelope plus canonical record bytes and commas is
            # algebraically identical to canonical(trial); no O(32) reencoding.
            envelope = len(encode({'su': owner, 'page': len(groups), 'records': []}))
            size = envelope + packed_bytes + len(item) + len(current)
            if current and (len(current) + 1 > 32 or size > FILL):
                groups.append(current)
                routes.append({'page': len(groups) - 1, 'space': space, 'low': low})
                current, low, packed_bytes = [], record['id'], 0
            current.append(record); packed_bytes += len(item)
        if current:
            groups.append(current)
            routes.append({'page': len(groups) - 1, 'space': space, 'low': low})
    # Emit through canonical serializer so charge accounts for actual work.
    pages = [encode({'su': owner, 'page': i, 'records': [compact(r) for r in group]})
             for i, group in enumerate(groups)]
    return groups, routes, pages


def measure_owner(owner, source, target, provenance, charge=None):
    """Return only technical sizes/digests/counts, never prose or model records.

    owner may be canonical SU192 or native SU-000192. Required provenance:
    root, state, report_sha256, owner_receipt_sha256, expanded_source_sha256,
    source_owner_sha256/native_target_sha256, source_owner_bytes/native_target_bytes,
    pins (mapping code-role -> SHA256). Optional metadata_owner_receipt_sha256.
    charge(number_of_bytes, operation_label) meters logical serialization/hash.
    Unsupported shapes return typed_encoding_unavailable, not a fit assertion.
    """
    out = {'format': 'r0-target-size-census/v1', 'status': 'typed_encoding_unavailable',
           'owner': owner, 'issues': [], 'limits': dict(LIMITS), 'tree_files': [], 'limit_exceptions': []}
    def encode(v):
        b = canonical(v)
        if charge:
            charge(len(b), 'target_canonical_bytes')
        return b
    def digest(b):
        if charge:
            charge(len(b), 'target_hash_bytes')
        return hashlib.sha256(b).hexdigest()
    try:
        if isinstance(owner, str) and re.fullmatch(r'SU-[0-9]{6}', owner):
            owner = f'SU{int(owner[3:]):02d}'
        rp = radix(owner)
        out['owner'] = owner
        uid = f'SU-{int(owner[2:]):06d}'
        require(len(uid) == 9, 'NATIVE_OWNER_RANGE')
        require(isinstance(source, dict) and isinstance(target, dict), 'OWNER_OBJECTS')
        require(source.get('domain') == 'fixed-fullbook-readonly/v1' and source.get('kind') == 'compact-source'
                and source.get('encoding') == ENCODING, 'SOURCE_ENCODING')
        shell, rows = source.get('shell'), source.get('rows')
        require(isinstance(shell, dict) and isinstance(rows, list), 'SOURCE_SHELL_ROWS')
        unit, span, heading = shell.get('source_unit'), shell.get('span'), shell.get('heading')
        require(isinstance(unit, dict) and unit.get('source_unit_id') == uid and isinstance(span, dict)
                and isinstance(heading, dict) and type(heading.get('critical')) is str, 'SOURCE_OWNER_HEADING')
        require(shell.get('domain') == 'fixed-independent-source-owner/v1' and shell.get('certificate_contract') == 'fixed-independent-source-certificate/v1', 'SOURCE_CERTIFICATE')
        require(type(span.get('trim_start')) is int and type(span.get('trim_end')) is int
                and 0 <= span['trim_start'] <= span['trim_end'] and span['trim_end'] - span['trim_start'] == len(rows), 'SOURCE_SPAN')
        selected, basis = [], [heading['critical']]
        for j, row in enumerate(rows):
            require(isinstance(row, list) and len(row) == 5, 'SOURCE_ROW_SHAPE')
            line, critical, diplomatic, patches, part = row
            require(type(line) is int and line > 0 and type(critical) is str
                    and (diplomatic is None or type(diplomatic) is str) and type(part) is int and part >= 0, 'SOURCE_ROW_TYPES')
            require('\n' not in critical and '\r' not in critical and (diplomatic is None or '\n' not in diplomatic and '\r' not in diplomatic), 'SOURCE_ROW_NEWLINE')
            require(isinstance(patches, list) and all(type(p) is str and p for p in patches)
                    and len(patches) == len(set(patches)), 'SOURCE_PATCH_IDS')
            basis.append(critical)
            if critical != '':
                selected.append((j, critical))
        pids = [f'{uid}-P{i + 1:04d}' for i in range(len(selected))]
        require(type(unit.get('paragraph_count')) is int and unit['paragraph_count'] == len(pids), 'SOURCE_PARAGRAPH_COUNT')
        basis_sha = digest('\n'.join(basis).encode()).upper()
        require(unit.get('critical_sha256') == basis_sha, 'SOURCE_BASIS')
        segments = target.get('segments')
        require(target.get('source_unit_id') == uid and type(target.get('schema_version')) is int
                and target['schema_version'] == 1 and target.get('source_critical_sha256') == basis_sha
                and isinstance(segments, list), 'TARGET_OWNER_SCHEMA_BASIS')
        require(isinstance(target.get('status'), str) and 0 < len(target['status']) <= 64, 'TARGET_STATUS')
        tids = [f'{uid}-T{i + 1:04d}' for i in range(len(segments))]
        require(pids and tids and len(pids) <= 9999 and len(tids) <= 9999, 'NATIVE_SLOT_RANGE')
        allowed = {'/notes'} | {f'/segments/{i}/notes' for i in range(len(segments))}
        def scan(v, path, allow):
            if isinstance(v, dict):
                for k, child in v.items():
                    require(type(k) is str, 'RAW_KEY_TYPE')
                    p = path + '/' + k.replace('~', '~0').replace('/', '~1')
                    require(k not in ('note', 'notes') or p in allow, 'UNSUPPORTED_NOTE_LOCATION')
                    scan(child, p, allow)
            elif isinstance(v, list):
                for i, child in enumerate(v):
                    scan(child, path + '/' + str(i), allow)
        scan(source, '', set())
        scan(target, '', allowed)
        prov_fields = ('root', 'state', 'report_sha256', 'owner_receipt_sha256', 'expanded_source_sha256',
                       'source_owner_sha256', 'native_target_sha256', 'pins')
        require(all(k in provenance for k in prov_fields), 'MISSING_PROVENANCE')
        prov = {k: copy.deepcopy(provenance[k]) for k in prov_fields}
        for k in prov_fields:
            if k.endswith('_sha256') or k == 'root':
                require(type(prov[k]) is str and re.fullmatch('[0-9a-fA-F]{64}', prov[k]), 'PROVENANCE_DIGEST')
        require(type(prov['state']) is str and isinstance(prov['pins'], dict) and bool(prov['pins'])
                and all(type(k) is str and type(v) is str and re.fullmatch('[0-9a-fA-F]{64}', v) for k, v in prov['pins'].items()), 'PROVENANCE_STATE_PINS')
        for key in ('metadata_owner_receipt_sha256', 'field_census_sha256', 'prior_archive_receipt_sha256'):
            if key in provenance:
                require(type(provenance[key]) is str and re.fullmatch('[0-9a-fA-F]{64}', provenance[key]), 'OPTIONAL_RECEIPT_DIGEST')
                prov[key] = provenance[key]
        prov.update(source_basis_sha256=basis_sha, native_status_exact_old_document=target['status'],
                    responsibility='UNKNOWN', approval='UNKNOWN', actual_use='UNKNOWN')
        origin = {'format': ORIGIN_FORMAT, 'source': prov,
                  'selection': {'native_owner': uid, 'owner': owner, 'source_ids': pids, 'target_ids': tids,
                                'scope': 'COMPLETE_R0_BODY_OWNER_RAW_METADATA_ARCHIVAL_ONLY'},
                  'archives': {}, 'records': {}, 'coverage': [], 'notes': {}, 'owner_note': {}}
        for kind in ('source_owner', 'native_target'):
            length = provenance.get(kind + '_bytes')
            require(type(length) is int and length > 0, 'RAW_LENGTH')
            origin['archives'][kind] = {'kind': kind, 'path': f'archives/{owner}/{kind}.raw.json',
                'sha256': prov[kind + '_sha256'], 'byte_length': length, 'media_type': 'application/json',
                'representation': 'authenticated_source_compact_cas' if kind == 'source_owner' else 'authenticated_native_target_cas'}
        records, nodes, projections = [], {}, {}
        for kind, ids, values in (('source', pids, [v for j, v in selected]),
                                  ('target', tids, [s.get('en') if isinstance(s, dict) else None for s in segments])):
            offset, parts = 0, []
            for i, (ident, value) in enumerate(zip(ids, values)):
                require(type(value) is str, 'BODY_TEXT_TYPE')
                if kind == 'target':
                    require(segments[i].get('target_segment_id') == ident, 'TARGET_ID_ORDER')
                b = value.encode('utf-8'); h = digest(b); bounds = [offset, offset + len(value)]
                loc = {'representation': 'authenticated_expanded_source' if kind == 'source' else 'native_target_json',
                       'json_pointer': f'/source_paragraphs/{i}/critical' if kind == 'source' else f'/segments/{i}/en', 'record_index': i}
                if kind == 'source':
                    j = selected[i][0]
                    for key, slot in (('compact_json_pointer', 1), ('source_line_json_pointer', 0), ('diplomatic_json_pointer', 2), ('patch_ids_json_pointer', 3), ('split_part_json_pointer', 4)):
                        loc[key] = f'/rows/{j}/{slot}'
                origin['records'][ident] = {'kind': kind, 'text_sha256': h, 'text_utf8_bytes': len(b), 'original_span': bounds, 'native_locator': loc}
                node = {'id': ident, 'kind': kind, 'slot': i + 1, 'order': i, 'live': True, 'version': 0,
                        'text': value, 'digest': h, 'original': {'ref': kind, 'span': bounds, 'version': 0,
                        'current_alignment': 'EXACT_NATIVE_ARCHIVE_FIELD_BYTES'}, 'prior': None,
                        'responsibility': {'for_version': 0, 'status': 'UNKNOWN', 'claims': []}, 'lineage': []}
                if kind == 'target':
                    node.update(facts=copy.deepcopy(FACTS), obligations=[])
                nodes[ident] = node; records.append(node); parts.append(value + '\n'); offset += len(value) + 1
            projections[kind] = ''.join(parts).encode('utf-8')
        node_groups, node_routes, node_pages = partition(owner, records, encode)
        locations = {r['id']: {'commit': H40, 'page': pg, 'record_sha256': digest(encode(r)), 'owner': owner}
                     for pg, group in enumerate(node_groups) for r in group}
        def reference(ident):
            n = nodes[ident]
            return {'id': ident, 'kind': n['kind'], 'version': 0, 'digest': n['digest'],
                    'start': 0, 'end': len(n['text']), 'locator': copy.deepcopy(locations[ident])}
        presence = {'missing': 0, 'null': 0, 'string': 0, 'empty_string': 0}
        def note(item, pointer, slot, about):
            typ = 'missing' if 'notes' not in item else 'null' if item['notes'] is None else 'string' if type(item['notes']) is str else 'unsupported'
            require(typ != 'unsupported', 'UNSUPPORTED_NOTE_TYPE')
            spec = {'presence': 'absent' if typ == 'missing' else 'present', 'type': typ, 'json_pointer': pointer}
            presence[typ] += 1
            if typ == 'string':
                value = item['notes']; b = value.encode(); h = digest(b); ident = f'{owner}:note:{slot:04d}'
                presence['empty_string'] += int(value == '')
                spec.update(id=ident, text_sha256=h, text_utf8_bytes=len(b))
                records.append({'id': ident, 'kind': 'note', 'slot': slot, 'version': 0, 'text': value,
                    'digest': h, 'prior': None, 'about': about,
                    'approval': {'for_note_version': 0, 'status': 'UNKNOWN', 'claims': []}})
            return spec
        used, last, max_refs = set(), 0, 0
        for i, segment in enumerate(segments):
            rr = segment.get('source_paragraph_ids')
            require(isinstance(rr, list) and rr and all(type(x) is str and x in nodes and x in pids for x in rr)
                    and len(rr) == len(set(rr)), 'COVERAGE_REFS')
            nums = [int(x[-4:]) for x in rr]
            require(nums == sorted(nums) and nums[0] >= last, 'COVERAGE_ORDER')
            last = nums[-1]; used.update(rr); max_refs = max(max_refs, len(rr)); tid = tids[i]
            if 'source_critical_sha256' in segment:
                require(len(rr) == 1 and segment['source_critical_sha256'] == nodes[rr[0]]['digest'].upper(), 'SEGMENT_SOURCE_BASIS')
            origin['coverage'].append({'target_id': tid, 'source_ids': rr})
            records.append({'id': f'{owner}:coverage:{i+1:04d}', 'kind': 'coverage', 'slot': i+1,
                            'mode': 'native_structural', 'sources': [reference(x) for x in rr], 'targets': [reference(tid)],
                            'source_alignment': 'UNKNOWN', 'claim': 'native_structural_only_not_actual_use'})
            about = reference(tid); about.pop('start'); about.pop('end')
            origin['notes'][tid] = note(segment, f'/segments/{i}/notes', i, about)
        require(used == set(pids), 'COVERAGE_INCOMPLETE')
        origin['owner_note'] = note(target, '/notes', 9999, {'kind': 'owner', 'owner': owner})
        ob = encode(origin); oh = digest(ob)
        originals, archives = {}, {}
        for kind, b in projections.items():
            originals[kind] = {'kind': 'derived_index_projection', 'provenance': 'projection_of_authenticated_archive_fields_no_approval',
                'origin_sha256': oh, 'commit': H40, 'path': f'projections/{rp}/{kind}.txt', 'git_blob': H40,
                'sha256': digest(b), 'byte_length': len(b), 'media_type': 'text/plain;charset=utf-8'}
        for kind, d in origin['archives'].items():
            archives[kind] = {**d, 'storage_path': f'archives/{rp}/{kind}.raw.json', 'commit': H40,
                             'git_blob': H40, 'origin_sha256': oh, 'provenance': 'host_attested_fixed_su_raw_no_approval'}
        groups, routes, pages = partition(owner, records, encode)
        counts = {k: sum(r['kind'] == k for r in records) for k in ('source', 'target', 'coverage', 'note')}
        def manifest(routes, cs, anchor):
            return encode({'format': FORMAT, 'su': owner, 'pages': routes, 'counts': {k: v for k, v in cs.items() if v},
                'originals': originals, 'archives': archives, 'initial_anchor': anchor, 'templates': TEMPLATES,
                'completeness': 'complete_fixed_native_SU_body_coverage_and_target_note_census_raw_metadata_archival_only'})
        mb = manifest(routes, counts, H40)
        nmb = manifest(node_routes, {k: counts[k] for k in ('source', 'target')}, None)
        expanded = [len(encode(r)) for r in records]
        encoded = [len(encode(compact(r))) for r in records]
        member = {'format': 'host-authenticated-r0-fullbook-owner/v24', 'root': prov['root'], 'state': prov['state'],
            'native_owner': uid, 'owner': owner, 'source_count': len(pids), 'target_count': len(tids),
            'coverage_count': len(tids), 'edge_count': sum(len(c['source_ids']) for c in origin['coverage']),
            'note_count': counts['note'], 'target_note_count': sum(s['type'] == 'string' for s in origin['notes'].values()),
            'owner_note_count': int(origin['owner_note']['type'] == 'string'), 'report_sha256': prov['report_sha256'], 'origin_sha256': oh}
        grant_bytes = len(encode(member))
        sizes = {'expanded_record_bytes': max(expanded), 'page_bytes': max(map(len, pages)), 'manifest_bytes': len(mb),
                 'origin_bytes': len(ob), 'raw_bytes': max(d['byte_length'] for d in origin['archives'].values()),
                 'projection_bytes': max(map(len, projections.values())), 'pages': len(pages),
                 'page_records': max(map(len, groups)), 'source_rows': len(rows), 'sources': len(pids), 'targets': len(tids),
                 'notes': counts['note'], 'coverage_sources': max_refs}
        violations = [k for k, value in sizes.items() if value > LIMITS[k]]
        limit_exceptions = []
        def excess(category, actual, limit, **where):
            if actual > limit:
                limit_exceptions.append({'category': category, 'actual': actual, 'limit': limit, **where})
        # Every record is generated from validated typed IDs; no arbitrary raw
        # field/path/value is copied into these technical exception descriptors.
        for record, length in zip(records, expanded):
            excess('expanded_record_bytes', length, 8192, record_id=record['id'], kind=record['kind'])
        for stage, stage_groups, stage_pages in (('baseline', groups, pages), ('node_anchor', node_groups, node_pages)):
            excess('pages', len(stage_pages), 128, stage=stage)
            for pg, (group, payload) in enumerate(zip(stage_groups, stage_pages)):
                excess('page_bytes', len(payload), 16384, stage=stage, page=pg, rows=len(group))
                excess('page_records', len(group), 32, stage=stage, page=pg, bytes=len(payload))
        excess('manifest_bytes', len(mb), 16384, stage='baseline')
        excess('manifest_bytes', len(nmb), 16384, stage='node_anchor')
        excess('origin_bytes', len(ob), 262144)
        for kind, descriptor in origin['archives'].items():
            excess('raw_bytes', descriptor['byte_length'], 1048576, archive_kind=kind)
        for kind, payload in projections.items():
            excess('projection_bytes', len(payload), 1048576, projection_kind=kind)
        for category in ('source_rows', 'sources', 'targets', 'notes'):
            excess(category, sizes[category], LIMITS[category])
        for row in origin['coverage']:
            excess('coverage_sources', len(row['source_ids']), 256, target_id=row['target_id'])
        files = [{'path': f'su/{rp}/p{i:04d}.json', 'payload_bytes': len(b)} for i, b in enumerate(pages)]
        files += [{'path': f'su/{rp}/manifest.json', 'payload_bytes': len(mb)},
                  {'path': f'origins/{rp}/origin.json', 'payload_bytes': len(ob)},
                  {'path': f'owners/{rp}/grant.json', 'payload_bytes': grant_bytes}]
        files += [{'path': f'projections/{rp}/{kind}.txt', 'payload_bytes': len(b)} for kind, b in projections.items()]
        files += [{'path': f'archives/{rp}/{kind}.raw.json', 'payload_bytes': d['byte_length']} for kind, d in origin['archives'].items()]
        out.update(status='measured_limit_exceeded' if limit_exceptions else 'measured', issues=violations,
            limit_exceptions=limit_exceptions,
            maxima=sizes, headroom={k: LIMITS[k] - v for k, v in sizes.items()}, counts=counts,
            note_presence=presence, owner_note_presence=origin['owner_note']['type'],
            coverage_edges=member['edge_count'], prospective_origin_sha256=oh, origin_format=ORIGIN_FORMAT,
            expanded_records_total_bytes=sum(expanded), compact_records_total_bytes=sum(encoded),
            page_payload_bytes=sum(map(len, pages)), manifest_payload_bytes=len(mb),
            node_anchor_page_payload_bytes=sum(map(len, node_pages)), node_anchor_manifest_bytes=len(nmb),
            node_anchor_pages=len(node_pages), owner_grant_bytes=grant_bytes,
            projection_payload_bytes=sum(map(len, projections.values())),
            raw_archive_payload_bytes=sum(d['byte_length'] for d in origin['archives'].values()),
            tree_files=files, exact_size_not_object_identity=True,
            typed_semantics='critical_en_current_string_notes_owner_local_structural_coverage',
            unknown_metadata='raw_archive_only', authority_and_approval='UNKNOWN',
            encoding_categories={'v22_layout': 'exact_record_page_manifest_layout_sizes_with_prospective_format_label',
              'r0_origin_grants': 'exact_proposed_wire_size_not_authenticated_or_admissible_origin',
              'prior_history_other_domains': 'UNKNOWN_UNDESIGNED_OVERHEAD'},
            future_references='fixed_width_size_placeholders_not_actual_object_identities',
            node_anchor_tree_files=[{'path': f'su/{rp}/p{i:04d}.json', 'payload_bytes': len(b)} for i,b in enumerate(node_pages)] + [{'path': f'su/{rp}/manifest.json', 'payload_bytes': len(nmb)}])
    except (Unsupported, UnicodeError, KeyError, TypeError, ValueError, RecursionError) as exc:
        # Never echo source values or exception messages from arbitrary objects.
        code = str(exc) if isinstance(exc, Unsupported) else type(exc).__name__
        out['issues'] = [code]
    return out


class TreeAccumulator:
    """Bounded technical path trie; exact Git tree sizes without blobs or OIDs.

    Intended maximum 2079 owners * (128 pages + 7 fixed files), enforced by
    max_files and max_nodes. Additional root/archive paths require explicit add.
    No content hashes or object deduplication/compression are claimed.
    """
    def __init__(self, max_files=300000, max_nodes=50000):
        self.root = {}
        self.max_files, self.max_nodes = max_files, max_nodes
        self.files, self.nodes, self.payload_bytes = 0, 1, 0

    def add(self, descriptors):
        for d in descriptors:
            path, size = d['path'], d['payload_bytes']
            require(type(path) is str and len(path) <= 512 and path.isascii() and '\0' not in path, 'TREE_PATH')
            parts = path.split('/')
            require(len(parts) <= 20 and all(p not in ('', '.', '..') for p in parts), 'TREE_PATH')
            require(type(size) is int and size >= 0, 'TREE_PAYLOAD_SIZE')
            cur = self.root
            for p in parts[:-1]:
                if p not in cur:
                    require(self.nodes < self.max_nodes, 'TREE_NODE_BUDGET')
                    cur[p] = {}; self.nodes += 1
                require(isinstance(cur[p], dict), 'TREE_PATH_COLLISION')
                cur = cur[p]
            require(parts[-1] not in cur, 'TREE_DUPLICATE_PATH')
            require(self.files < self.max_files, 'TREE_FILE_BUDGET')
            cur[parts[-1]] = size; self.files += 1; self.payload_bytes += size

    def summary(self):
        count, total, maximum, fanout = 0, 0, 0, 0
        violations = []
        stack = [('', self.root)]
        while stack:
            path, node = stack.pop(); count += 1
            n = sum(len(('40000' if isinstance(v, dict) else '100644').encode()) + 1 + len(k.encode('ascii')) + 1 + 20 for k, v in node.items())
            total += n; maximum = max(maximum, n); fanout = max(fanout, len(node))
            if n > 16384 or len(node) > 200:
                violations.append({'path': path, 'bytes': n, 'fanout': len(node)})
            stack.extend((path + '/' + k, v) for k, v in node.items() if isinstance(v, dict))
        return {'tree_count': count, 'tree_payload_bytes': total, 'tree_max_bytes': maximum,
                'tree_max_fanout': fanout, 'files': self.files, 'blob_payload_bytes': self.payload_bytes,
                'issues': violations, 'includes_only_supplied_paths': True}


def measure_root_grant(owners, root, state, report_sha256, charge=None):
    """Exact PROPOSED root/scope lengths; no computed/authenticated tree OIDs."""
    require(isinstance(owners, list) and 0 < len(owners) <= 2079, 'ROOT_SCOPE_COUNT')
    for owner in owners:
        radix(owner)
    require(owners == sorted(set(owners), key=lambda x: (len(x), x)), 'ROOT_SCOPE_ORDER')
    require(type(root) is str and re.fullmatch('[0-9a-f]{64}', root) and type(report_sha256) is str
            and re.fullmatch('[0-9a-f]{64}', report_sha256) and type(state) is str, 'ROOT_PROVENANCE')
    scope_raw = canonical({'count': len(owners), 'sus': owners})
    scope_hash = hashlib.sha256(scope_raw).hexdigest()
    grant = {'format': 'host-accepted-r0-fullbook-radix-roots/v24', 'mode': 'real_r0_body_fullbook',
             'root': root, 'state': state, 'report_sha256': report_sha256,
             'scope_count': len(owners), 'scope_sha256': scope_hash,
             'indexes': {n: {'git_tree': H40, 'sha256': H64} for n in ('owners', 'origins', 'archives')},
             'origin_sha256': H64}
    b = canonical(grant)
    sb = canonical({'count': len(owners), 'sha256': scope_hash})
    if charge:
        charge(len(scope_raw) * 2 + len(b) + len(sb), 'target_root_canonical_and_hash_bytes')
    return {'format': grant['format'], 'status': 'prospective_size_only', 'root_grant_bytes': len(b),
            'scope_descriptor_bytes': len(sb), 'scope_count': len(owners), 'scope_sha256': scope_hash,
            'root_grant_headroom': 4096 - len(b), 'issues': [] if len(b) <= 4096 else ['root_grant_bytes'],
            'tree_files': [{'path': 'grant.json', 'payload_bytes': len(b)}, {'path': 'scope.json', 'payload_bytes': len(sb)}],
            'future_references': 'fixed_width_size_placeholders_not_actual_object_identities'}
