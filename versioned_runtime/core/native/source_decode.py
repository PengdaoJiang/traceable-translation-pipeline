"""Independent R0 payload decoder and complete body-free field inventory.
No I/O or import-time work. No native source module imported or executed.
"""
import collections
import decimal
import hashlib
import json
import re

FORMAT = 'R0-field-inventory/v24'
ENCODING = 'rows:[source_line,critical,diplomatic_or_null_same,patch_ids,split_part];record_index=trim_start+position;paragraph_id=SU-P+nonblank_ordinal'
DOMAIN = 'fixed-fullbook-readonly/v1'
SOURCE_DOMAIN = 'fixed-independent-source-owner/v1'
CERT = 'fixed-independent-source-certificate/v1'
HEAD = '9f9d13d94eac30731142fdc1577bb298eb5ff2b9'
LINE_KEYS = set('record_index source_line diplomatic critical patch_ids split_part'.split())
UNIT_KEYS = set('ordinal source_unit_id volume_id declared_start declared_end declared_occurrence heading_kind source_line_start source_anchor_sha256 paragraph_count character_count critical_sha256 title_present'.split())
SPAN_KEYS = set('marker_index next_marker_index trim_start trim_end leading_blank_records trailing_blank_records next_marker'.split())
SOURCE_KEYS = {'domain','kind','encoding','shell','rows'}
SHELL_KEYS = {'domain','certificate_contract','fixed_source_commit','source_pins_sha256','source_unit','heading','span'}
TARGET_KEYS = {'schema_version','source_unit_id','source_critical_sha256','status','segments','chapter_title_en','notes'}
SEGMENT_KEYS = {'target_segment_id','source_paragraph_ids','en','notes','source_critical_sha256'}
KNOWN_KEYS = SOURCE_KEYS | SHELL_KEYS | UNIT_KEYS | SPAN_KEYS | LINE_KEYS | TARGET_KEYS | SEGMENT_KEYS

class ShapeError(Exception):
    pass

def need(ok, code):
    if not ok: raise ShapeError(code)

def canonical(v):
    return json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')

def sha(raw): return hashlib.sha256(raw).hexdigest()

def strict_json(raw, charge=lambda n,k:None):
    charge(len(raw),'payload_json_input_bytes')
    def unique(items):
        out={}
        for k,v in items:
            need(k not in out,'DUPLICATE_JSON_KEY');out[k]=v
        return out
    def bad(_):raise ShapeError('NONFINITE_JSON')
    try:
        v=json.loads(raw.decode('utf-8','strict'),object_pairs_hook=unique,parse_float=decimal.Decimal,parse_constant=bad)
        todo=[(v,0)];count=0
        while todo:
            child,depth=todo.pop();count+=1
            need(depth<=64 and count<=65536,'JSON_SHAPE_CAP')
            if type(child) is dict:
                for key,value in child.items():key.encode('utf-8','strict');todo.append((value,depth+1))
            elif type(child) is list:todo.extend((c,depth+1) for c in child)
            elif type(child) is str:child.encode('utf-8','strict')
            else:need(child is None or type(child) in (bool,int,decimal.Decimal),'JSON_SCALAR_TYPE')
        return v
    except (UnicodeError,ValueError,RecursionError):raise ShapeError('INVALID_JSON_UTF8') from None

def typename(v):
    if v is None:return 'null'
    if type(v) is str:return 'empty_string' if v=='' else 'string'
    if type(v) is list:return 'empty_array' if not v else 'array'
    if type(v) is dict:return 'empty_object' if not v else 'object'
    if type(v) is bool:return 'boolean'
    if type(v) is int:return 'integer'
    if type(v) is decimal.Decimal:return 'number'
    raise ShapeError('INVENTORY_TYPE')

def allowed_keys(role,path):
    if role=='source':
        if path=='':return SOURCE_KEYS
        if path=='/shell':return SHELL_KEYS
        if path=='/shell/source_unit':return UNIT_KEYS
        if path=='/shell/span':return SPAN_KEYS
        if path=='/shell/heading' or path=='/shell/span/next_marker' or re.fullmatch(r'/shell/span/(leading|trailing)_blank_records/[0-9]+',path):return LINE_KEYS
    else:
        if path=='':return TARGET_KEYS
        if re.fullmatch(r'/segments/[0-9]+',path):return SEGMENT_KEYS
    return set()

def inventory(value, role, charge=lambda n,k:None):
    """One row per node commitment, compact grouped counters, every exception key/location.
    Unknown key names are SHA256 path tokens; values never enter emitted reports.
    All unknown descendants retain ARCHIVAL_ONLY disposition. Ordinals are preorder.
    """
    groups=collections.Counter();notes=collections.Counter();totals=collections.Counter();exceptions=[]
    commitment=hashlib.sha256();note_commitment=hashlib.sha256()
    def record(event,h=commitment):
        b=canonical(event);charge(len(b),'field_event_serialization_bytes');charge(len(b),'field_event_hash_bytes');h.update(b);h.update(b'\n')
    def walk(v,path,safe,unknown=False,unsupported=False):
        ordinal=totals['present_nodes'];totals['present_nodes']+=1
        typ=typename(v);disposition='ARCHIVAL_ONLY'
        native_note=role!='source' and (path=='/notes' or re.fullmatch(r'/segments/[0-9]+/notes',path))
        key=path.rsplit('/',1)[-1]
        unexpected_note=key in ('note','notes') and not native_note
        unsupported=unsupported or unexpected_note or bool(native_note and v is not None and type(v) is not str)
        if unsupported:disposition='UNSUPPORTED_TYPED'
        elif not unknown:
            if role=='source' and re.fullmatch(r'/rows/[0-9]+/1',path) and type(v) is str and v!='':disposition='SUPPORTED_TYPED_FIELD'
            if role!='source' and (re.fullmatch(r'/segments/[0-9]+/en',path) or native_note and type(v) is str):disposition='SUPPORTED_TYPED_FIELD' if role=='current' else 'ARCHIVAL_ONLY'
            if role!='source' and (re.fullmatch(r'/segments/[0-9]+/(target_segment_id|source_paragraph_ids)(/[0-9]+)?',path) or path in ('/schema_version','/source_unit_id','/source_critical_sha256')):disposition='SUPPORTED_STRUCTURAL_FIELD' if role=='current' else 'ARCHIVAL_ONLY'
        if type(v) is str:
            b=v.encode('utf-8');charge(len(b),'field_string_utf8_bytes');charge(len(b),'field_value_hash_bytes');payload=[len(b),sha(b)]
        elif type(v) in (dict,list):payload=[len(v)]
        elif type(v) is decimal.Decimal:payload=[str(v)]
        else:payload=[v]
        schema=re.sub(r'/[0-9]+(?=/|$)','/*',safe)
        if role=='source' and re.fullmatch(r'/rows/[0-9]+/[0-4](?:/[0-9]+)?',safe):
            parts=safe.split('/');parts[2]='*'
            if len(parts)==5:parts[4]='*'
            schema='/'.join(parts)
        groups[(schema,typ,disposition)]+=1;totals[disposition]+=1
        need(len(groups)<=16384,'FIELD_GROUP_CAP')
        record([ordinal,safe,typ,disposition,payload])
        if native_note or unexpected_note:
            notes[('unexpected_location:' if unexpected_note else 'supported_location:')+typ]+=1
            record([safe,typ,payload],note_commitment)
            if unsupported:exceptions.append({'ordinal':ordinal,'path':safe,'type':typ,'disposition':'UNSUPPORTED_TYPED','code':'UNEXPECTED_NOTE_LOCATION' if unexpected_note else 'UNSUPPORTED_NOTES_VALUE'})
        if type(v) is dict:
            permitted=allowed_keys(role,path)
            optional=({'notes','chapter_title_en'} if role!='source' and path=='' else {'notes','source_critical_sha256'} if role!='source' and re.fullmatch(r'/segments/[0-9]+',path) else set())
            for missing in sorted(permitted-set(v)-optional):
                mp=safe+'/'+missing;totals['required_absent_slots']+=1;record(['required_absent',mp]);groups[(re.sub(r'/[0-9]+(?=/|$)','/*',mp),'absent','UNSUPPORTED_TYPED')]+=1
                exceptions.append({'ordinal':ordinal,'path':mp,'type':'absent','disposition':'UNSUPPORTED_TYPED','code':'MISSING_REQUIRED_FIELD'})
            for k,c in v.items():
                kb=k.encode('utf-8');charge(len(kb),'field_key_utf8_bytes');totals['object_fields']+=1
                escaped=k.replace('~','~0').replace('/','~1')
                newpath=path+'/'+escaped
                is_unknown=unknown or k not in permitted
                segment=escaped if not is_unknown else '@key-sha256:'+sha(kb)
                newsafe=safe+'/'+segment
                if k not in permitted and not unknown:
                    exceptions.append({'ordinal':totals['present_nodes'],'path':newsafe,'type':typename(c),'disposition':'ARCHIVAL_ONLY' if k not in ('note','notes') else 'UNSUPPORTED_TYPED','code':'UNKNOWN_FIELD','key_utf8_bytes':len(kb),'subtree_included':True})
                walk(c,newpath,newsafe,is_unknown,unsupported)
        elif type(v) is list:
            totals['array_slots']+=len(v)
            for i,c in enumerate(v):walk(c,path+'/'+str(i),safe+'/'+str(i),unknown,unsupported)
    walk(value,'','')
    absent=[]
    if role!='source' and type(value) is dict:
        for k in ('notes','chapter_title_en'):
            if k not in value:absent.append('/'+k)
        if type(value.get('segments')) is list:
            for i,seg in enumerate(value['segments']):
                if type(seg) is dict:
                    for k in ('notes','source_critical_sha256'):
                        if k not in seg:absent.append(f'/segments/{i}/{k}')
        for p in absent:
            totals['expected_absent_slots']+=1;groups[(re.sub(r'/[0-9]+/','/*/',p),'absent','ARCHIVAL_ONLY' if role=='previous' else 'SUPPORTED_ABSENCE')]+=1
            record(['absent',p])
            if p.endswith('/notes'):notes['supported_location:absent']+=1;record([p,'absent'],note_commitment)
    return {'format':FORMAT,'denominator':dict(totals),'schema_groups':[{'path':p,'type':t,'disposition':d,'count':n} for (p,t,d),n in sorted(groups.items())],
            'notes':dict(notes),'field_commitment_sha256':commitment.hexdigest(),'note_commitment_sha256':note_commitment.hexdigest(),'exceptions':exceptions}

def source_decode(obj, owner, charge=lambda n,k:None):
    """Independently reconstruct the exact legacy expansion without original module execution."""
    uid=owner['native_owner'];need(type(obj) is dict,'SOURCE_OBJECT')
    need(SOURCE_KEYS<=set(obj) and obj['domain']==DOMAIN and obj['kind']=='compact-source' and obj['encoding']==ENCODING,'SOURCE_ENCODING')
    shell=obj['shell'];rows=obj['rows'];need(type(shell) is dict and SHELL_KEYS<=set(shell),'SOURCE_SHELL')
    need(shell['domain']==SOURCE_DOMAIN and shell['certificate_contract']==CERT and shell['fixed_source_commit']==HEAD,'SOURCE_CERTIFICATE')
    need(type(shell['source_pins_sha256']) is str and re.fullmatch('[0-9a-f]{64}',shell['source_pins_sha256']),'SOURCE_PINS_DIGEST')
    u=shell['source_unit'];sp=shell['span'];heading=shell['heading']
    need(type(u) is dict and UNIT_KEYS<=set(u),'SOURCE_UNIT_FIELDS')
    need(u['source_unit_id']==uid and u['ordinal']==int(uid[3:]) and u['volume_id']==owner['volume'],'SOURCE_UNIT_ID_VOLUME')
    need(type(rows) is list and len(rows)<=4096 and type(sp) is dict and SPAN_KEYS<=set(sp),'SOURCE_ROWS_SPAN')
    a,b,c,d=[sp[k] for k in ('marker_index','next_marker_index','trim_start','trim_end')]
    need(all(type(x) is int for x in (a,b,c,d)) and 0<=a and a+1<=c<=d<=b and d-c==len(rows),'SOURCE_SPAN_RANGE')
    def check(r):
        need(type(r) is dict and LINE_KEYS<=set(r),'SOURCE_LINE_FIELDS')
        need(type(r['record_index']) is int and r['record_index']>=0 and type(r['source_line']) is int and r['source_line']>0,'SOURCE_LINE_COORDINATES')
        need(type(r['split_part']) is int and r['split_part']>=0,'SOURCE_SPLIT_PART')
        need(all(type(r[k]) is str and '\r' not in r[k] and '\n' not in r[k] for k in ('critical','diplomatic')),'SOURCE_LINE_TEXT')
        p=r['patch_ids'];need(type(p) is list and all(type(x) is str and x for x in p) and len(p)==len(set(p)),'SOURCE_PATCH_IDS')
    check(heading);body=[];ps=[];counts=collections.Counter()
    for i,row in enumerate(rows):
        need(type(row) is list and len(row)==5,'SOURCE_FIVE_SLOT_ROW')
        line,critical,diplomatic,patches,part=row
        r={'record_index':c+i,'source_line':line,'critical':critical,'diplomatic':critical if diplomatic is None else diplomatic,'patch_ids':patches,'split_part':part};check(r);body.append(r)
        counts['rows']+=1;counts['blank_rows']+=critical=='';counts['whitespace_nonempty_rows']+=bool(critical) and not critical.strip()
        counts['diplomatic_null_same_rows']+=diplomatic is None;counts['diplomatic_explicit_empty_rows']+=diplomatic=='';counts['critical_diplomatic_differ_rows']+=critical!=r['diplomatic'];counts['patched_rows']+=bool(patches);counts['split_rows']+=part>0
        if critical!='':
            n=len(ps)+1;cb=critical.encode();db=r['diplomatic'].encode();charge(len(cb)+len(db),'source_text_utf8_bytes');charge(len(cb)+len(db),'source_text_hash_bytes')
            ps.append({'source_paragraph_id':f'{uid}-P{n:04d}','source_unit_id':uid,'ordinal':n,**r,'critical_sha256':sha(cb).upper(),'diplomatic_sha256':sha(db).upper()})
    leading=sp['leading_blank_records'];trailing=sp['trailing_blank_records'];nxt=sp['next_marker']
    need(type(leading) is list and type(trailing) is list and len(leading)==c-a-1 and len(trailing)==b-d,'SOURCE_TRIM_COUNTS')
    chain=[heading]+leading+body+trailing
    for r in chain:check(r)
    need([r['record_index'] for r in chain]==list(range(a,b)),'SOURCE_RECORD_ORDER')
    need(all(r['critical']=='' for r in leading+trailing) and (not body or body[0]['critical']!='' and body[-1]['critical']!=''),'SOURCE_TRIM_BLANKS')
    if nxt is not None:check(nxt);need(nxt['record_index']==b,'SOURCE_NEXT_MARKER');chain=chain+[nxt]
    for prev,cur in zip(chain,chain[1:]):
        need(cur['source_line']>=prev['source_line'],'SOURCE_LINE_ORDER')
        need((cur['split_part']==prev['split_part']+1 and cur['diplomatic']==prev['diplomatic']) if cur['source_line']==prev['source_line'] else cur['split_part']==0,'SOURCE_SPLIT_ORDER')
    hb=heading['diplomatic'].encode();charge(len(hb),'source_heading_utf8_bytes');charge(len(hb),'source_heading_hash_bytes')
    need(heading['source_line']==u['source_line_start'] and sha(hb).upper()==u['source_anchor_sha256'],'SOURCE_HEADING_ANCHOR')
    block='\n'.join([heading['critical']]+[r['critical'] for r in body]);bb=block.encode();charge(len(bb),'source_basis_utf8_bytes');charge(len(bb),'source_basis_hash_bytes')
    basis=sha(bb).upper();need(basis==u['critical_sha256']==owner['source_basis_sha256'],'SOURCE_LF_BASIS')
    need(type(u['paragraph_count']) is int and len(ps)==u['paragraph_count']==owner['declared_paragraphs'],'SOURCE_PARAGRAPH_DENOMINATOR')
    need(type(u['character_count']) is int and sum(len(p['critical'].strip()) for p in ps)==u['character_count'],'SOURCE_CHARACTER_COUNT')
    expanded={**shell,'source_line_records':body,'source_paragraphs':ps,'critical_block':block}
    try:eb=canonical(expanded)
    except (TypeError,ValueError):raise ShapeError('EXPANSION_CANONICAL_UNSUPPORTED_NUMBER') from None
    charge(len(eb),'expanded_source_serialization_bytes');charge(len(eb),'expanded_source_hash_bytes')
    return {'paragraphs':ps,'basis':basis,'expanded_source_sha256':sha(eb),'expanded_source_bytes':len(eb),'counts':dict(counts),'source_pins_sha256':shell['source_pins_sha256']}

def target_decode(doc,owner,source,role,charge=lambda n,k:None):
    uid=owner['native_owner'];need(type(doc) is dict,'TARGET_OBJECT')
    need({'schema_version','source_unit_id','source_critical_sha256','status','segments'}<=set(doc),'TARGET_REQUIRED_FIELDS')
    need(type(doc['schema_version']) is int and doc['schema_version']==1 and doc['source_unit_id']==uid,'TARGET_OWNER_SCHEMA')
    need(doc['source_critical_sha256']==source['basis'],'TARGET_SOURCE_BASIS')
    need(type(doc['status']) is str and doc['status'] in {'pilot-draft','draft','review','approved','stale'},'TARGET_STATUS_ARCHIVAL')
    segs=doc['segments'];need(type(segs) is list and len(segs)<=4096,'TARGET_SEGMENTS')
    ps={p['source_paragraph_id']:p for p in source['paragraphs']};degree=collections.Counter();used=set();previous=0;ordered=True;edges=0;empty=0;claims=0;parent={}
    def find(x):
        parent.setdefault(x,x)
        while parent[x]!=x:parent[x]=parent[parent[x]];x=parent[x]
        return x
    def union(x,y):parent[find(x)]=find(y)
    coverage=[]
    for i,seg in enumerate(segs):
        need(type(seg) is dict and {'target_segment_id','source_paragraph_ids','en'}<=set(seg),'TARGET_SEGMENT_FIELDS')
        tid=f'{uid}-T{i+1:04d}';need(seg['target_segment_id']==tid,'TARGET_ID_ORDER');need(type(seg['en']) is str,'TARGET_EN_STRING')
        refs=seg['source_paragraph_ids'];need(type(refs) is list and 0<len(refs)<=4096 and all(type(x) is str for x in refs),'TARGET_SOURCE_REF_SHAPE')
        need(len(set(refs))==len(refs) and all(x in ps for x in refs),'TARGET_SOURCE_REF_MEMBERSHIP')
        nums=[int(x[-4:]) for x in refs];ordered &= nums==sorted(nums) and nums[0]>=previous;previous=nums[-1]
        for sid in refs:degree[sid]+=1;union('P:'+sid,'T:'+tid)
        used.update(refs);edges+=len(refs);empty+=not bool(seg['en'].strip())
        if 'source_critical_sha256' in seg:
            need(len(refs)==1 and seg['source_critical_sha256']==ps[refs[0]]['critical_sha256'],'TARGET_PARAGRAPH_CLAIM');claims+=1
        coverage.append({'target_id':tid,'source_ids':refs})
    components=collections.defaultdict(lambda:[0,0])
    for node in parent:components[find(node)][0 if node.startswith('P:') else 1]+=1
    graph=collections.Counter()
    for p,t in components.values():graph['one_to_one' if (p,t)==(1,1) else 'one_to_many' if p==1 else 'many_to_one' if t==1 else 'many_to_many']+=1
    cov=canonical(coverage);charge(len(cov),'coverage_serialization_bytes');charge(len(cov),'coverage_hash_bytes')
    return {'targets':len(segs),'edges':edges,'source_count':len(ps),'covered_sources':len(used),'missing_sources':len(ps)-len(used),'empty_en':empty,'paragraph_hash_claims':claims,'strict_order':bool(ordered),'complete_structural_coverage':used==set(ps),'maximum_sources_per_target':max([len(x['source_ids']) for x in coverage]+[0]),'sources_with_multiple_targets':sum(n>1 for n in degree.values()),'components':dict(graph),'coverage_sha256':sha(cov),'literary_alignment':'UNKNOWN_NOT_ESTABLISHED_BY_STRUCTURE','native_status_exact_old_document':doc['status'],'semantic_approval':'UNKNOWN'}
