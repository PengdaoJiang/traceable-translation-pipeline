"""Nontrivial bounded synthetic owners, explicitly no native provenance."""
import copy,hashlib,importlib.util,json
from pathlib import Path
import kernel_streaming as stream
k=stream.k
HERE=Path(__file__).resolve().parent
p=HERE/'synthetic_sources.py'
spec=importlib.util.spec_from_file_location('v22_synthetic',p);base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)

def capture(number,pairs=16):
    # Only one tiny original template; all identity fields rebuilt for requested owner.
    template=base.prepare(1);old='SU01';owner=f'SU{number:02d}';uid=f'SU-{number:06d}'
    origin=template['origins'][old];source=json.loads(template['archives'][old]['source_owner']);target=json.loads(template['archives'][old]['native_target'])
    heading=f'SYNTHETIC owner {number:06d}'
    source['shell']['heading']['critical']=heading;source['shell']['source_unit']['source_unit_id']=uid;source['shell']['source_unit']['paragraph_count']=pairs;source['shell']['span']['trim_end']=pairs
    source['rows']=[[i+1,f'Synthetic source {number:06d}/{i:04d} '+('x'*96),None,[],0] for i in range(pairs)]
    basis=k.sha(('\n'.join([heading]+[x[1] for x in source['rows']])).encode()).upper();source['shell']['source_unit']['critical_sha256']=basis
    target['source_unit_id']=uid;target['source_critical_sha256']=basis;target['segments']=[{'target_segment_id':f'{uid}-T{i+1:04d}','en':f'Synthetic target {number:06d}/{i:04d} '+('y'*96),'source_paragraph_ids':[f'{uid}-P{i+1:04d}']} for i in range(pairs)]
    archives={'source_owner':k.canonical(source),'native_target':k.canonical(target)}
    origin['source'].update(source_owner_sha256=k.sha(archives['source_owner']),native_target_sha256=k.sha(archives['native_target']),source_basis_sha256=basis)
    pids=[f'{uid}-P{i+1:04d}' for i in range(pairs)];tids=[f'{uid}-T{i+1:04d}' for i in range(pairs)]
    origin['selection'].update(native_owner=uid,owner=owner,source_ids=pids,target_ids=tids)
    origin['records']={};origin['archives']={};origin['notes']={};origin['coverage']=[];originals={}
    for kind,raw in archives.items():
        origin['archives'][kind]={'kind':kind,'path':k.archive_path(owner,kind),'sha256':k.sha(raw),'byte_length':len(raw),'media_type':'application/json','representation':k.ARCHIVE_REPRESENTATIONS[kind]}
    for kind,ids,values in [('source',pids,[x[1] for x in source['rows']]),('target',tids,[x['en'] for x in target['segments']])]:
        offset=0
        for i,(ident,text) in enumerate(zip(ids,values)):
            loc={'representation':'authenticated_expanded_source' if kind=='source' else 'native_target_json','json_pointer':f'/source_paragraphs/{i}/critical' if kind=='source' else f'/segments/{i}/en','record_index':i}
            if kind=='source':
                for key,slot in [('compact_json_pointer',1),('source_line_json_pointer',0),('diplomatic_json_pointer',2),('patch_ids_json_pointer',3),('split_part_json_pointer',4)]:loc[key]=f'/rows/{i}/{slot}'
            origin['records'][ident]={'kind':kind,'text_sha256':k.sha(text.encode()),'text_utf8_bytes':len(text.encode()),'original_span':[offset,offset+len(text)],'native_locator':loc};offset+=len(text)+1
        originals[kind]=''.join(text+'\n' for text in values).encode()
    for i,tid in enumerate(tids):origin['notes'][tid]={'presence':'absent','type':'missing','json_pointer':f'/segments/{i}/notes'};origin['coverage'].append({'target_id':tid,'source_ids':[pids[i]]})
    member=template['owner_grants'][old];member.update(owner=owner,native_owner=uid,source_count=pairs,target_count=pairs,coverage_count=pairs,edge_count=pairs,origin_sha256=k.sha(k.canonical(origin)))
    return {'owner':owner,'origin':origin,'member_grant':member,'archives':archives,'originals':originals,'models':[],'retained':[]}

def captures(count,pairs=16):
    for number in range(1,count+1):yield capture(number,pairs)

def inventory(count,pairs=16):return {c['owner']:k.sha(k.canonical(stream.capture_receipt(c))) for c in captures(count,pairs)}
