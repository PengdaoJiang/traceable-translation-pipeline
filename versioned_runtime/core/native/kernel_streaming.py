"""v25 bounded-owner genesis and complete cold audit.

Trusted host inputs are exact capture receipts, not a repository-local grant.
Only a same-epoch complete durable closure token permits streaming publication.
Prior bytes are ARCHIVAL_ONLY, never native revision or approval evidence.
"""
import contextlib, copy, hashlib, importlib.util, os, re, sqlite3, sys, tempfile, types, weakref
from pathlib import Path

HERE=Path(__file__).resolve().parent
base_bytes=(HERE/'kernel_base.py').read_bytes()
module_bytes=Path(__file__).read_bytes()
capacity_bytes=(HERE/'capacity_gate.py').read_bytes()
platform_path=HERE.parent.parent/'platform_api.py'
platform_bytes=platform_path.read_bytes()
PLATFORM=types.ModuleType('pinned_semantic_platform_api');PLATFORM.__file__=str(platform_path)
sys.modules[PLATFORM.__name__]=PLATFORM
exec(compile(platform_bytes,str(platform_path),'exec'),PLATFORM.__dict__)
PIN=hashlib.sha256(b'semantic-platform-native/v1\0'+base_bytes+b'\0'+module_bytes+b'\0'+capacity_bytes+b'\0'+platform_bytes).hexdigest()
k=types.ModuleType('v25_kernel_base');k.__file__=str(HERE/'kernel_base.py');k.__executed_source_sha256__=PIN;k.__platform_api__=PLATFORM
exec(compile(base_bytes,k.__file__,'exec'),k.__dict__)
spec=importlib.util.spec_from_file_location('v25_capacity_gate',HERE/'capacity_gate.py')
capacity=importlib.util.module_from_spec(spec);spec.loader.exec_module(capacity)
k.capacity_gate=capacity;k._MODULE=k
need=k.need
BATCH_BYTES=8*1024*1024;BATCH_OBJECTS=512
RETENTION='SELECTED_ENDPOINT_ONLY_INTERMEDIATE_REVISIONS_UNKNOWN'
BASELINE_MESSAGE='host admitted bounded radix owner-set baseline; provenance mode in grant; not whole book'
_TOKENS=weakref.WeakKeyDictionary()
_AUDITS=weakref.WeakKeyDictionary()
class _ColdResult(dict):
    __hash__=object.__hash__
    __eq__=object.__eq__

class _AdmittedRoot: pass

class Repo(k.Repo):
    """Batches release only after flush/assert; cannot use ordinary CAS thereafter."""
    def __init__(self,path):
        super().__init__(path);self.epoch=None;self.batch_enabled=False;self.batch_readonly=False;self.generation=0
        self.highwater={'required_bytes':0,'required_objects':0,'staged_bytes':0,'batch_count':0}
        self.released_in_epoch=False
    @contextlib.contextmanager
    def integrity_operation(self):
        need(self.epoch is None,'nested integrity epoch unsupported')
        with super().integrity_operation():
            self.epoch=object();self.released_in_epoch=False
            try:yield
            finally:self.epoch=None;self.batch_enabled=False
    def _measure(self):
        values={'required_bytes':sum(len(b) for _,b in self.required.values()),'required_objects':len(self.required),'staged_bytes':sum(len(b) for _,b in self.staged.values())}
        for name,value in values.items():self.highwater[name]=max(self.highwater[name],value)
        return values
    def _room(self,n):
        if not self.batch_enabled:return
        values=self._measure()
        if values['required_objects']>=BATCH_OBJECTS or values['required_bytes']+n>BATCH_BYTES:self.release_batch()
    def get(self,h,expected=None,category='state'):
        self._room(k.SCHEMA['object_bytes_max'])
        b=super().get(h,expected,category);self._measure();return b
    def stage(self,kind,b):
        self._room(len(b));h=super().stage(kind,b);self._measure();return h
    def release_batch(self):
        need(self.epoch is not None,'batch outside integrity epoch')
        if self.batch_readonly:self.admit_existing_required()
        else:self.flush()
        self.assert_admitted()
        self.memo.clear();self.trees.clear();self.required.clear();self.staged.clear();self.operation_admitted.clear()
        self.highwater['batch_count']+=1;self.released_in_epoch=True;self.generation+=1
    @contextlib.contextmanager
    def object_batch(self,readonly=False):
        need(self.epoch is not None and not self.batch_enabled,'invalid object batch scope')
        self.batch_enabled=True;self.batch_readonly=readonly
        try:yield;self.release_batch()
        finally:self.batch_enabled=False;self.batch_readonly=False
    def cas(self,new,old):
        need(not self.released_in_epoch,'streamed state requires complete durable closure token')
        super().cas(new,old)
    def cas_admitted_root(self,token,new,old):
        value=_TOKENS.pop(token,None)
        need(value is not None,'unknown/consumed root admission')
        binding=(self,self.epoch,self.generation,new,old,k.code_pin(),k.SCHEMA_PIN)
        need(value['binding']==binding and value['service'] is k._service_key(self.service_key) and self.epoch is not None,'root admission epoch/repository/root changed')
        need(self.ref()==old,'CAS old root conflict')
        actual=self._load(new,'commit','final_root_header')[1]
        need(k.sha(actual)==value['commit_sha256'] and self.root(new)==value['tree'],'root admission header changed')
        k._durable_ref_cas(self,new,old)

class DescriptorStore:
    """Bounded-cache disk sort. This is scratch metadata, never authority."""
    def __init__(self,directory):
        fd,name=tempfile.mkstemp(prefix='v25-descriptors-',suffix='.sqlite',dir=directory);os.close(fd)
        self.path=Path(name);self.db=sqlite3.connect(name)
        self.db.execute('PRAGMA cache_size=-1024');self.db.execute('PRAGMA temp_store=FILE')
        self.db.execute('CREATE TABLE paths (phase TEXT,path TEXT,mode TEXT,oid TEXT,PRIMARY KEY(phase,path)) WITHOUT ROWID')
        self.count=0
    def put(self,phase,path,oid,replace=False):
        need(isinstance(path,str) and len(path)<=512 and path.isascii() and all(re.fullmatch(r'[A-Za-z0-9_.-]+',x) and x not in ('.','..') for x in path.split('/')),'descriptor path')
        need(path.count('/')<=20 and k.OID.fullmatch(oid),'descriptor bounds')
        need(self.count<1000000,'descriptor row budget')
        try:self.db.execute(('INSERT OR REPLACE' if replace else 'INSERT')+' INTO paths VALUES (?,?,?,?)',(phase,path,'100644',oid))
        except sqlite3.IntegrityError:raise k.Rejected('duplicate descriptor path') from None
        self.count+=1
    def clone(self,old,new):
        n=self.db.execute('SELECT count(*) FROM paths WHERE phase=?',(old,)).fetchone()[0]
        need(self.count+n<=1000000,'descriptor row budget')
        self.db.execute('INSERT INTO paths SELECT ?,path,mode,oid FROM paths WHERE phase=?',(new,old));self.count+=n
    def rows(self,phase):
        return self.db.execute('SELECT path,mode,oid FROM paths WHERE phase=? ORDER BY path COLLATE BINARY',(phase,))
    def close(self):self.db.close()


def fold_tree_entries(r,entries):
    """Longest-common-prefix stack, <=200 child descriptors per depth."""
    stack=[('',{})];previous=None;count=0
    def finish():
        name,children=stack.pop();raw=k.tree_bytes(children);h=r.stage('tree',raw)
        need(name not in stack[-1][1],'file/directory path collision');stack[-1][1][name]=('40000',h)
        need(len(stack[-1][1])<=200,'tree fanout limit')
    for path,mode,oid in entries:
        need(mode=='100644' and k.OID.fullmatch(oid),'tree descriptor type/OID')
        need(previous is None or previous<path,'tree entries unsorted/duplicate');previous=path
        parts=path.split('/');need(len(parts)<=21,'tree depth bound')
        common=0
        while common<len(stack)-1 and common<len(parts)-1 and stack[common+1][0]==parts[common]:common+=1
        while len(stack)-1>common:finish()
        for part in parts[common:-1]:
            need(part not in stack[-1][1],'file/directory collision');stack.append((part,{}))
        need(parts[-1] not in stack[-1][1],'duplicate tree path');stack[-1][1][parts[-1]]=(mode,oid)
        need(len(stack[-1][1])<=200,'tree fanout limit');count+=1;need(count<=1000000,'tree file count budget')
    while len(stack)>1:finish()
    return r.stage('tree',k.tree_bytes(stack[0][1]))


def retained_paths(owner):
    base='retained/'+k.owner_radix_path(owner)
    return base+'/inventory.json',base+'/prior.raw.json'


def capture_receipt(capture):
    return {'owner':capture['owner'],'origin_sha256':k.sha(k.canonical(capture['origin'])),
            'member_grant_sha256':k.sha(k.canonical(capture['member_grant'])),
            'archives':{name:{'sha256':k.sha(raw),'bytes':len(raw)} for name,raw in capture['archives'].items()},
            'retained':[{'metadata_sha256':k.sha(k.canonical(x['metadata'])),'raw_sha256':k.sha(x['raw']),'raw_bytes':len(x['raw'])} for x in capture.get('retained',[])]}


def validate_capture(capture,inventory,mode):
    owner=capture['owner'];need(owner in inventory,'capture outside external owner inventory')
    need(k.sha(k.canonical(capture_receipt(capture)))==inventory[owner],'capture differs from external receipt')
    member=capture['member_grant'];origin=capture['origin'];k._member_grant_contract(member)
    need(member['owner']==owner and member['format']==('host-authenticated-r0-owner/v25' if mode=='real_r0_body' else 'synthetic-scale-single-owner-origin/v1'),'capture owner/mode')
    k._member_origin_contract(origin,member['origin_sha256'],[owner],member)
    fields=k._verify_archive_fields(capture['archives'],origin)
    need(set(capture['originals'])=={'source','target'},'capture projections')
    for kind,key in (('source','source_ids'),('target','target_ids')):
        expected=''.join(fields['text'][i]+'\n' for i in origin['selection'][key]).encode()
        need(capture['originals'][kind]==expected,'capture exact derived projection')
    return fields


def retained_inventory(owner,ret):
    inventory_path,raw_path=retained_paths(owner)
    if not ret:return {'format':'retained-owner-archive/v25','owner':owner,'entries':[]}
    need(isinstance(ret,list) and len(ret)==1,'at most one selected prior per owner')
    raw=ret[0]['raw'];meta=ret[0]['metadata']
    keys={'disposition','domain','format','history_coverage','native_owner','raw_byte_length','raw_sha256','role','source_git_blob','source_git_commit','source_git_commit_absence','source_receipt_sha256'}
    # Cold rebuild strips physical fields; restores immutable logical labels.
    meta={**meta,'domain':'native_target','role':'selected_prior_endpoint','disposition':'ARCHIVAL_ONLY_NO_CURRENT_APPROVAL','history_coverage':RETENTION}
    need(set(meta)==keys and meta['format']=='selected-prior-archive/v25','retained descriptor exact fields')
    need(meta['source_git_commit'] is None and meta['source_git_commit_absence']=='Stage-A owner row does not authenticate a unique intermediate commit','retained source commit absence contract')
    desc={**meta,'git_blob':k.oid('blob',raw)}
    if 'source_git_blob' in desc:need(desc['source_git_blob']==desc['git_blob'],'retained source Git identity')
    need(type(raw) is bytes and 0<len(raw)<=k.SCHEMA['object_bytes_max'],'retained raw bound')
    need(isinstance(desc,dict) and desc.get('native_owner')==f'SU-{int(owner[2:]):06d}','retained owner')
    need(desc.get('raw_sha256')==k.sha(raw) and desc.get('raw_byte_length')==len(raw),'retained exact identity')
    need(desc.get('git_blob')==k.oid('blob',raw),'retained native Git blob identity')
    k._origin_digest(desc.get('source_receipt_sha256'),'retained receipt')
    return {'format':'retained-owner-archive/v25','owner':owner,'entries':[{**copy.deepcopy(desc),'storage_path':raw_path,'domain':'native_target','role':'selected_prior_endpoint','disposition':'ARCHIVAL_ONLY_NO_CURRENT_APPROVAL','history_coverage':RETENTION}]}


def _regenerate(r,raw_anchor,owner,grant):
    index=k.OwnerIndex(r,raw_anchor,grant);origin=index.origin(owner);member=index.member_grant(owner)
    raws={kind:r.read_path(raw_anchor,k.archive_storage_path(owner,kind)) for kind in k.ARCHIVE_KINDS}
    fields=k._verify_archive_fields(raws,origin);rows=[];nodes={};projections={}
    for kind,key in (('source','source_ids'),('target','target_ids')):
        projections[kind]=r.read_path(raw_anchor,k.original_path(owner,kind))
        for ident in origin['selection'][key]:
            mapping=origin['records'][ident];text=fields['text'][ident]
            node={'id':ident,'kind':kind,'slot':k.locate(ident)[2],'order':mapping['native_locator']['record_index'],'live':True,'version':0,'text':text,'digest':mapping['text_sha256'],'original':{'ref':kind,'span':mapping['original_span'],'version':0,'current_alignment':'EXACT_NATIVE_ARCHIVE_FIELD_BYTES' if grant['mode']=='real_r0_body' else 'EXACT_SYNTHETIC_ARCHIVE_FIELD_BYTES'},'prior':None,'responsibility':{'for_version':0,'status':'UNKNOWN','claims':[]},'lineage':[]}
            if kind=='target':node.update(facts=copy.deepcopy(k.FACT_TEMPLATE),obligations=[])
            nodes[ident]=node;rows.append(node)
    for i,cov in enumerate(origin['coverage']):
        rows.append({'id':owner+f':coverage:{i+1:04d}','kind':'coverage','slot':i+1,'mode':'native_structural','sources':[k.span_ref(nodes[x]) for x in cov['source_ids']],'targets':[k.span_ref(nodes[cov['target_id']])],'source_alignment':'UNKNOWN','claim':'native_structural_only_not_actual_use'})
    for ident,spec in [*origin['notes'].items(),(None,origin['owner_note'])]:
        if spec['type']!='string':continue
        text=fields['notes'][ident] if ident else fields['owner_note']
        about={key:nodes[ident][key] for key in ('id','kind','version','digest')} if ident else {'kind':'owner','owner':owner}
        rows.append({'id':spec['id'],'kind':'note','slot':k.locate(spec['id'])[2],'version':0,'text':text,'digest':k.sha(text.encode()),'about':about,'prior':None,'approval':{'for_note_version':0,'status':'UNKNOWN','claims':[]}})
    return {'owner':owner,'origin':origin,'member_grant':member,'archives':raws,'originals':projections,'models':rows}


def _refs(capture,anchor,mode):
    owner=capture['owner'];member=capture['member_grant'];origin=capture['origin']
    archives={kind:{**copy.deepcopy(d),'storage_path':k.archive_storage_path(owner,kind),'commit':anchor,'git_blob':k.oid('blob',capture['archives'][kind]),'origin_sha256':member['origin_sha256'],'provenance':k.archive_provenance(mode)} for kind,d in origin['archives'].items()}
    refs={kind:{'kind':'derived_index_projection','provenance':k.projection_provenance(mode),'origin_sha256':member['origin_sha256'],'commit':anchor,'path':k.original_path(owner,kind),'git_blob':k.oid('blob',raw),'sha256':k.sha(raw),'byte_length':len(raw),'media_type':'text/plain;charset=utf-8'} for kind,raw in capture['originals'].items()}
    return refs,archives


def _scope_from_inventory(inventory):
    need(isinstance(inventory,dict) and 1<=len(inventory)<=2079,'external metadata inventory count')
    scope=sorted(inventory,key=lambda su:(len(su),su))
    for owner in scope:k.su_groups(owner);k._origin_digest(inventory[owner],'external capture receipt')
    return scope


def build_initial_streaming_session(r,captures,*,expected_inventory,mode):
    """Publish N0; highwater is the detached post-closure/CAS N0 snapshot."""
    with r.integrity_operation():
        context=(r.epoch,k._repository_identity(r),k._service_key(r.service_key),k.code_pin(),k.SCHEMA_PIN)
        result=_prepare_initial_streaming_in_epoch(r,captures,expected_inventory=expected_inventory,mode=mode)
        root=result['commit'];grant=result['grant'];audit=result['admission']
        token=admit_durable_closure(r,root,None,grant,audit)
        need(context[0] is r.epoch and r.epoch is not None and context[1]==k._repository_identity(r)
             and context[2] is k._service_key(r.service_key) and context[3:]==(k.code_pin(),k.SCHEMA_PIN),
             'initial repository/epoch/service/pins changed')
        r.cas_admitted_root(token,root,None)
        session=k.LogSession(k._SESSION_TOKEN,root,root,k.code_pin(),k.SCHEMA_PIN);session.repo_path=str(r.path);session.origin_sha256=grant['origin_sha256'];session.origin_blob=grant['indexes']['origins']['git_tree'];session.origin_grant=copy.deepcopy(grant)
        k._SESSION_BINDINGS[session]=k._session_binding(session);k._VALIDATION_REUSE.add(session);k._SESSION_PROVENANCE[session]={'mode':'FULL_INITIAL_STREAMING_ADMISSION','checkpoint_root':None}
        result['highwater']=dict(r.highwater)
        return result,session


def _prepare_initial_streaming_in_epoch(r,captures,*,expected_inventory,mode):
    """Capture once; next two passes reconstruct only from durable destination raws.

    expected_inventory is authenticated HOST input, never read from destination.
    Metadata is O(owner count), capped at 2079. Payload state is owner/batch bounded.
    """
    need(r.epoch is not None,'initial build requires active epoch')
    need(mode in ('real_r0_body','synthetic_scale_only'),'stream source mode')
    scope=_scope_from_inventory(expected_inventory);scope_set=set(scope)
    store=DescriptorStore(r.path.parent)
    need(r.ref() is None,'stream genesis requires empty public ref')
    try:
        seen=set();retained_count=0
        for capture in captures:
            owner=capture['owner'];need(owner not in seen,'duplicate capture owner');validate_capture(capture,expected_inventory,mode);seen.add(owner)
            with r.object_batch():
                payloads={k.owner_grant_path(owner):k.canonical(capture['member_grant']),k.origin_path(owner):k.canonical(capture['origin'])}
                payloads.update({k.archive_storage_path(owner,kind):raw for kind,raw in capture['archives'].items()})
                payloads.update({k.original_path(owner,kind):raw for kind,raw in capture['originals'].items()})
                inv=retained_inventory(owner,capture.get('retained'));ip,rp=retained_paths(owner);payloads[ip]=k.canonical(inv)
                if inv['entries']:payloads[rp]=capture['retained'][0]['raw'];retained_count+=1
                for path,raw in payloads.items():store.put('raw',path,r.stage('blob',raw))
            del payloads,inv,capture
        need(seen==scope_set,'incomplete external capture inventory')
        with r.object_batch():
            pre=fold_tree_entries(r,store.rows('raw'));top=r.tree(pre);indexes={}
            for name in ('owners','origins','archives','retained'):
                mode0,h=top[name];need(mode0=='40000','index tree');indexes[name]={'git_tree':h,'sha256':k.sha(r.get(h,'tree'))}
            grant={'format':'host-accepted-streaming-owner-roots/v25','mode':mode,'root':k.NATIVE_ROOT if mode=='real_r0_body' else k.SYNTHETIC_ROOT,'state':k.NATIVE_STATE if mode=='real_r0_body' else k.SYNTHETIC_STATE,'scope_count':len(scope),'scope_sha256':k.sha(k.scope_bytes(scope)),'indexes':indexes,'origin_sha256':indexes['origins']['sha256']}
            k._grant_contract(grant);store.put('raw','grant.json',r.stage('blob',k.canonical(grant)))
            raw_tree=fold_tree_entries(r,store.rows('raw'));anchor=r.stage('commit',k.commit_bytes(raw_tree,None,'v25 immutable exact archives and selected endpoints; no approval inheritance'))
        store.clone('raw','nodes')
        with r.object_batch():
            for path,payload in (('schema.json',k.canonical(k.SCHEMA)),('scope.json',k.canonical(k.scope_descriptor(grant)))):store.put('nodes',path,r.stage('blob',payload))
        for owner in scope:
            with r.object_batch():
                capture=_regenerate(r,anchor,owner,grant);refs,archives=_refs(capture,anchor,mode)
                encoded=k.encode_su(owner,[x for x in capture['models'] if x['kind'] in ('source','target')],refs,archives=archives)
                for path,raw in encoded.items():store.put('nodes',path,r.stage('blob',raw))
            del capture,refs,archives,encoded
        with r.object_batch():
            version_tree=fold_tree_entries(r,store.rows('nodes'));version_anchor=r.stage('commit',k.commit_bytes(version_tree,anchor,'v25 complete initial mapped versions; not upstream revision history'))
        store.clone('nodes','final');located=0
        for owner in scope:
            with r.object_batch():
                capture=_regenerate(r,anchor,owner,grant);refs,archives=_refs(capture,anchor,mode)
                route=k.decode(r.read_path(version_anchor,k.manifest_path(owner)))
                nodes={x['id']:x for x in capture['models'] if x['kind'] in ('source','target')}
                for row in capture['models']:
                    for ref in k.version_refs(row):
                        ident=ref['id'];need(k.locate(ident)[0]==owner,'cross-owner genesis unsupported')
                        ref['locator']={'commit':version_anchor,'page':k.route_page(route,ident),'record_sha256':k.sha(k.canonical(nodes[ident])),'owner':owner};located+=1
                for path,raw in k.encode_su(owner,capture['models'],refs,initial_anchor=version_anchor,archives=archives).items():store.put('final',path,r.stage('blob',raw),True)
            del capture,refs,archives,nodes,route
        with r.object_batch():
            final_tree=fold_tree_entries(r,store.rows('final'));root=r.stage('commit',k.commit_bytes(final_tree,version_anchor,BASELINE_MESSAGE))
        audit=cold_streaming(r,root,k.scope_descriptor(grant),expected_origin_sha256=grant['origin_sha256'],require_origin_baseline=True,require_empty_obligations=True,expected_grant=grant)
        context=types.SimpleNamespace(admission=root,root=root,code=k.code_pin(),schema=k.SCHEMA_PIN,origin_grant=grant,origin_sha256=grant['origin_sha256'],_active={},_seen=set(),transitions=0)
        with r.object_batch():checkpoint=capacity.check_candidate_capacity(k,r,context,root)
        return {'anchor':anchor,'version_anchor':version_anchor,'commit':root,'admission':audit,'initial_locators':located,'origin_sha256':grant['origin_sha256'],'grant':grant,'checkpoint_bytes':len(checkpoint),'retained':retained_count,'scratch_metadata':str(store.path)}
    finally:store.close()


def _ancestors(r,commit):
    from v27_pinned_durable_proofs import DiskAncestry,RunBudget
    return DiskAncestry(k,r,commit,directory=r.path.parent,budget=RunBudget())


def _iter_paths(r,root):
    count=0
    def walk(h,prefix,depth):
        nonlocal count
        need(depth<=20,'namespace depth limit')
        tree=r.tree(h);count+=1;need(count<=1000000,'namespace tree budget')
        need(tree or depth==0,'unexpected empty directory')
        for name,(mode,oid) in sorted(tree.items(),key=lambda x:x[0]+('/' if x[1][0]=='40000' else '')):
            path=prefix+name
            if mode=='40000':yield from walk(oid,path+'/',depth+1)
            else:yield path,mode,oid
    yield from walk(root,'',0)


def _enumerate_scope(r,commit,grant):
    # Only O(owner IDs); never grant/origin caches for complete scope.
    index=k.OwnerIndex(r,commit,grant);found=[];visits=0
    def walk(h,prefix):
        nonlocal visits
        visits+=1;need(visits<=16*grant['scope_count']+1,'owner index directory budget')
        for name,(mode,child) in r.tree(h).items():
            need(mode=='40000','owner index directories only')
            if re.fullmatch('u[0-9]{2}',name):
                groups=prefix+[name[1:]];su=f'SU{int("".join(groups)):02d}'
                need(k.owner_radix_path(su)=='/'.join(prefix+[name]),'canonical owner radix')
                leaf=r.tree(child);need(set(leaf)=={'grant.json'} and leaf['grant.json'][0]=='100644','exact owner leaf namespace')
                found.append(su);need(len(found)<=grant['scope_count'],'extra owner index')
            else:
                need(re.fullmatch('[0-9]{2}',name) and len(prefix)<15,'radix intermediate directory');walk(child,prefix+[name])
    walk(index.roots['owners'],[]);found.sort(key=lambda su:(len(su),su))
    need(len(found)==len(set(found))==grant['scope_count'] and k.sha(k.scope_bytes(found))==grant['scope_sha256'],'owner inventory commitment')
    return found


def cold_streaming(r,commit,expected_scope,verify_originals=True,require_empty_obligations=False,*,expected_origin_sha256=None,require_origin_baseline=False,expected_grant):
    need(r.epoch is not None,'stream cold requires integrity epoch');k._grant_contract(expected_grant)
    need(verify_originals is True and expected_origin_sha256==expected_grant['origin_sha256'],'complete cold originals/grant required')
    store=DescriptorStore(r.path.parent);counts={x:0 for x in ('owners','records','nodes','coverage','notes','target_notes','owner_notes','archive_payload_bytes','projection_payload_bytes','origin_payload_bytes','retained_objects','retained_payload_bytes')}
    roll=hashlib.sha256();joint_anchor=None;joint_version=None;ancestors=None
    try:
        with r.object_batch(readonly=True):
            ancestors=_ancestors(r,commit);scope=_enumerate_scope(r,commit,expected_grant)
            need(expected_scope==scope or expected_scope==k.scope_descriptor(expected_grant),'external cold scope')
            for path,value in (('schema.json',k.SCHEMA),('scope.json',k.scope_descriptor(expected_grant)),('grant.json',expected_grant)):
                raw=r.read_path(commit,path);need(raw==k.canonical(value),'root header bytes');store.put('expected',path,k.oid('blob',raw))
                store.put('version_expected',path,k.oid('blob',raw))
                if path=='grant.json':store.put('raw_expected',path,k.oid('blob',raw))
        for owner in scope:
            with r.object_batch(readonly=True):
                snap=k.Snapshot(r,commit,expected_grant);snap._admitted_ancestors=ancestors;origin=snap.index.origin(owner);member=snap.member_grant(owner);rows=snap.su(owner);manifest=snap.manifests[owner]
                for path in (k.owner_grant_path(owner),k.origin_path(owner),k.manifest_path(owner)):
                    store.put('expected',path,r.path_oid(commit,path))
                for page in manifest['pages']:store.put('expected',k.page_path(owner,page['page']),r.path_oid(commit,k.page_path(owner,page['page'])))
                raw_archives={};texts={};anchors=set()
                for kind,ref in manifest['archives'].items():
                    need(ref['commit'] in ancestors,'archive anchor ancestry');anchors.add(ref['commit'])
                    need({key:ref[key] for key in origin['archives'][kind]}==origin['archives'][kind] and ref['origin_sha256']==member['origin_sha256'],'archive descriptor origin binding')
                    need(ref['provenance']==k.archive_provenance(expected_grant['mode']),'archive provenance')
                    need(r.path_oid(ref['commit'],ref['storage_path'])==ref['git_blob'],'archive anchor path')
                    raw_archives[kind]=k._read_archive(r,commit,ref);store.put('expected',ref['storage_path'],ref['git_blob']);counts['archive_payload_bytes']+=len(raw_archives[kind])
                need(len(anchors)==1,'joint archive anchor per owner');anchor=next(iter(anchors))
                if joint_anchor is None:joint_anchor=anchor
                need(joint_anchor==anchor,'joint archive anchor across owners')
                for kind,ref in manifest['originals'].items():
                    need(ref['path']==k.original_path(owner,kind) and ref['commit']==anchor,'projection fixed original path/anchor')
                    raw=r.read_path(ref['commit'],ref['path']);need(k.oid('blob',raw)==ref['git_blob'] and k.sha(raw)==ref['sha256'] and len(raw)==ref['byte_length'],'projection identity')
                    need(r.path_oid(commit,ref['path'])==ref['git_blob'],'projection current path unchanged');store.put('expected',ref['path'],ref['git_blob'])
                    texts[(ref['commit'],ref['path'])]=raw.decode('utf-8');counts['projection_payload_bytes']+=len(raw)
                for rec in rows.values():
                    need(rec['kind'] in ('source','target','coverage','note'),'new mode does not admit unverified cross-owner relationships')
                    if require_empty_obligations:need(rec.get('obligations',[])==[],'baseline pending empty')
                    for ref in k.version_refs(rec):need(ref.get('locator',{}).get('commit') in ancestors,'exact-version locator ancestry')
                    if rec.get('prior'):need(rec['prior']['commit'] in ancestors,'prior ancestry')
                    k.validate_record(snap,rec)
                    if rec['kind'] in ('source','target'):counts['nodes']+=1
                    elif rec['kind']=='coverage':counts['coverage']+=1
                    else:counts['notes']+=1;counts['target_notes' if rec['about']['kind']=='target' else 'owner_notes']+=1
                fields=k._verify_archive_fields(raw_archives,origin);k._verify_origin_records(snap,origin,texts,member['origin_sha256'],require_origin_baseline,fields)
                ip,rp=retained_paths(owner);iraw=r.read_path(commit,ip);inv=k.decode(iraw)
                need(inv.get('format')=='retained-owner-archive/v25' and inv.get('owner')==owner and set(inv)=={'format','owner','entries'} and isinstance(inv['entries'],list) and len(inv['entries'])<=1,'retained inventory contract')
                need(r.path_oid(anchor,ip)==k.oid('blob',iraw),'immutable retained inventory');store.put('expected',ip,k.oid('blob',iraw))
                for desc in inv['entries']:
                    raw=r.read_path(commit,rp);need(retained_inventory(owner,[{'raw':raw,'metadata':{key:value for key,value in desc.items() if key not in ('storage_path','domain','role','disposition','history_coverage','git_blob')}}])==inv,'retained exact inventory semantics')
                    need(r.path_oid(anchor,rp)==k.oid('blob',raw),'retained anchor unchanged');store.put('expected',rp,k.oid('blob',raw));counts['retained_objects']+=1;counts['retained_payload_bytes']+=len(raw)
                version=manifest['initial_anchor'];need(version in ancestors,'initial version anchor ancestry')
                if joint_version is None:joint_version=version
                need(joint_version==version,'joint initial version anchor')
                static_paths=[k.owner_grant_path(owner),k.origin_path(owner),ip]+[k.archive_storage_path(owner,x) for x in k.ARCHIVE_KINDS]+[k.original_path(owner,x) for x in ('source','target')]
                if inv['entries']:static_paths.append(rp)
                for path in static_paths:
                    h=r.path_oid(commit,path);store.put('raw_expected',path,h);store.put('version_expected',path,h)
                original=_regenerate(r,anchor,owner,expected_grant);refs0,archives0=_refs(original,anchor,expected_grant['mode'])
                for path,raw in k.encode_su(owner,[x for x in original['models'] if x['kind'] in ('source','target')],refs0,archives=archives0).items():store.put('version_expected',path,k.oid('blob',raw))
                del original,refs0,archives0
                counts['records']+=len(rows);counts['owners']+=1;counts['origin_payload_bytes']+=len(k.canonical(origin))
                roll.update(k.canonical({'owner':owner,'manifest':r.path_oid(commit,k.manifest_path(owner)),'records':len(rows),'origin':member['origin_sha256']}));roll.update(b'\n')
            del snap,origin,member,rows,manifest,raw_archives,texts,fields,inv,iraw
        path_count=0
        for role,role_commit in (('raw_expected',joint_anchor),('version_expected',joint_version),('expected',commit)):
            with r.object_batch(readonly=True):
                actual=_iter_paths(r,r.root(role_commit));wanted=iter(store.rows(role));sentinel=object();npaths=0
                while True:
                    a=next(actual,sentinel);b=next(wanted,sentinel)
                    if a is sentinel or b is sentinel:need(a is b,'missing/extra namespace path '+role);break
                    need(a==b,'exact namespace path/mode/OID mismatch '+role);npaths+=1
                if role=='expected':path_count=npaths
        with r.object_batch(readonly=True):
            def parents(c):return [x[7:].decode() for x in r.get(c,'commit').split(b'\n\n',1)[0].splitlines() if x.startswith(b'parent ')]
            need(parents(joint_anchor)==[] and parents(joint_version)==[joint_anchor],'genesis raw/version ancestry roles')
            if require_origin_baseline:need(parents(commit)==[joint_version],'baseline direct version anchor parent')
        result=_ColdResult({**counts,'scope_count':len(scope),'sus':len(scope),'paths':path_count,'origin_grant':copy.deepcopy(expected_grant),'origin_sha256':expected_origin_sha256,'origin_blob':expected_grant['indexes']['origins']['git_tree'],'owner_commitment_sha256':roll.hexdigest(),'input_mode':expected_grant['mode'],'genesis_namespace_roles_verified':3,'all_history_transitions_audited':False,'unknown_domains':k.SCHEMA['domains'],'ancestor_commit_headers_read':len(ancestors),'required_origin_baseline':require_origin_baseline,'required_empty_obligations':require_empty_obligations,'payload_memory':'one-owner-plus-bounded-batch; owner IDs and bounded ancestry metadata disclosed'})
        _AUDITS[result]=(r,r.epoch,commit,k.sha(k.canonical(expected_grant)),k.sha(k.canonical(result)))
        return result
    finally:
        if ancestors is not None:ancestors.close()
        store.close()


def admit_durable_closure(r,root,old,grant,audit,session=None):
    """Visit every committed child freshly, in same locked epoch; no visited set."""
    need(r.epoch is not None and not r.staged,'durable closure requires flushed epoch')
    need(isinstance(audit,_ColdResult) and _AUDITS.get(audit)==(r,r.epoch,root,k.sha(k.canonical(grant)),k.sha(k.canonical(audit))),'closure requires completed same-epoch semantic audit')
    if session is None:
        need(old is None and audit['required_origin_baseline'] and audit['required_empty_obligations'] and r.ref() is None,'genesis closure requires audited empty baseline')
        context=types.SimpleNamespace(admission=root,root=root,code=k.code_pin(),schema=k.SCHEMA_PIN,origin_grant=grant,origin_sha256=grant['origin_sha256'],_active={},_seen=set(),transitions=0)
    else:
        k._reconstruction_session_check(r,session,root,k.code_pin(),k.SCHEMA_PIN)
        need(session.origin_grant==grant,'closure session grant');context=session
    with r.object_batch(readonly=True):capacity.check_candidate_capacity(k,r,context,root)
    count=0;total=0;rolling=hashlib.sha256()
    with r.object_batch(readonly=True):
        commits=_ancestors(r,root)
        def visit(h,kind,depth):
            nonlocal count,total
            need(depth<=22 and count<1000000,'durable closure traversal bound')
            # Deliberately bypass payload cache and staged bytes; actual store verification.
            _,raw=r._load(h,kind,'durable_closure');count+=1;total+=len(raw)
            rolling.update(k.canonical([h,kind,len(raw),k.sha(raw)]));rolling.update(b'\n')
            if kind=='tree':
                entries=k.parse_tree(raw)
                for mode,child in entries.values():visit(child,'tree' if mode=='40000' else 'blob',depth+1)
            # _load proof metadata is operation-local and bounded too.
            if len(r.operation_admitted)>=BATCH_OBJECTS:r.release_batch()
        for commit in commits:
            _,raw=r._load(commit,'commit','durable_commit');need(raw.startswith(b'tree '),'commit tree header')
            tree=raw.split(b'\n',1)[0][5:].decode();visit(tree,'tree',0)
        _,cb=r._load(root,'commit','durable_root');tree=cb.split(b'\n',1)[0][5:].decode();commits.close()
    token=_AdmittedRoot();_TOKENS[token]={'binding':(r,r.epoch,r.generation,root,old,k.code_pin(),k.SCHEMA_PIN),'service':k._service_key(r.service_key),'commit_sha256':k.sha(cb),'tree':tree,'grant_sha256':k.sha(k.canonical(grant)),'audit_sha256':k.sha(k.canonical(audit)),'closure_sha256':rolling.hexdigest(),'object_visits':count,'payload_bytes':total}
    return token


# Old v22 files/APIs remain untouched. v25 shared validators call this bounded cold.
k.cold=cold_streaming


def restore_checkpoint_streaming(r,checkpoint,requested_root,code,schema,expected_latest=None,publish=False):
    """Full baseline + bounded-body replay + final cold; no sender lazy receipt."""
    k.check_pins(code,schema)
    need(isinstance(checkpoint,dict) and set(checkpoint)=={'kind','baseline','final','code','schema','scope','origin_sha256','origin_grant'} and checkpoint['kind']=='trusted_host_admitted_chain_not_user_signature','external chain checkpoint shape')
    grant=checkpoint['origin_grant'];k._grant_contract(grant)
    need(checkpoint['code']==code and checkpoint['schema']==schema and checkpoint['origin_sha256']==grant['origin_sha256'] and checkpoint['scope']==k.scope_descriptor(grant),'external chain checkpoint binding')
    need(requested_root==checkpoint['final'] and (expected_latest is None or requested_root==expected_latest),'external exact final root')
    baseline=checkpoint['baseline'];need(k.OID.fullmatch(baseline) and k.OID.fullmatch(requested_root),'checkpoint OIDs')
    with r.integrity_operation():
        current=r.ref() if publish else None
        if publish:need(current in (None,baseline,requested_root),'receiver main parent conflict')
        with r.object_batch(readonly=True):
            need(r.get(baseline,'commit').endswith(('\n\n'+BASELINE_MESSAGE+'\n').encode()),'baseline role')
        cold_streaming(r,baseline,checkpoint['scope'],require_empty_obligations=True,expected_origin_sha256=grant['origin_sha256'],require_origin_baseline=True,expected_grant=grant)
        # Explicitly bounded O(transition OIDs), never all message/request bytes.
        chain=[];head=requested_root
        while head!=baseline:
            need(len(chain)<100000 and head not in chain,'transition ancestry cycle/budget')
            with r.object_batch(readonly=True):
                raw,delta=k.parse_log(r,head);need(delta['code']==code and delta['schema']==schema,'historical transition pins')
                chain.append(head);head=delta['parent']
            del raw,delta
        s=k.LogSession(k._SESSION_TOKEN,baseline,baseline,code,schema);s.repo_path=str(r.path);s.origin_sha256=grant['origin_sha256'];s.origin_blob=grant['indexes']['origins']['git_tree'];s.origin_grant=copy.deepcopy(grant);k._SESSION_BINDINGS[s]=k._session_binding(s)
        for child in reversed(chain):
            with r.object_batch(readonly=True):
                actual,delta=k.parse_log(r,child);plan=k._reconstruct(r,s.root,delta['request'],code,schema,s)
                need(child==plan['candidate'] and actual==k.commit_bytes(plan['tree'],s.root,plan['message']),'replay exact transition')
                capacity.check_plan_capacity(k,r,s,plan)
                r.admit_existing_required()  # Reconstructed staged bytes cannot replace missing receiver objects.
                k.session_advance(s,plan);k.bump('log_transitions_replayed')
            del actual,delta,plan
        need(s.root==requested_root,'replay final root')
        audit=cold_streaming(r,requested_root,checkpoint['scope'],expected_origin_sha256=grant['origin_sha256'],expected_grant=grant)
        with r.object_batch(readonly=True):capacity.check_candidate_capacity(k,r,s,requested_root)
        # Baseline-only empty receiver may use genesis closure. Replayed candidate
        # has registered reconstruction binding, with final pending proved above.
        if publish and current!=requested_root:
            if current is None and requested_root==baseline:
                audit=cold_streaming(r,baseline,checkpoint['scope'],expected_origin_sha256=grant['origin_sha256'],require_origin_baseline=True,require_empty_obligations=True,expected_grant=grant)
                token=admit_durable_closure(r,requested_root,None,grant,audit)
            else:
                token=admit_durable_closure(r,requested_root,current,grant,audit,s)
            r.cas_admitted_root(token,requested_root,current)
        else:
            # Audit still establishes complete real storage durability; no CAS.
            admit_durable_closure(r,requested_root,requested_root,grant,audit,s)
        k._VALIDATION_REUSE.add(s);k._SESSION_PROVENANCE[s]={'mode':'FULL_STREAMING_COLD_REPLAY_FINAL','checkpoint_root':None}
        return s


def full_audit_streaming(r,session):
    k._reconstruction_session_check(r,session,session.root,session.code,session.schema)
    checkpoint=k.make_checkpoint(session.origin_grant,session.admission,session.root)
    k.reset_service_cache(r.path)
    restored=restore_checkpoint_streaming(r,checkpoint,session.root,session.code,session.schema,session.root,False)
    need(restored._active==session._active and restored._seen==session._seen and restored.transitions==session.transitions,'full audit pending exact comparison')
    return {'baseline':restored.admission,'final':restored.root,'transitions':restored.transitions,'pending_active':len(restored._active),'pending_seen':len(restored._seen),'all_history_transitions_audited':True,'fullbook_native_history_complete':False}

k._restore_checkpoint=restore_checkpoint_streaming
k.full_audit=full_audit_streaming
