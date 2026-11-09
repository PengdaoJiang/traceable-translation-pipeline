"""Experimental v30-cold compound native/persistent-pending kernel.
Authority is external corpus admission + deterministic transitions, never reports.
The default Repo root is PHYSICAL. Native view is an explicit scoped projection.
"""
import contextlib,copy,hashlib,importlib.util,re,sys,weakref
from pathlib import Path
HERE=Path(__file__).resolve().parent
def _load_local(name,path):
    # Execute the selected source bytes, never a preloaded same-named module or
    # a stale pyc. These exact files are covered by EXECUTION_FILES below.
    import types
    module=types.ModuleType(name);module.__file__=str(path)
    exec(compile(path.read_bytes(),str(path),'exec'),module.__dict__)
    sys.modules[name]=module;return module

proofs=_load_local('v27_pinned_durable_proofs',HERE/'durable_proofs.py')
maps=_load_local('v27_pinned_merkle_map',HERE/'merkle_map.py')
native=_load_local('v27_frozen_native',HERE/'native/kernel_streaming.py')
sys.modules['kernel_streaming']=native
source_adapter=_load_local('source_adapter',HERE/'native/source_adapter.py')
synthetic_fixtures=_load_local('synthetic_fixtures',HERE/'native/synthetic_fixtures.py')
pack_io=_load_local('pack_io',HERE/'native/pack_io.py')
MerkleMap=maps.MerkleMap
DiskAncestry,DurableClosure,RunBudget=proofs.DiskAncestry,proofs.DurableClosure,proofs.RunBudget
k=native.k;need=k.need
SCHEMA={'format':'native-persistent-compound/v27','native_schema':k.SCHEMA_PIN,'pending':'pending-map-roots/v26','normal_baseline':'empty-after-external-native-cold','namespace':['combined.json','grant.json','native','pending'],'transition':'derived-native-delta-single-physical-parent-CAS','checkpoint':'external-exact-bytes-and-latest-same-instance','hot_events_max':256,'checkpoint_bytes':16384}
# Include all executable derivation, transport, proof and adapter sources.
EXECUTION_FILES=('native_pending.py','merkle_map.py','durable_proofs.py','native/kernel_streaming.py','native/kernel_base.py','native/capacity_gate.py','native/source_adapter.py','native/adapter_receipts.py','native/target_size.py','native/source_decode.py','native/synthetic_fixtures.py','native/synthetic_sources.py','native/pack_io.py')
PIN=hashlib.sha256(b'semantic-platform-compound/v1\0'+b''.join(name.encode()+b'\0'+(HERE/name).read_bytes()+b'\0' for name in EXECUTION_FILES)+b'platform_api.py\0'+(HERE.parent/'platform_api.py').read_bytes()+b'\0').hexdigest()
SCHEMA_PIN=k.sha(k.canonical(SCHEMA));_SESSIONS=weakref.WeakKeyDictionary()
class Repo(native.Repo):
    def __init__(self,path):super().__init__(path);self._native_mode=False
    def _measure(self):
        values=super()._measure()
        if self.epoch is not None and not self.batch_enabled:
            need(values['required_objects']<=8192 and values['required_bytes']<=32*1024**2,'bounded hot construction objects/bytes')
        return values
    @contextlib.contextmanager
    def native_view(self):
        old=self._native_mode;self._native_mode=True
        try:yield
        finally:self._native_mode=old
    def physical_root(self,commit):return k.Repo.root(self,commit)
    def root(self,commit):
        root=self.physical_root(commit)
        if not self._native_mode:return root
        entries=self.tree(root)
        if 'combined.json' not in entries:return root
        _header(self,entries)
        return entries['native'][1]

def _header(r,top,grant=None,native_baseline=None):
    need(set(top)==set(SCHEMA['namespace']),'exact combined root namespace')
    need(all(top[x][0]==('40000' if x in ('native','pending') else '100644') for x in top),'combined root modes')
    descriptor=k.decode(r.get(top['combined.json'][1],'blob'))
    need(set(descriptor)=={'format','schema','code','native_baseline'} and descriptor['format']==SCHEMA['format'] and descriptor['schema']==SCHEMA and descriptor['code']==PIN,'combined format/schema/code')
    need(k.OID.fullmatch(descriptor['native_baseline']) is not None,'native baseline OID')
    if native_baseline is not None:need(descriptor['native_baseline']==native_baseline,'exact native baseline')
    actual=k.decode(r.get(top['grant.json'][1],'blob'));k._grant_contract(actual)
    if grant is not None:need(actual==grant,'external corpus grant')
    return descriptor,actual

def _state_contract(state):
    need(type(state) is dict and set(state)=={'format','seen','active','targets','seen_count','active_count','target_count','transitions'},'pending descriptor fields')
    need(state['format']=='pending-map-roots/v26','pending descriptor version')
    for x in ('seen','active','targets'):need(type(state[x]) is str and k.OID.fullmatch(state[x]),'pending OID')
    for x in ('seen_count','active_count','target_count','transitions'):need(type(state[x]) is int and 0<=state[x]<2**63,'pending counter')
    need(state['target_count']<=state['active_count']<=state['seen_count'],'count relations')

def event_key(e):return [e['event'],e['target']]
def event_contract(e):
    need(type(e) is dict and set(e)=={'event','target','owner','target_version','seed','old_version','new_version','responsibility'},'event exact fields')
    k._origin_digest(e['event'],'event');own,kind,_,_=k.locate(e['target']);seedown,seedkind,_,_=k.locate(e['seed'])
    need(kind=='target' and seedkind in ('source','target') and own==seedown==e['owner'],'event identities')
    need(all(type(e[x]) is int and 0<=e[x]<2**63 for x in ('target_version','old_version','new_version')) and e['new_version']==e['old_version']+1,'event versions')
    need(e['responsibility']=={'for_version':e['target_version'],'status':'UNKNOWN','claims':[]} and type(e['responsibility']['for_version']) is int,'exact UNKNOWN responsibility')
    raw=k.canonical(e);need(len(raw)<=2048,'event bound');return raw

def read_state(r,root,grant=None,native_baseline=None):
    top=r.tree(r.physical_root(root));desc,grant=_header(r,top,grant,native_baseline)
    tree=r.tree(top['pending'][1]);need(set(tree)=={'meta','seen','active','targets'} and tree['meta'][0]=='100644','pending exact namespace')
    state=k.decode(r.get(tree['meta'][1],'blob'));_state_contract(state);mm=MerkleMap(k,r)
    for x in ('seen','active','targets'):
        need(tree[x]==('40000',state[x]),'pending real edge');need(mm.count(state[x])==state['target_count' if x=='targets' else x+'_count'],'root count')
    return state,top['native'][1],desc,grant

def _tree(r,native_tree,state,grant,native_baseline):
    _state_contract(state)
    pending=r.stage('tree',k.tree_bytes({'meta':('100644',r.stage('blob',k.canonical(state))),**{x:('40000',state[x]) for x in ('seen','active','targets')}}))
    desc={'format':SCHEMA['format'],'schema':SCHEMA,'code':PIN,'native_baseline':native_baseline}
    return r.stage('tree',k.tree_bytes({'combined.json':('100644',r.stage('blob',k.canonical(desc))),'grant.json':('100644',r.stage('blob',k.canonical(grant))),'native':('40000',native_tree),'pending':('40000',pending)}))

class Session:
    def __init__(self):raise k.Rejected('factory only')
    @property
    def origin_grant(self):return self.grant
    @property
    def origin_sha256(self):return self.grant['origin_sha256']
    @property
    def origin_blob(self):return self.grant['indexes']['origins']['git_tree']
    @property
    def repo_path(self):return str(self.repo.path)
    @property
    def transitions(self):return self.state['transitions']
    def records(self,target):
        result=_query(self.repo,self,target,None,256)
        need(result['next'] is None,'use paginated pending query for large target')
        return result['events']

def _binding(s):return (s.repo,s.native_baseline,s.baseline,s.root,PIN,SCHEMA_PIN,k.sha(k.canonical(s.grant)),k.sha(k.canonical(s.state)))
def check(s,root=None):
    need(isinstance(s,Session) and _SESSIONS.get(s)==_binding(s),'registered compact native session')
    need(root is None or s.root==root,'session exact root')
def _session(r,native_baseline,baseline,root,grant,state):
    s=object.__new__(Session);s.repo=r;s.native_baseline=native_baseline;s.baseline=baseline;s.root=root;s.grant=copy.deepcopy(grant);s.state=copy.deepcopy(state);_SESSIONS[s]=_binding(s);return s
_old_session_check=k.session_check
# Dispatch solely registered v27 sessions. This is NOT a reuse credential.
def _adapter_check(s,parent,code,schema):
    if isinstance(s,Session):
        check(s,parent);k.check_pins(code,schema);k._grant_contract(s.grant)
    else:_old_session_check(s,parent,code,schema)
k.session_check=_adapter_check

def fork(s):
    check(s)
    return _session(s.repo,s.native_baseline,s.baseline,s.root,s.grant,s.state)

def _empty(r):
    empty=MerkleMap(k,r).empty()[0]
    return {'format':'pending-map-roots/v26','seen':empty,'active':empty,'targets':empty,'seen_count':0,'active_count':0,'target_count':0,'transitions':0}
def _migration(r,native_baseline,grant):
    state=_empty(r);tree=_tree(r,r.physical_root(native_baseline),state,grant,native_baseline)
    message=k.canonical({'format':'native-empty-pending-migration/v27','native_baseline':native_baseline,'code':PIN,'schema':SCHEMA_PIN,'grant_sha256':k.sha(k.canonical(grant))})
    root=r.stage('commit',k.commit_bytes(tree,native_baseline,message.decode()))
    _checkpoint_bytes(r,native_baseline,root,root,grant,state)
    return root,state

def _cold(r,root,grant,baseline=False):
    with r.native_view():return native.cold_streaming(r,root,k.scope_descriptor(grant),expected_origin_sha256=grant['origin_sha256'],expected_grant=grant,require_empty_obligations=baseline,require_origin_baseline=baseline)

def _closure(r,root):
    need(not r._native_mode,'physical closure only')
    with r.object_batch(readonly=True),DurableClosure(k,r,directory=r.path.parent) as proof:return proof.verify(root)
def _published_cas(r,new,old):
    # Only called after full physical closure OR compact admitted-parent induction.
    need(not r._native_mode and r.epoch is not None and r.ref()==old,'physical CAS context/current')
    r._load(new,'commit','combined_cas_header')
    k._durable_ref_cas(r,new,old)
def migrate(r,native_session):
    _old_session_check(native_session,native_session.root,k.code_pin(),k.SCHEMA_PIN)
    need(native_session.repo_path==str(r.path) and native_session.root==native_session.admission and not native_session._seen and not native_session._active and native_session.transitions==0,'only admitted empty native baseline migration')
    grant=native_session.origin_grant;baseline=native_session.root
    with r.integrity_operation():
        need(r.ref()==baseline,'migration main baseline');_cold(r,baseline,grant,True)
        with r.object_batch():root,state=_migration(r,baseline,grant)
        _closure(r,root);_published_cas(r,root,baseline)
        return _session(r,baseline,root,root,grant,state)

def _mutate(r,state,opened,resolved):
    state=copy.deepcopy(state);mm=MerkleMap(k,r);need(len(opened)+len(resolved)<=SCHEMA['hot_events_max'],'bounded derived events')
    keys=set()
    for opening,events in ((True,opened),(False,resolved)):
        for event in events:
            raw=event_contract(event);key=event_key(event);serialized=k.canonical(key);need(serialized not in keys,'duplicate transition key');keys.add(serialized);oid=k.oid('blob',raw)
            if opening:
                need(mm.lookup(state['seen'],key) is None,'duplicate opened including resolved history')
                r.stage('blob',raw);state['seen'],state['seen_count']=mm.insert(state['seen'],key,'blob',oid);state['active'],state['active_count']=mm.insert(state['active'],key,'blob',oid)
                target=mm.lookup(state['targets'],[event['target']]);sub=target[1] if target else mm.empty()[0]
                sub,_=mm.insert(sub,key,'blob',oid);state['targets'],state['target_count']=mm.insert(state['targets'],[event['target']],'tree',sub)
            else:
                need(mm.lookup(state['active'],key)==('blob',oid) and mm.lookup(state['seen'],key)==('blob',oid),'resolve exact active immutable obligation')
                state['active'],state['active_count']=mm.delete(state['active'],key)
                target=mm.lookup(state['targets'],[event['target']]);need(target is not None and target[0]=='tree','resolve target map')
                need(mm.lookup(target[1],key)==('blob',oid),'resolve exact target event');sub,n=mm.delete(target[1],key)
                if n:state['targets'],state['target_count']=mm.insert(state['targets'],[event['target']],'tree',sub)
                else:state['targets'],state['target_count']=mm.delete(state['targets'],[event['target']])
    state['transitions']+=1;_state_contract(state);return state

def _prune_intermediates(r,root):
    """Keep only staged objects reached by the final physical candidate.
    Existing durable reads remain required. No history traversal: stop at every
    non-staged edge. Hot construction runs without automatic batch rollover.
    """
    reachable=set();todo=[root]
    while todo:
        oid=todo.pop()
        if oid in reachable or oid not in r.staged:continue
        reachable.add(oid);kind,raw=r.staged[oid]
        if kind=='tree':todo.extend(child for mode,child in k.parse_tree(raw).values())
        elif kind=='commit':
            for line in raw.split(b'\n\n',1)[0].splitlines():
                if line.startswith(b'tree '):todo.append(line[5:].decode())
                elif line.startswith(b'parent '):todo.append(line[7:].decode())
        else:need(kind=='blob','unexpected staged kind')
    for oid in set(r.staged)-reachable:
        kind,raw=r.staged.pop(oid)
        # A real read may subsequently be restaged with identical bytes. Its
        # existing durable admission remains a requirement even when not a new
        # final edge; only staged-only intermediates lose their requirement.
        if r.operation_admitted.get(oid)!=r._admission_signature(kind,raw):
            r.required.pop(oid,None);r.memo.pop(oid,None);r.trees.pop(oid,None)

def _plan(r,s,request):
    check(s);need(s.repo is r and not r.batch_enabled,'session repo/unbatched bounded construction');raw=k.canonical(request);need(len(raw)<=65536,'bounded request');request=k.decode(raw)
    before,native_tree,_,_=read_state(r,s.root,s.grant,s.native_baseline);need(before==s.state,'parent root descriptor')
    if request.get('op')=='resolve_pending':
        need(set(request)=={'op','items','reason'} and request['reason']=='local_technical_resolution','resolution request')
        resolved=request['items'];need(type(resolved) is list and 0<len(resolved)<=16,'resolution bounds')
        keys=[tuple(event_key(e)) for e in resolved];need(keys==sorted(set(keys)),'resolution order/duplicates');opened=[]
    else:
        need(request.get('op') in ('revise_text','revise_note_text'),'native requests only')
        old_lazy=getattr(r,'_lazy_validate',False);r._lazy_validate=True;r._lazy_owner_reports={}
        try:
            with r.native_view():
                fn=k._reconstruct_note_revision if request['op']=='revise_note_text' else k._reconstruct_revision
                plan=fn(r,s.root,request,k.code_pin(),k.SCHEMA_PIN,s)
        finally:r._lazy_validate=old_lazy
        native_tree=plan['tree'];opened=plan['delta']['opened'];resolved=plan['delta']['resolved']
        # Native-only candidate is a reconstruction intermediate, never ref-published
        # nor required on receivers: no real edge references that commit.
        intermediate=plan['candidate'];r.staged.pop(intermediate,None);r.required.pop(intermediate,None);r.memo.pop(intermediate,None)
    state=_mutate(r,s.state,opened,resolved);tree=_tree(r,native_tree,state,s.grant,s.native_baseline)
    delta={'format':'native-pending-transition/v27','code':PIN,'schema':SCHEMA_PIN,'parent':s.root,'request':request,'opened':opened,'resolved':resolved,'before':s.state,'after':state,'native_after':native_tree}
    message=k.canonical(delta);need(len(message)<=65536,'combined log bound');root=r.stage('commit',k.commit_bytes(tree,s.root,message.decode()))
    _prune_intermediates(r,root)
    need(len(r.required)<=8192 and sum(len(b) for _,b in r.required.values())<=32*1024**2,'hot object budget')
    # Pre-publication capacity uses the exact export envelope, including actual
    # repo identity, grant, candidate IDs and counters. No authority is minted.
    _checkpoint_bytes(r,s.native_baseline,s.baseline,root,s.grant,state)
    return {'root':root,'tree':tree,'parent':s.root,'state':state,'delta':delta,'request_sha256':k.sha(raw)}
def _advance(s,plan):s.root=plan['root'];s.state=copy.deepcopy(plan['state']);_SESSIONS[s]=_binding(s)
def _intent(r,plan):return r.path/'combined-intents'/(k.sha(k.canonical({'parent':plan['parent'],'request':plan['request_sha256']}))+'.json')
def apply(r,s,request,failpoint=None):
    check(s);need(s.repo is r,'session repository')
    with r.integrity_operation():
        check(s);need(r.ref()==s.root,'apply exact main');plan=_plan(r,s,request)
        need(len(r.required)<=8192 and sum(len(b) for _,b in r.required.values())<=32*1024**2,'hot object budget')
        r.flush();path=_intent(r,plan);raw=k.canonical(plan)
        if path.exists():need(path.read_bytes()==raw,'intent exact retry')
        else:k.durable_file(path,raw,True)
        if failpoint=='before_cas':return {'interrupted':failpoint,'root':plan['root']}
        r.cas(plan['root'],s.root)
        if failpoint=='after_cas':return {'interrupted':failpoint,'root':plan['root']}
        _advance(s,plan);return {'root':s.root,'state':copy.deepcopy(s.state),'opened':plan['delta']['opened'],'resolved':plan['delta']['resolved']}
def recover(r,s,request):
    check(s);need(s.repo is r,'session repository')
    with r.integrity_operation():
        plan=_plan(r,s,request);path=_intent(r,plan);need(path.exists() and path.read_bytes()==k.canonical(plan),'exact authorized intent')
        current=r.ref();need(current in (s.root,plan['root']),'recovery third state');r.flush()
        if current==s.root:r.cas(plan['root'],s.root)
        else:k._durable_ref_fence(r,plan['root'])
        _advance(s,plan);return {'root':s.root,'already_published':current==plan['root']}

def _query(r,s,target,after,limit):
    check(s);need(s.repo is r and k.locate(target)[1]=='target' and type(limit) is int and 1<=limit<=256,'target query')
    if after is not None:need(type(after) is dict and set(after)=={'format','root','target','last_hash'} and after['format']=='native-pending-cursor/v27' and after['root']==s.root and after['target']==target,'cursor snapshot binding')
    mm=MerkleMap(k,r);value=mm.lookup(s.state['targets'],[target]);events=[];last=None;more=False
    if value:
        need(value[0]=='tree','target subtree')
        for key,kind,oid in mm.iter_from(value[1],after_hash=after['last_hash'] if after else None,limit=limit+1):
            if len(events)==limit:more=True;break
            need(kind=='blob' and mm.lookup(s.state['active'],key)==('blob',oid),'query active consistency')
            event=k.decode(r.get(oid,'blob'));event_contract(event);need(event_key(event)==key and event['target']==target,'query identity');events.append(event);last=mm.key(key)[0]
    return {'events':events,'next':{'format':'native-pending-cursor/v27','root':s.root,'target':target,'last_hash':last} if more else None,'root':s.root,'total_seen':s.state['seen_count']}
def query(r,s,target,after=None,limit=64):
    with r.integrity_operation():return _query(r,s,target,after,limit)
def query_native(r,s,request,kind='target'):
    check(s);need(s.repo is r and kind in ('target','note','archive','origin'),'query adapter')
    fn={'target':k.query,'note':k.query_note,'archive':k.query_archive,'origin':k.query_origin}[kind]
    previous=getattr(r,'_lazy_validate',False);r._lazy_validate=True;r._lazy_owner_reports={}
    try:
        with r.native_view():result=fn(r,request,s.root,k.code_pin(),k.SCHEMA_PIN,session=s)
        result['authentication'].update(combined_code=PIN,combined_schema=SCHEMA_PIN,pending_state='PERSISTENT_EXACT_ROOT_BOUND',pending_seen=s.state['seen_count'],pending_active=s.state['active_count'])
        return result
    finally:r._lazy_validate=previous

def _checkpoint_bytes(r,native_baseline,baseline,root,grant,state):
    """Pure candidate/export envelope serializer; never creates a session.
    Called before mutation flush/intent/CAS, and for empty migration as well.
    """
    _state_contract(state);k._grant_contract(grant)
    need(all(type(oid) is str and k.OID.fullmatch(oid) for oid in (native_baseline,baseline,root)),'checkpoint root IDs')
    c={'format':'external-native-pending-checkpoint/v27','repository':k._repository_identity(r),'native_baseline':native_baseline,'baseline':baseline,'root':root,'code':PIN,'schema':SCHEMA_PIN,'grant':grant,'state':state,'trust':'PRIOR_FULL_NATIVE_ADMISSION_AND_DERIVED_TRANSITIONS'}
    raw=k.canonical(c);need(len(raw)<=SCHEMA['checkpoint_bytes'],'compact checkpoint bound');return raw

def checkpoint(r,s):
    check(s);need(s.repo is r,'checkpoint repository identity');state,_,_,_=read_state(r,s.root,s.grant,s.native_baseline);need(state==s.state,'checkpoint descriptor')
    return _checkpoint_bytes(r,s.native_baseline,s.baseline,s.root,s.grant,state)

def export(r,s):
    with r.integrity_operation():return checkpoint(r,s)
def _checkpoint_envelope(r,raw,authenticated_sha256):
    need(type(raw) is bytes and len(raw)<=SCHEMA['checkpoint_bytes'] and k.sha(raw)==authenticated_sha256,'external checkpoint exact hash')
    c=k.decode(raw);need(set(c)=={'format','repository','native_baseline','baseline','root','code','schema','grant','state','trust'} and c['format']=='external-native-pending-checkpoint/v27','checkpoint envelope')
    need(c['repository']==k._repository_identity(r),'checkpoint repository instance');need(c['code']==PIN and c['schema']==SCHEMA_PIN,'checkpoint pins')
    need(c['trust']=='PRIOR_FULL_NATIVE_ADMISSION_AND_DERIVED_TRANSITIONS','checkpoint trust contract');k._grant_contract(c['grant'])
    need(k.OID.fullmatch(c['root']) and k.OID.fullmatch(c['baseline']) and k.OID.fullmatch(c['native_baseline']),'checkpoint root IDs')
    _state_contract(c['state']);return c

def _restore_envelope(r,c):
    state,_,_,_=read_state(r,c['root'],c['grant'],c['native_baseline']);need(state==c['state'],'checkpoint state')
    return _session(r,c['native_baseline'],c['baseline'],c['root'],c['grant'],state)

def lazy_restore(r,raw,authenticated_sha256,expected_latest):
    c=_checkpoint_envelope(r,raw,authenticated_sha256)
    need(c['root']==expected_latest,'checkpoint latest')
    with r.integrity_operation():
        need(r.ref()==expected_latest,'latest ref mismatch');return _restore_envelope(r,c)

def prepare_journal(r,s,request):
    """Return exact parent receipt and bounded journal. Host must durably
    authenticate both BEFORE apply; repository intent alone is not host latest.
    No main mutation. Returned bytes are not themselves external authentication.
    """
    check(s);need(s.repo is r,'journal repository')
    with r.integrity_operation():
        need(r.ref()==s.root,'journal parent main');receipt=checkpoint(r,s);plan=_plan(r,s,request)
        journal={'format':'external-native-pending-journal/v27','parent_checkpoint_sha256':k.sha(receipt),'parent':s.root,'candidate':plan['root'],'request':request,'code':PIN,'schema':SCHEMA_PIN}
        raw=k.canonical(journal);need(len(raw)<=131072,'journal bound');return receipt,raw

def recover_journal(r,parent_raw,parent_hash,journal_raw,journal_hash,expected_latest):
    """Same-repo bounded crash reconciliation from two EXTERNALLY authenticated
    byte strings plus independent latest. Cannot detect joint host/Git rollback.
    """
    c=_checkpoint_envelope(r,parent_raw,parent_hash)
    need(type(journal_raw) is bytes and len(journal_raw)<=131072 and k.sha(journal_raw)==journal_hash,'external journal exact hash')
    j=k.decode(journal_raw);need(set(j)=={'format','parent_checkpoint_sha256','parent','candidate','request','code','schema'} and j['format']=='external-native-pending-journal/v27','journal envelope')
    need(j['code']==PIN and j['schema']==SCHEMA_PIN and j['parent_checkpoint_sha256']==parent_hash and j['parent']==c['root'] and k.OID.fullmatch(j['candidate']),'journal parent/pins')
    need(expected_latest in (j['parent'],j['candidate']),'journal external latest')
    with r.integrity_operation():
        current=r.ref();need(current==expected_latest or (expected_latest==j['parent'] and current==j['candidate']),'journal exact parent/candidate reconciliation');s=_restore_envelope(r,c)
        plan=_plan(r,s,j['request']);need(plan['root']==j['candidate'],'journal exact deterministic candidate');r.flush()
        if current==j['parent']:r.cas(plan['root'],current)
        else:k._durable_ref_fence(r,plan['root'])
        _advance(s,plan);return s

def audit_pending(r,s):
    state,_,_,_=read_state(r,s.root,s.grant,s.native_baseline);need(state==s.state,'audit descriptor');mm=MerkleMap(k,r);counts={'seen':0,'active':0,'targets':0,'target_events':0}
    with r.object_batch(readonly=True):
        for key,kind,oid in mm.iter_items(state['seen']):
            need(kind=='blob','seen type');event=k.decode(r.get(oid,'blob'));event_contract(event);need(event_key(event)==key,'seen identity');counts['seen']+=1
        for key,kind,oid in mm.iter_items(state['active']):
            need(kind=='blob' and mm.lookup(state['seen'],key)==('blob',oid),'active seen bijection');event=k.decode(r.get(oid,'blob'));event_contract(event);need(event_key(event)==key,'active identity')
            value=mm.lookup(state['targets'],[event['target']]);need(value and value[0]=='tree' and mm.lookup(value[1],key)==('blob',oid),'active target bijection');counts['active']+=1
        for key,kind,oid in mm.iter_items(state['targets']):
            need(len(key)==1 and kind=='tree','target index');n=0
            for ekey,ekind,eoid in mm.iter_items(oid):
                need(ekind=='blob' and mm.lookup(state['active'],ekey)==('blob',eoid),'target active inverse');event=k.decode(r.get(eoid,'blob'));event_contract(event);need(event_key(event)==ekey and event['target']==key[0],'target event');n+=1
            need(n>0,'empty target entry');counts['targets']+=1;counts['target_events']+=n
    need(counts['seen']==state['seen_count'] and counts['active']==counts['target_events']==state['active_count'] and counts['targets']==state['target_count'],'full pending counts');return counts

def _restore_context(r):
    # Operation-local guard, never serialized or accepted from a caller/report.
    return (r,r.epoch,k._repository_identity(r),k._service_key(r.service_key),
            PIN,SCHEMA_PIN,k.sha(k.canonical(SCHEMA)),k.code_pin(),k.SCHEMA_PIN)

def _check_restore_context(r,context):
    current=_restore_context(r)
    need(current[0] is context[0] and current[1] is context[1] and current[1] is not None
         and current[2]==context[2] and current[3] is context[3] and current[4:]==context[4:],
         'restore repository/epoch/service/pins changed')

def _empty_native_audit(r,s,final,grant,audit,context):
    """Prove strict baseline native cold implies the EMPTY wrapper's semantics.
    No saved PASS, sender receipt, cross-repo result or cross-epoch reuse enters.
    This does not authorize publication: pending audit and closure still follow.
    """
    _check_restore_context(r,context)
    need(isinstance(audit,native._ColdResult) and native._AUDITS.get(audit)==
         (r,r.epoch,s.native_baseline,k.sha(k.canonical(grant)),k.sha(k.canonical(audit))),
         'empty audit requires completed same-epoch native baseline cold')
    need(audit['required_origin_baseline'] is True and audit['required_empty_obligations'] is True,
         'empty audit requires strict origin baseline semantics')
    check(s,final);need(s.repo is r and s.root==s.baseline and s.transitions==0,'empty migration exact final')
    with r.object_batch(readonly=True):
        state,native_tree,_,_=read_state(r,final,grant,s.native_baseline)
        need(state==s.state==_empty(r),'canonical EMPTY pending state')
        need(native_tree==r.physical_root(s.native_baseline),'identical native baseline tree')
        expected,_=_migration(r,s.native_baseline,grant)
        need(final==expected,'exact EMPTY migration envelope/parent')
        r.admit_existing_required()  # Reconstruction never repairs missing bytes.
    _check_restore_context(r,context)
    return audit

def _narrow_native_audit(r, n0, final, grant, audit, context):
    """Internal post-exact-replay optimization, not independent admission.
    None means structurally outside the bounded subset; the caller must cold.
    Validation/identity exceptions propagate and NEVER become fallback success.
    The returned plain report is not registered native admission authority.
    """
    _check_restore_context(r, context)
    k.need(isinstance(audit, native._ColdResult) and native._AUDITS.get(audit) ==
           (r, r.epoch, n0, k.sha(k.canonical(grant)), k.sha(k.canonical(audit))),
           'registered same-epoch baseline audit required')
    k.need(audit['required_origin_baseline'] is True and
           audit['required_empty_obligations'] is True, 'strict baseline required')
    changed = []; owners = set(); visits = 0
    def walk(a, b, prefix='', depth=0):
        nonlocal visits
        if a == b: return True
        visits += 1
        if visits > 256 or depth > 20: return False
        before, after = r.tree(a), r.tree(b)
        if before.keys() != after.keys(): return False
        for name in sorted(before):
            old, new = before[name], after[name]
            if old == new: continue
            path = prefix + name
            if old[0] != new[0]: return False
            if old[0] == '40000':
                if not walk(old[1], new[1], path + '/', depth + 1): return False
                continue
            m = re.fullmatch(r'su/((?:[0-9]{2}/)*u[0-9]{2})/p[0-9]{4}\.json', path)
            if old[0] != '100644' or m is None: return False
            owner = f"SU{int(m[1].replace('/', '').replace('u', '')):02d}"
            if path != k.page_path(owner, int(path.rsplit('/p', 1)[1][:-5])): return False
            owners.add(owner); changed.append(path)
            if len(owners) > 1 or len(changed) > 128: return False
        return True
    with r.object_batch(readonly=True):
        _, native_tree, _, _ = read_state(r, final, grant, n0)
        eligible = walk(r.physical_root(n0), native_tree)
    if not eligible or len(owners) != 1:
        _check_restore_context(r, context)
        return None
    owner = next(iter(owners))
    # Existing bounded, disk-backed ancestry. No new all-history Python set.
    with r.object_batch(readonly=True), native._ancestors(r, final) as ancestors:
        k.need(n0 in ancestors, 'strict baseline is final ancestor')
        with r.native_view():
            snap = k.Snapshot(r, final, grant); snap._admitted_ancestors = ancestors
            rows = snap.su(owner)
            for rec in rows.values():
                k.need(rec['kind'] in ('source', 'target', 'coverage', 'note'), 'narrow supported native record kind')
                for ref in k.version_refs(rec):
                    k.need(ref.get('locator', {}).get('commit') in ancestors, 'locator ancestry')
                if rec.get('prior'): k.need(rec['prior']['commit'] in ancestors, 'prior ancestry')
            previous = getattr(r, '_lazy_owner_reports', {})
            r._lazy_owner_reports = {}
            try:
                k._validate_lazy_owner(snap, owner)
            finally:
                r._lazy_owner_reports = previous
        ancestor_count = len(ancestors); record_count = len(rows)
    _check_restore_context(r, context)
    derived = copy.deepcopy(dict(audit))
    derived.update(required_origin_baseline=False, required_empty_obligations=False,
                   ancestor_commit_headers_read=ancestor_count)
    basis = {'mode': 'STRICT_BASELINE_STATIC_PLUS_COMPLETE_FINAL_CHANGED_OWNER',
             'baseline_audited_commit': n0, 'equivalent_projection_commit': final,
             'final_native_cold_performed': False, 'native_cold_calls': 1,
             'changed_owner': owner, 'changed_paths': changed, 'tree_pairs': visits,
             'final_owner_records_rechecked': record_count,
             'final_ancestor_headers_read': ancestor_count,
             'manifest_and_current_path_mode_set': 'EXACT_BASELINE_IDENTICAL',
             'changed_page_bytes': 'RECHECKED_IN_COMPLETE_FINAL_OWNER',
             'static_archive_census_and_historical_namespaces': 'INHERITED_STRICT_SAME_EPOCH_BASELINE',
             'genesis_namespace_roles': 'INHERITED_BASELINE_NOT_RESCANNED',
             'aggregate_counts_and_owner_commitment': 'INHERITED_IDENTICAL_MANIFESTS_AND_STATIC_BYTES'}
    return derived, basis

def restore(r,native_baseline,baseline,final,grant,publish=False):
    k._grant_contract(grant)
    with r.integrity_operation():
        current=r.ref();need(not publish or current in (None,native_baseline,baseline,final),'receiver main conflict')
        context=_restore_context(r);baseline_audit=_cold(r,native_baseline,grant,True)
        with r.object_batch(readonly=True):
            expected,state=_migration(r,native_baseline,grant);need(expected==baseline,'exact empty migration');r.admit_existing_required()
        s=_session(r,native_baseline,baseline,baseline,grant,state)
        with r.object_batch(readonly=True):chain=DiskAncestry(k,r,final,directory=r.path.parent,stop=baseline,budget=RunBudget())
        try:
            for child in chain.oldest():
                if child==baseline:continue
                actual=r.get(child,'commit');message=k.decode(actual.split(b'\n\n',1)[1][:-1])
                need(message.get('format')=='native-pending-transition/v27' and message.get('parent')==s.root and message.get('code')==PIN and message.get('schema')==SCHEMA_PIN,'combined replay pins/parent')
                plan=_plan(r,s,message['request']);need(plan['root']==child and plan['delta']==message,'exact deterministic combined replay')
                with r.object_batch(readonly=True):r.admit_existing_required()
                _advance(s,plan)
        finally:chain.close()
        need(s.root==final,'exact final')
        if final==baseline:
            native_audit=_empty_native_audit(r,s,final,grant,baseline_audit,context)
            native_basis={'mode':'SAME_EPOCH_STRICT_BASELINE_PLUS_EXACT_EMPTY_MIGRATION',
                          'audited_commit':native_baseline,'equivalent_projection_commit':final,
                          'final_native_cold_performed':False,'native_cold_calls':1}
        else:
            narrow=_narrow_native_audit(r,native_baseline,final,grant,baseline_audit,context)
            if narrow is None:
                native_audit=_cold(r,final,grant)
                native_basis={'mode':'FINAL_COMPOUND_NATIVE_COLD','audited_commit':final,
                              'final_native_cold_performed':True,'native_cold_calls':2}
            else:
                native_audit,native_basis=narrow
        pending=audit_pending(r,s);closure=_closure(r,final)
        _check_restore_context(r,context)
        if publish and current!=final:_published_cas(r,final,current)
        return s,{'root':final,'native':dict(native_audit),'native_audit_basis':native_basis,'pending':pending,'closure':closure,'transitions':s.transitions,'empty_baseline':True}


def build_initial_pending_session(r,captures,*,expected_inventory,mode):
    """Bounded initial build + EMPTY migration, retaining both closures/CAS.
    Owner scope uses the existing strict 1..2079 external inventory contract.
    This is source capability, not host approval to run any particular scope.
    Reuse strict N0 audit only inside its original lock, with no caller audit,
    callback or previously returned session. result['commit'] remains N0;
    result['highwater'] is a detached snapshot at full N0+M completion.
    """
    need(mode in ('real_r0_body','synthetic_scale_only'),'initial source mode')
    with r.integrity_operation():
        context=_restore_context(r)  # Before generation and the first cold audit.
        result=native._prepare_initial_streaming_in_epoch(
            r,captures,expected_inventory=expected_inventory,mode=mode)
        baseline=result['commit'];grant=result['grant'];audit=result['admission']
        _check_restore_context(r,context)
        token=native.admit_durable_closure(r,baseline,None,grant,audit)
        _check_restore_context(r,context)
        r.cas_admitted_root(token,baseline,None)
        need(r.ref()==baseline,'initial exact published baseline')
        with r.object_batch():root,state=_migration(r,baseline,grant)
        session=_session(r,baseline,root,root,grant,state)
        _empty_native_audit(r,session,root,grant,audit,context)
        audit_pending(r,session)
        _closure(r,root);_check_restore_context(r,context)
        _published_cas(r,root,baseline)
        result['highwater']=dict(r.highwater)
        result['highwater_scope']='N0_AND_EMPTY_PENDING_COMPLETE'
        return result,session
