#!/usr/bin/env python3
"""Authenticated host restart checkpoints with lazy per-owner validation.

The host authenticates the old R2 database. This kernel verifies the granted raw
bytes, their bounded fixed-shape projection, full membership and note census.
No legacy imports, native writes, metadata-derived approval or daily raw scan.
"""
import contextlib, copy, hashlib, json, os, re, sqlite3, subprocess, threading, zlib, tempfile, time, weakref
from collections import OrderedDict
from pathlib import Path

SCHEMA={'format':'bounded-su-git-unified-v1','su_digits_max':32,'su_identity':'canonical-decimal-min-two-digits','su_directory':'base100-prefix-uXX-leaf','original_directory':'base100-prefix-uXX-leaf/kind.txt','scope':'immutable-complete-SU-list-count-external-admission','tree_bytes':16384,'page_bytes':16384,'record_bytes':8192,'page_records':32,'su_pages':64,'slot_max':2047,'manifest_bytes':16384,'span':'Unicode-codepoint-half-open-exact-version','identity':'SU:typed-kind:permanent-slot','originals':'typed-fixed-commit-path-blob-sha256-byte-length','domains':['actual_use','hold','approval','migration','source_alignment'],'split_merge':'retire-old-ID-create-new-ID-explicit-lineage-not-implemented-by-v1-apply','authority':'external-parent-request-code-schema-reconstruction','cache':'disposable-not-authoritative'}
SCHEMA['pending']={'format':'pending-commit-log-v1','log_bytes':65536,'authority':'external-admission-and-exact-request-transition-replay','index':'untrusted-SQLite-locator','session':'authenticated-memory-only','resolution':'exact-event-target-version-UNKNOWN-not-attestation'}
SCHEMA['genesis']='raw-originals-then-version-anchor-then-complete-baseline'
SCHEMA['version_locator']='mandatory-typed-exact-version-fixed-commit-page-blob-recordhash'
SCHEMA['checkpoint']='external-host-admitted-final-chain-not-user-signature'
LAYOUT='compact'
SCHEMA.update(format='bounded-su-git-pages-v9-'+LAYOUT,slot_max=9999,su_pages=128,identity='SU:typed-kind:permanent-logical-ID-not-page-position')
SCHEMA['page_layout']=LAYOUT
SCHEMA['initial_compact_fill_bytes']=12288
SCHEMA['genesis_page_partition']='node-relation-note-independent-routes-node-pages-reused'
SCHEMA['format']='bounded-su-git-streaming-v25'
SCHEMA['revision_validation']={'policy':'authenticated-unchanged-coverage-reuse-v1','authority':'complete-cold-and-deterministic-replay-before-reuse','binding':'factory-session-repository-admission-parent-code-schema-origin-grant-and-blob','scope':'externally-granted-single-native-owner-coverage-only-no-dependency-reverse-or-cross-SU','allowed':'pure-source-or-target-text-and-derived-UNKNOWN-facts-only','fallback':'full-coverage-validation-and-revoke-reuse-on-relation-guard-failure','replay':'full-validation-no-reuse-credential-until-complete'}
SCHEMA['origin']='mode-separated-immutable-per-owner-origin-SHA256-under-compact-host-index-root-not-self-authenticated-native-DB'
SCHEMA['native_scope']='COMPLETE_R0_BODY_OWNER_RAW_METADATA_ARCHIVAL_ONLY'
SCHEMA['native_limits']={'owners':2079,'targets':256,'sources':256,'notes':256,'source_rows':4096,'coverage_sources':256,'origin_bytes':262144}
SCHEMA['coverage_semantics']='explicit-native-structural-links-not-alignment-validation-or-actual-use'
SCHEMA['originals']='legacy-internal-key-only-derived-critical-en-index-projections-LF-separated-not-raw-originals'
SCHEMA['archives']='two-current-exact-raw-SU-CAS-blobs-plus-separate-selected-prior-retained-index-no-approval-or-complete-history'
SCHEMA['raw_projection']='fixed-compact-empty-string-skip-nonempty-ordinal-P-and-complete-native-target-census'
SCHEMA['genesis']='immutable-radix-owner-grants-origins-archives-projections-then-version-anchor-then-complete-owner-set-baseline'
SCHEMA['checkpoint']='external-host-admitted-final-chain-plus-explicit-origin-sha256'
SCHEMA['native_opaque_ids']='not-arbitrary-opaque-only-typed-and-observed-SU-six-digit-P-or-T-four-digit-spellings'
SCHEMA['native_owner']='six-digit-native-owner-normalized-to-canonical-SU-decimal-only-ID-bytes-unchanged'
SCHEMA['identity']='exact-supported-stable-ID-bytes-no-renumbering-cross-kind-slot-reuse'
SCHEMA['notes']='complete-target-and-owner-missing-null-string-census-empty-string-retained-target-v0-or-owner-binding-no-approval'
SCHEMA['external_grant']='single-owner-exact-P-T-coverage-edge-note-counts-A-report-and-origin-SHA256-bound-to-session'
SCHEMA['source_semantics']='critical-only-query-and-edit; diplomatic-patch-split-line-coordinates-archival-only'
SCHEMA['external_directory_evidence']='R2-directory-digest-and-authenticated-entry-SHA256-in-origin; full-entry-only-in-A-evidence-not-Git-archive'
SCHEMA['object_bytes_max']=1024*1024
SCHEMA['service_known_objects_max']=4096
SCHEMA['pure_hash_memo_bytes_max']=2*1024*1024
SCHEMA['storage_trust']='normal-OS-durability-cooperative-single-writer-append-only-objects-coordinated-GC'
SCHEMA['tamper_boundary']='no-immediate-detection-of-same-UID-out-of-service-object-mutation'
SCHEMA['cache']='bounded-verified-immutable-payload-LRU-and-service-ledger-plus-operation-local-durable-proof'
SCHEMA['operation_admission']='request-lifetime-OID-kind-length-SHA256-proof-after-real-load-or-durable-write-never-staged-only'
SCHEMA['routing']='node-relation-note-full-typed-ID-range-boundaries-global-physical-page-IDs'
SCHEMA['version_locator']='fixed-commit-page-ID-expanded-record-hash-owner'
SCHEMA['templates']='immutable-UNKNOWN-encoding-only-independent-subject-and-version'
SCHEMA['joint_scope']='R0_CURRENT_BODY_AND_SELECTED_PRIOR_NOT_COMPLETE_NATIVE_HISTORY'
SCHEMA['streaming']={'batch_bytes':8388608,'batch_objects':512,'owner_ids_max':2079,'proof':'same-epoch-streaming-complete-durable-closure','retained':'selected-prior-archive-only-v25'}
SCHEMA['root_grant_bytes_max']=4096
SCHEMA['radix']={'digits_per_level':2,'fanout_max':200,'owner_cap':2079,'immutable_indexes':['owners','origins','archives','retained'],'membership':'one-owner-grant-path-under-external-tree-root','scope':'compact-count-and-canonical-owner-list-SHA256','origin_objects':'unchanged-per-owner-canonical-bytes','cold':'full-namespace-and-all-owner-validation','hot':'no-whole-scope-enumeration-or-grant-copy','owner_index_directory_budget':'16*scope_count+1','cold_namespace_directory_and_path_budget':'scope_count*(su_pages+128)+32','cold_namespace_depth_max':20}
SCHEMA['input_modes']=['real_r0_body','synthetic_scale_only']
SCHEMA['external_grant']='compact-external-radix-roots-count-scope-digest-mode-with-independent-leaf-grants'
SCHEMA['revision_validation']['scope']='one-dirty-member-local-native-coverage-no-cross-owner-relations'
SCHEMA['external_directory_evidence']='pure-R0-frozen-Stage-A-owner-row-and-v24-byte-census-receipts-no-R2-directory-claim'
SCHEMA['restart']={'format':'external-host-lazy-restart/v1','authority':'external-authenticated-exact-checkpoint-SHA256-and-independent-latest-root','repository':'canonical-path-and-directory-device-inode-no-cross-repository-restore','pending':'canonical-root-bound-active-and-all-seen-keys-O-active-plus-seen','checkpoint_bytes_max':16*1024*1024,'pending_keys_max':100000,'ordinary_restart':'bounded-root-headers-no-owner-enumeration-no-replay','first_owner_use':'full-local-record-semantics-origin-and-projections-raw-archives-inherited','unvisited_owners':'inherited-prior-admission-not-freshly-verified','fresh_pack_import':'full-cold-baseline-plus-deterministic-replay-required'}
SCHEMA['revision_validation']['authority']='full-cold-replay-or-exact-external-host-restart-checkpoint-with-touched-owner-validation'
SCHEMA['pending']['session']='authenticated-live-memory-or-external-root-bound-host-checkpoint'
SCHEMA['pending']['query_order']='ascending-event-digest-then-target-ID-independent-of-insertion-or-restart'
SCHEMA['publication_capacity']={'transitions_max':100000}
FACT_TEMPLATE={d:{'status':'UNKNOWN','reason':'no_verified_fact'} for d in SCHEMA['domains']}
TEMPLATES={'facts_unknown_v1':FACT_TEMPLATE,'responsibility_unknown_v1':{'status':'UNKNOWN','claims':[]}}

REF='refs/heads/main'
COUNTERS={}
SU_PATTERN=r'SU(?:[0-9]{2}|[1-9][0-9]{2,31})'
SU=re.compile(SU_PATTERN+r'\Z')
ID=re.compile('('+SU_PATTERN+r'):(source|target|coverage|dependency|reverse|note):([0-9]{4})\Z')
NATIVE_ID=re.compile(r'SU-([0-9]{6})-([PT])([0-9]{4})\Z')
OID=re.compile(r'[0-9a-f]{40}\Z')
class Rejected(Exception):pass

def need(ok,why):
    if not ok:raise Rejected(why)
def bump(k,n=1):COUNTERS[k]=COUNTERS.get(k,0)+n

PLATFORM=globals().get('__platform_api__')
need(PLATFORM is not None,'verified semantic platform bootstrap required')
EXECUTED_SOURCE_PIN=globals().get('__executed_source_sha256__')
need(isinstance(EXECUTED_SOURCE_PIN,str) and re.fullmatch('[0-9a-f]{64}',EXECUTED_SOURCE_PIN),'verified bootstrap required')

def canonical(v):
    def valid(x):
        if isinstance(x,dict):
            need(all(isinstance(k,str) for k in x),'non-string key')
            for y in x.values():valid(y)
        elif isinstance(x,list):
            for y in x:valid(y)
        else:need(x is None or type(x) in (str,int,bool),'invalid canonical scalar')
    valid(v)
    return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8')
def decode(b):
    def unique(pairs):
        d={}
        for k,v in pairs:need(k not in d,'duplicate key');d[k]=v
        return d
    try:v=json.loads(b,object_pairs_hook=unique)
    except (ValueError,UnicodeError) as e:raise Rejected('invalid JSON') from e
    need(canonical(v)==b,'noncanonical JSON');return v
# Pure byte-keyed crypto memo. Neither declared digests nor OIDs are cache keys.
_HASH_MEMO=OrderedDict()
_HASH_BYTES=0
_HASH_LIMIT=SCHEMA['pure_hash_memo_bytes_max']
_HASH_STATS={}
def _hash(algorithm,kind,b):
    global _HASH_BYTES
    need(type(b) is bytes,'immutable hash input')
    key=(algorithm,kind,b);prefix='sha256' if algorithm=='sha256' else 'git_oid'
    if key in _HASH_MEMO:
        _HASH_MEMO.move_to_end(key);name=prefix+'_hit_bytes'
        _HASH_STATS[name]=_HASH_STATS.get(name,0)+len(b);bump(name,len(b))
        return _HASH_MEMO[key]
    name=prefix+'_compute_bytes';_HASH_STATS[name]=_HASH_STATS.get(name,0)+len(b);bump(name,len(b))
    value=(hashlib.sha256(b) if algorithm=='sha256' else hashlib.sha1(kind.encode()+b' '+str(len(b)).encode()+b'\0'+b)).hexdigest()
    charge=len(b)+len(kind)+96
    if charge<=_HASH_LIMIT:
        while _HASH_MEMO and _HASH_BYTES+charge>_HASH_LIMIT:
            old,_=_HASH_MEMO.popitem(last=False);_HASH_BYTES-=len(old[2])+len(old[1])+96
        _HASH_MEMO[key]=value;_HASH_BYTES+=charge
    return value
def clear_hash_memo():
    """Drop only pure crypto entries; retain object service and all counters."""
    global _HASH_BYTES
    _HASH_MEMO.clear();_HASH_BYTES=0
def sha(b):return _hash('sha256','',b)
def oid(kind,b):
    need(kind in ('blob','tree','commit','tag'),'Git object kind')
    return _hash('sha1',kind,b)
SCHEMA_PIN=sha(canonical(SCHEMA))
def code_pin():return EXECUTED_SOURCE_PIN

_SERVICE={}
_STAT_KEYS=('cache_hits','cache_misses','cache_evictions','known_evictions','first_load_hash_bytes','first_load_verified_bytes','new_object_hash_bytes','new_object_verified_bytes','persistent_probe_bytes','code_read_bytes','admission_file_fsync_calls','admission_directory_fsync_calls','pack_sync_passes','temporary_object_write_bytes','collision_reused')
def _service(path):return _service_key(str(Path(path).resolve()))
def _service_key(key):
    if key not in _SERVICE:_SERVICE[key]={'cache':OrderedDict(),'known':OrderedDict(),'known_limit':4096,'pack_synced':False,'bytes':0,'limit':512*1024,'stats':dict.fromkeys(_STAT_KEYS,0)}
    return _SERVICE[key]
def _stat(state,k,n=1):
    state['stats'][k]=state['stats'].get(k,0)+n;bump(k,n)
def _trim(state):
    while state['cache'] and state['bytes']>state['limit']:
        _,(_,b)=state['cache'].popitem(last=False);state['bytes']-=len(b)+128;_stat(state,'cache_evictions')
def _remember(state,h,k,b):
    need(type(b) is bytes,'immutable object bytes')
    if h in state['cache']:
        old=state['cache'].pop(h);state['bytes']-=len(old[1])+128
    if len(b)+128<=state['limit']:
        state['cache'][h]=(k,b);state['bytes']+=len(b)+128;_trim(state)
    state['known'][h]=(k,len(b));state['known'].move_to_end(h)
    while len(state['known'])>state['known_limit']:
        state['known'].popitem(last=False);_stat(state,'known_evictions')
def reset_service_cache(path,clear_hashes=True):
    """Quiescent test/GC barrier: invalidate before GC/deletion/replacing a repo.

    Existing Repo handles consult the replacement state on their next access.
    The admission ledger is metadata only, independently bounded to 4096 OIDs,
    and is not the bounded payload cache. clear_hashes resets the global pure hash memo.
    """
    global _HASH_BYTES
    key=str(Path(path).resolve());limit=_service(path)['limit'];_SERVICE.pop(key,None);_service(path)['limit']=limit
    if clear_hashes:_HASH_MEMO.clear();_HASH_STATS.clear();_HASH_BYTES=0
def set_cache_limit(path,bytes):
    need(type(bytes) is int and bytes>=0,'cache byte limit');state=_service(path);state['limit']=bytes;_trim(state)
def cache_stats(path):
    state=_service(path)
    return {**state['stats'],'cache_bytes':state['bytes'],'cache_limit':state['limit'],'cache_entries':len(state['cache']),'known_objects':len(state['known']),'known_limit':state['known_limit'],'hash_memo_bytes':_HASH_BYTES,'hash_memo_limit':_HASH_LIMIT,**{k:_HASH_STATS.get(k,0) for k in ('sha256_compute_bytes','sha256_hit_bytes','git_oid_compute_bytes','git_oid_hit_bytes')}}
def check_pins(code,schema):need(code==code_pin(),'code pin');need(schema==SCHEMA_PIN,'schema pin')
def locate(ident):
    need(isinstance(ident,str),'ID string')
    m=ID.fullmatch(ident)
    if m is not None:su,kind,slot=m.groups()
    else:
        m=NATIVE_ID.fullmatch(ident);need(m is not None,'supported typed/native ID syntax')
        owner,tag,slot=m.groups();su=f'SU{int(owner):02d}';kind='source' if tag=='P' else 'target'
    slot=int(slot);need(slot<=SCHEMA['slot_max'],'slot limit')
    return su,kind,slot,None

def tree_bytes(entries):
    need(len(entries)<=200,'radix/tree fanout limit');out=[]
    bump('tree_fanout_max_observed',max(0,len(entries)-COUNTERS.get('tree_fanout_max_observed',0)))
    for n,(mode,h) in sorted(entries.items(),key=lambda x:x[0]+('/' if x[1][0]=='40000' else '')):
        need(mode in ('40000','100644') and n not in ('','.','..') and '/' not in n and '\0' not in n,'tree entry')
        need(OID.fullmatch(h),'object ID');out.append(mode.encode()+b' '+n.encode('ascii')+b'\0'+bytes.fromhex(h))
    result=b''.join(out);need(len(result)<=SCHEMA['tree_bytes'],'tree byte limit');return result
def parse_tree(b):
    need(len(b)<=SCHEMA['tree_bytes'],'tree byte limit')
    d={};at=0
    while at<len(b):
        try:z=b.index(b'\0',at);mode,n=b[at:z].decode('ascii').split(' ',1)
        except (ValueError,UnicodeError) as e:raise Rejected('tree encoding') from e
        need(n not in d and z+21<=len(b),'tree duplicate/truncated');d[n]=(mode,b[z+1:z+21].hex());at=z+21
    need(tree_bytes(d)==b,'canonical tree');bump('tree_entries_parsed',len(d));return d

def commit_bytes(tree,parent,message):
    return (f'tree {tree}\n'+(f'parent {parent}\n' if parent else '')+'author Neutral local fragment test <local-fragment@invalid> 1700000000 +0000\ncommitter Neutral local fragment test <local-fragment@invalid> 1700000000 +0000\n\n'+message+'\n').encode()

def fsync_dir(p):
    bump('directory_fsync_calls')
    PLATFORM.sync_directory(p)
def durable_file(p,b,exclusive=False):
    p=Path(p);fresh=not p.parent.exists();p.parent.mkdir(parents=True,exist_ok=True)
    if fresh:fsync_dir(p.parent.parent)
    if exclusive:
        with PLATFORM.open_exclusive(p) as f:need(f.write(b)==len(b),'short file write');f.flush();PLATFORM.sync_file(f);bump('file_fsync_calls')
    else:
        q=p.with_name(p.name+'.tmp-'+str(os.getpid()))
        with PLATFORM.open_exclusive(q) as f:need(f.write(b)==len(b),'short file write');f.flush();PLATFORM.sync_file(f);bump('file_fsync_calls')
        PLATFORM.atomic_replace(q,p)
    fsync_dir(p.parent);bump('metadata_write_bytes',len(b))

def _durable_ref_cas(r,new,old):
    """Atomic Git CAS followed by explicit ref file/namespace durability.

    Git's core.fsync option is extra defense, not a capability proof. If the
    post-CAS fence fails, raise without returning success; the actual ref may
    already be new and callers must use existing journal reconciliation.
    """
    need(type(new) is str and OID.fullmatch(new),'CAS new root format')
    need(old is None or type(old) is str and OID.fullmatch(old),'CAS old root format')
    backend=r.git('config','--local','--get','extensions.refstorage',ok=False)
    if backend.returncode not in (0,1) or (backend.returncode==0 and backend.stdout.strip().lower()!=b'files'):
        raise PLATFORM.CapabilityUnavailable('durable_git_reference','this provider requires directly syncable files refs')
    path=r.path/'refs/heads/main';directories=(path.parent,path.parent.parent,r.path)
    need(not path.is_symlink(),'direct no-symlink main ref')
    for directory in directories:
        need(directory.is_dir(),'existing reference namespace required')
        fsync_dir(directory)  # Capability must be available before CAS.
    if path.exists():
        with PLATFORM.open_read(path) as current:
            need(current.read(128)==((old or '')+'\n').encode(),'direct main ref old bytes')
    result=r.git('-c','core.fsync=all','update-ref',REF,new,old or '0'*40,ok=False)
    need(result.returncode==0,'CAS conflict')
    _durable_ref_fence(r,new)

def _durable_ref_fence(r,root):
    """Repeatable post-CAS durability fence, including recovery's no-CAS path."""
    path=r.path/'refs/heads/main'
    need(type(root) is str and OID.fullmatch(root),'ref fence root format')
    with PLATFORM.open_read(path) as published:
        need(published.read(128)==(root+'\n').encode(),'published direct ref bytes')
        PLATFORM.sync_file(published);bump('file_fsync_calls')
    for directory in (path.parent,path.parent.parent,r.path):fsync_dir(directory)
    need(r.ref()==root,'durable ref changed after fence')



class Repo:
    def __init__(self,path):
        self.path=Path(path).resolve();self.service_key=str(self.path);need((self.path/'objects').is_dir(),'dedicated bare Git required')
        self.batch=None
        self.memo={};self.trees={};self.staged={};self.required={};self.operation_admitted={}
    def close(self):
        p,self.batch=self.batch,None
        if p is not None:
            for stream in (p.stdin,p.stdout,p.stderr):
                try:stream.close()
                except (OSError,BrokenPipeError):pass
            p.wait()
    def _reader(self):
        if self.batch is None:
            self.batch=subprocess.Popen(['git','--git-dir='+str(self.path),'cat-file','--batch'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        return self.batch
    def git(self,*args,data=None,ok=True):
        p=subprocess.run(['git','-c','pack.threads=1','-c','gc.auto=0','--git-dir='+str(self.path),*args],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        bump('git_stdout_read_bytes',len(p.stdout));bump('git_stdin_write_bytes',len(data or b''))
        if ok:need(p.returncode==0,'git '+str(args)+': '+p.stderr.decode(errors='replace'))
        return p.stdout if ok else p
    def _sync_unknown_storage(self,h):
        # Readability and a valid OID prove identity, not completed durability.
        # In particular, an interrupted link+directory-fsync must be repaired
        # before get() can establish the durable-known fast path.
        state=_service_key(self.service_key)
        if h in state['known']:return
        def sync_file(path):
            with open(path,'rb') as f:PLATFORM.sync_file(f)
            bump('file_fsync_calls');_stat(state,'admission_file_fsync_calls')
        def sync_directory(path):
            fsync_dir(path);_stat(state,'admission_directory_fsync_calls')
        loose=self.path/'objects'/h[:2]/h[2:]
        if loose.is_file():
            sync_file(loose);sync_directory(loose.parent);sync_directory(self.path/'objects')
        elif not state['pack_synced']:
            pack=self.path/'objects'/'pack'
            need(pack.is_dir(),'unknown object has no local storage')
            # No payload reads. A cooperative durable importer calls admit_head
            # after each new pack import to invalidate this store-level barrier.
            for path in sorted(pack.iterdir()):
                if path.suffix in ('.pack','.idx','.rev','.bitmap') and path.is_file():sync_file(path)
            sync_directory(pack);sync_directory(self.path/'objects')
            state['pack_synced']=True;_stat(state,'pack_sync_passes')
    def _admission_signature(self,k,b):return (k,len(b),sha(b))
    def _record_admission(self,h,k,b):
        signature=self._admission_signature(k,b)
        need(h not in self.operation_admitted or self.operation_admitted[h]==signature,'operation object collision')
        self.operation_admitted[h]=signature;bump('operation_admission_proofs')
        bump('operation_admission_peak',max(0,len(self.operation_admitted)-COUNTERS.get('operation_admission_peak',0)))
    def _load(self,h,expected=None,category='state',allow_missing=False):
        # Official Git reader; no staged shortcut. A cache miss always validates
        # header, type, length and content identity even for a known durable OID.
        state=_service_key(self.service_key);_stat(state,'cache_misses')
        self._reader();self.batch.stdin.write(h.encode()+b'\n');self.batch.stdin.flush()
        hdr=self.batch.stdout.readline(4096).split()
        if allow_missing and hdr==[h.encode(),b'missing']:
            need(not (self.path/'objects'/h[:2]/h[2:]).exists(),'existing object unreadable')
            return None
        need(len(hdr)==3 and hdr[0]==h.encode(),'missing/invalid object header')
        try:k=hdr[1].decode('ascii');n=int(hdr[2])
        except (ValueError,UnicodeError):raise Rejected('object header encoding')
        need(k in ('blob','tree','commit','tag') and 0<=n<=SCHEMA['object_bytes_max'],'object type/length or prototype byte limit')
        if expected:need(k==expected,'object type')
        b=self.batch.stdout.read(n);need(len(b)==n and self.batch.stdout.read(1)==b'\n','batch truncated')
        before=_HASH_STATS.get('git_oid_compute_bytes',0)
        need(oid(k,b)==h,'object bytes identity')
        _stat(state,'first_load_hash_bytes',_HASH_STATS.get('git_oid_compute_bytes',0)-before)
        _stat(state,'first_load_verified_bytes',len(b));self._sync_unknown_storage(h);_remember(state,h,k,b);self._record_admission(h,k,b)
        bump('logical_read_bytes',len(b));bump(category+'_read_bytes',len(b));bump('objects_read')
        return k,b
    def get(self,h,expected=None,category='state'):
        need(isinstance(h,str) and OID.fullmatch(h),'invalid oid');state=_service_key(self.service_key)
        if h in self.staged:k,b=self.staged[h]
        elif h in state['cache'] and h in state['known']:
            k,b=state['cache'][h];state['cache'].move_to_end(h);state['known'].move_to_end(h);_stat(state,'cache_hits');bump('memory_object_hits');self._record_admission(h,k,b)
        else:k,b=self._load(h,expected,category)
        if expected:need(k==expected,'object type')
        bump('logical_object_access_bytes',len(b));self.required[h]=(k,b)
        return b
    def stage(self,k,b):
        need(type(b) is bytes and len(b)<=SCHEMA['object_bytes_max'],'immutable staged bytes/prototype byte limit');state=_service_key(self.service_key)
        before=_HASH_STATS.get('git_oid_compute_bytes',0);h=oid(k,b)
        _stat(state,'new_object_hash_bytes',_HASH_STATS.get('git_oid_compute_bytes',0)-before)
        _stat(state,'new_object_verified_bytes',len(b))
        need(h not in self.required or self.required[h]==(k,b),'same-operation staged content collision')
        need(h not in self.operation_admitted or self.operation_admitted[h]==self._admission_signature(k,b),'staged/admitted content collision')
        self.staged[h]=(k,b);self.required[h]=(k,b);bump('logical_staged_bytes',len(b));return h
    def _persistent_probe(self, expected):
        """Read actual bytes through official Git with bounded diagnostic drain.

        A portable buffered-reader thread replaces nonblocking OS pipe flags.
        Any diagnostic rejects; no success escapes before the reader joins.
        """
        if not expected:return []
        p=subprocess.Popen(['git','--git-dir='+str(self.path),'cat-file','--batch'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        missing=[];diagnostic=threading.Event();reader=None
        def drain_errors():
            try:
                while True:
                    data=p.stderr.read1(8192)
                    if not data:return
                    diagnostic.set()
                    # Any diagnostic is already rejection. Stop the producer so
                    # stdout cannot block while a failed Git waits for input.
                    try:p.kill()
                    except ProcessLookupError:pass
                    return
            except (OSError,ValueError):diagnostic.set()
        try:
            reader=threading.Thread(target=drain_errors,daemon=True);reader.start()
            for h,(kind,wanted) in sorted(expected.items()):
                need(oid(kind,wanted)==h,'expected object identity')
                need(not diagnostic.is_set(),'persistent Git diagnostic')
                p.stdin.write(h.encode()+b'\n');p.stdin.flush()
                header=p.stdout.readline(4096)
                need(not diagnostic.is_set(),'persistent Git diagnostic')
                fields=header.split()
                if fields==[h.encode(),b'missing']:
                    need(not (self.path/'objects'/h[:2]/h[2:]).exists(),'persistent existing object unreadable')
                    missing.append(h);continue
                need(len(fields)==3 and fields[0]==h.encode(),'persistent object header')
                try:size=int(fields[2])
                except ValueError:raise Rejected('persistent object length')
                need(fields[1].decode()==kind,'persistent object type')
                need(size==len(wanted),'persistent object length')
                body=p.stdout.read(size);end=p.stdout.read(1)
                need(len(body)==size and end==b'\n','persistent object truncated')
                bump('persistent_disk_read_bytes',len(body));_stat(_service_key(self.service_key),'persistent_probe_bytes',len(body));bump('persistent_objects_verified')
                need(oid(kind,body)==h and body==wanted,'persistent object hash/content')
            p.stdin.close();p.stdin=None;rc=p.wait();reader.join(timeout=5)
            need(not reader.is_alive() and rc==0 and not diagnostic.is_set(),'persistent Git diagnostic')
            return missing
        finally:
            if p.poll() is None:p.kill();p.wait()
            if p.stdin is not None:p.stdin.close()
            if reader is not None and reader.ident is not None:reader.join(timeout=5)
            p.stdout.close();p.stderr.close()
    def verify_persistent_required(self):
        need(not self._persistent_probe(self.required),'persistent required object missing')
        bump('persistent_verification_passes')
    def assert_admitted(self):
        for h,(k,b) in self.required.items():
            need(self.operation_admitted.get(h)==self._admission_signature(k,b),'required object lacks operation-local durable proof')
    def admit_existing_required(self):
        # Reconstructed staged bytes are not persistence. The proof is populated
        # only by real verified reads, admitted cached bytes, or completed writes.
        for h,(k,b) in self.required.items():
            if self.operation_admitted.get(h)!=self._admission_signature(k,b):
                actual=self._load(h,k,'admission');need(actual==(k,b),'existing staged identity')
        self.assert_admitted()
    def _write_object(self,h,k,b):
        p=self.path/'objects'/h[:2]/h[2:];p.parent.mkdir(exist_ok=True)
        # Always fsync fanout's parent: a prior interrupted mkdir may exist.
        fsync_dir(self.path/'objects')
        payload=zlib.compress(k.encode()+b' '+str(len(b)).encode()+b'\0'+b)
        fd,temp=tempfile.mkstemp(prefix='.normal-tmp-',dir=p.parent);created=False
        try:
            with os.fdopen(fd,'wb') as f:
                need(f.write(payload)==len(payload),'short object write');_stat(_service_key(self.service_key),'temporary_object_write_bytes',len(payload));f.flush();PLATFORM.sync_file(f);bump('file_fsync_calls')
            # link is atomic no-replace; never expose a partially written OID.
            try:PLATFORM.publish_noreplace(temp,p);created=True
            except FileExistsError:
                self.close();actual=self._load(h,k,'admission');need(actual==(k,b),'concurrent object collision');_stat(_service_key(self.service_key),'collision_reused')
            fsync_dir(p.parent)
        except BaseException:
            # No admission survives a write/fsync failure, even after link success.
            state=_service_key(self.service_key);state['known'].pop(h,None);self.operation_admitted.pop(h,None)
            old=state['cache'].pop(h,None)
            if old:state['bytes']-=len(old[1])+128
            raise
        finally:
            try:os.unlink(temp)
            except OSError:pass  # An abandoned private temp is safe and never an OID.
        if created:bump('loose_compressed_write_bytes',len(payload));bump('objects_written')
        _remember(_service_key(self.service_key),h,k,b);self._record_admission(h,k,b)
    def flush(self):
        for h,(k,b) in self.required.items():
            if self.operation_admitted.get(h)==self._admission_signature(k,b):
                bump('persistent_existing_reused');continue
            # A bounded cross-operation metadata ledger does not prove staged
            # bytes equal a preexisting object, nor hold every cold object at once.
            actual=self._load(h,k,'admission',allow_missing=h in self.staged)
            if actual is not None:need(actual==(k,b),'existing staged identity')
            else:self._write_object(h,k,b)
        self.assert_admitted()
    @contextlib.contextmanager
    def integrity_operation(self):
        # Cooperating authenticated requests serialize. This is not an OS sandbox
        # against a noncooperating writer changing files after final verification.
        with PLATFORM.repository_lock(self.path/'integrity.lock'):
            self.close();self.memo={};self.trees={};self.required={};self.staged={};self.operation_admitted={}
            bump('request_scopes')
            try:yield
            finally:
                self.close();self.memo={};self.trees={};self.required={};self.staged={};self.operation_admitted={}
    def tree(self,h):
        data=self.get(h,'tree')
        if h not in self.trees:self.trees[h]=parse_tree(data);bump('trees_parsed')
        return self.trees[h]
    def root(self,commit):
        b=self.get(commit,'commit');line=b.split(b'\n',1)[0];need(line.startswith(b'tree '),'commit root');return line[5:].decode()
    def path_oid(self,commit,path):
        h=self.root(commit)
        for i,n in enumerate(path.split('/')):
            d=self.tree(h);need(n in d,'path absent '+path);mode,h=d[n]
            need(mode==('100644' if i==len(path.split('/'))-1 else '40000'),'path type')
        return h
    def read_path(self,commit,path,category='state'):return self.get(self.path_oid(commit,path),'blob',category)
    def update_tree(self,old,changes):
        entries=dict(self.tree(old)) if old else {};groups={}
        for path,h in changes.items():
            a,*tail=path.split('/');groups.setdefault(a,[]).append(('/'.join(tail),h))
        for n,rows in groups.items():
            if rows[0][0]=='':need(len(rows)==1,'overlapping tree change');entries[n]=('100644',rows[0][1])
            else:
                prev=entries.get(n);need(prev is None or prev[0]=='40000','tree path collision')
                entries[n]=('40000',self.update_tree(prev[1] if prev else None,dict(rows)))
        return self.stage('tree',tree_bytes(entries))
    def ref(self):
        p=self.git('rev-parse','--verify',REF,ok=False)
        return p.stdout.strip().decode() if p.returncode==0 else None
    def admit_head(self,root):
        """Trusted seed/import hook, after completed durable Git import.

        Caller is responsible for fsynced pack import and coordinated closure/GC.
        This validates the stored commit, not externally supplied authority, and
        cannot admit an in-memory staged-only root. Normal publish uses flush.
        """
        need(isinstance(root,str) and OID.fullmatch(root),'admission root OID')
        _service_key(self.service_key)['pack_synced']=False
        self._load(root,'commit','admission')
        return root
    def cas(self,new,old):
        self.assert_admitted()
        need(isinstance(new,str) and OID.fullmatch(new) and self.operation_admitted.get(new,(None,))[0]=='commit','CAS root not durable-admitted')
        _durable_ref_cas(self,new,old)

def su_groups(su):
    need(isinstance(su,str) and SU.fullmatch(su),'SU ID')
    digits=su[2:];need(len(digits)<=SCHEMA['su_digits_max'],'SU digit resource limit')
    digits=('0' if len(digits)%2 else '')+digits
    return [digits[i:i+2] for i in range(0,len(digits),2)]
def su_dir(su):
    groups=su_groups(su);return '/'.join(['su']+groups[:-1]+['u'+groups[-1]])
def manifest_path(su):return su_dir(su)+'/manifest.json'
def page_path(su,index):return su_dir(su)+f'/p{index:04d}.json'
def original_path(su,kind):
    need(kind in ('source','target'),'original kind')
    return 'projections/'+owner_radix_path(su)+'/'+kind+'.txt'
ARCHIVE_KINDS=('source_owner','native_target')
ARCHIVE_REPRESENTATIONS={'source_owner':'authenticated_source_compact_cas','native_target':'authenticated_native_target_cas'}
def archive_path(su,kind):
    need(isinstance(su,str) and SU.fullmatch(su) and kind in ARCHIVE_KINDS,'typed archive kind/owner')
    return 'archives/'+su+'/'+kind+'.raw.json'
def owner_radix_path(su):
    groups=su_groups(su)
    return '/'.join(groups[:-1]+['u'+groups[-1]])
def owner_grant_path(su):return 'owners/'+owner_radix_path(su)+'/grant.json'
def origin_path(su):return 'origins/'+owner_radix_path(su)+'/origin.json'
def archive_storage_path(su,kind):
    need(kind in ARCHIVE_KINDS,'archive kind')
    return 'archives/'+owner_radix_path(su)+'/'+kind+'.raw.json'
def provenance_mode(grant):return grant['mode']
def public_scope(grant):
    return SCHEMA['joint_scope'] if grant['mode']=='real_r0_body' else 'SYNTHETIC_SCALE_ONLY_NO_NATIVE_PROVENANCE'
def projection_provenance(mode):
    return 'projection_of_authenticated_archive_fields_no_approval' if mode=='real_r0_body' else 'projection_of_synthetic_test_fields_no_native_provenance'
def archive_provenance(mode):
    return 'host_attested_fixed_su_raw_no_approval' if mode=='real_r0_body' else 'synthetic_test_raw_no_native_provenance'
def scope_descriptor(grant):return {'count':grant['scope_count'],'sha256':grant['scope_sha256']}
def make_checkpoint(grant,baseline,final):
    _grant_contract(grant)
    return {'kind':'trusted_host_admitted_chain_not_user_signature','baseline':baseline,'final':final,'code':code_pin(),'schema':SCHEMA_PIN,'scope':scope_descriptor(grant),'origin_sha256':grant['origin_sha256'],'origin_grant':copy.deepcopy(grant)}

def _read_archive(r,commit,descriptor):
    bump('archive_access_calls');h=r.path_oid(commit,descriptor['storage_path'])
    need(h==descriptor['git_blob'],'archive current path differs from admitted baseline')
    raw=r.get(h,'blob','archive');bump('archive_logical_bytes',len(raw))
    need(len(raw)==descriptor['byte_length'] and sha(raw)==descriptor['sha256'],'archive raw exact SHA256/length')
    return raw
def scope_bytes(sus):
    bump('scope_enumeration_calls');bump('scope_members_enumerated',len(sus) if isinstance(sus,list) else 0)
    need(isinstance(sus,list),'external scope list')
    for su in sus:su_groups(su)
    need(sus==sorted(set(sus),key=lambda su:(len(su),su)),'canonical unique scope')
    need(bool(sus),'empty scope')
    return canonical({'count':len(sus),'sus':sus})
def empty_facts(reason='no_verified_fact'):return {d:{'status':'UNKNOWN','reason':reason} for d in SCHEMA['domains']}

SPACES=('node','relation','note')
def record_space(ident):
    kind=locate(ident)[1]
    return 'node' if kind in ('source','target') else 'note' if kind=='note' else 'relation'
def record_sort_key(ident):
    locate(ident);return ident

def route_page(m,ident):
    own=locate(ident)[0];need(m['su']==own,'route owner')
    space=record_space(ident);ds=[d for d in m['pages'] if d['space']==space]
    need(ds and ds[0]['low'] is None,'route first boundary')
    found=ds[0]['page']
    for d in ds[1:]:
        if d['low']<=ident:found=d['page']
        else:break
    return found

def _check_manifest(su,m):
    need(isinstance(m,dict) and set(m)=={'format','su','pages','counts','originals','archives','initial_anchor','templates','completeness'},'manifest shape')
    need(m['format']==SCHEMA['format'] and m['su']==su,'manifest identity')
    need(m['templates']==TEMPLATES,'immutable encoding templates')
    need(m['initial_anchor'] is None or OID.fullmatch(m['initial_anchor']),'initial anchor')
    need(isinstance(m['archives'],dict) and set(m['archives'])==set(ARCHIVE_KINDS),'manifest exact archive kinds')
    for kind,ref in m['archives'].items():_archive_ref_contract(su,kind,ref)
    ds=m['pages'];need(isinstance(ds,list) and 0<len(ds)<=128,'SU page limit')
    need(len(canonical(m))<=16384,'manifest limit')
    seen=set();last={};last_space=-1
    for d in ds:
        need(isinstance(d,dict) and set(d)=={'page','space','low'},'route descriptor shape')
        need(type(d['page']) is int and 0<=d['page']<128 and d['page'] not in seen,'route duplicate/page ID');seen.add(d['page'])
        space=d['space'];need(space in SPACES and SPACES.index(space)>=last_space,'route space order');last_space=SPACES.index(space)
        if space not in last:need(d['low'] is None,'route first boundary');last[space]=''
        else:
            low=d['low'];need(isinstance(low,str) and locate(low)[0]==su and record_space(low)==space and low>last[space],'route order/owner/space');last[space]=low

def version_refs(record,kind=None):
    kind=record['kind'] if kind is None else kind
    if kind=='note':need(isinstance(record.get('about'),dict) and record['about'].get('kind') in ('owner','target'),'note explicit binding shape')
    return record['sources']+record['targets'] if kind=='coverage' else [record['basis']] if kind=='dependency' else [record['about']] if kind=='note' and record['about'].get('kind')=='target' else []

def _encode_record(r,m):
    if LAYOUT=='fixed':return copy.deepcopy(r)
    v=copy.deepcopy(r);own,kind,slot,_=locate(v['id'])
    need(v.pop('kind')==kind and v.pop('slot')==slot,'logical identity encoding')
    if kind in ('source','target'):
        need(v.pop('responsibility')=={'for_version':v['version'],'status':'UNKNOWN','claims':[]},'independent responsibility template')
        v['responsibility_ref']='responsibility_unknown_v1'
        if kind=='target':
            facts=v.pop('facts');need(set(facts)==set(FACT_TEMPLATE),'facts domains')
            v['facts_ref']='facts_unknown_v1';v['facts_overrides']={d:f for d,f in facts.items() if f!=FACT_TEMPLATE[d]}
    refs=version_refs(v,kind)
    for ref in refs:
        loc=ref.pop('locator');need(set(loc)=={'commit','page','record_sha256','owner'},'locator shape')
        need(loc['owner']==locate(ref['id'])[0],'locator owner')
        ref['location']={'anchor':0 if loc['commit']==m['initial_anchor'] else loc['commit'],'page':loc['page'],'record':loc['record_sha256']}
    return v

def _decode_record(v,m):
    if LAYOUT=='fixed':return copy.deepcopy(v)
    r=copy.deepcopy(v);own,kind,slot,_=locate(r['id']);need('kind' not in r and 'slot' not in r,'duplicate encoded identity')
    r.update(kind=kind,slot=slot)
    if kind in ('source','target'):
        need(r.pop('responsibility_ref',None)=='responsibility_unknown_v1','responsibility reference')
        need('responsibility' not in r,'duplicate responsibility')
        r['responsibility']={'for_version':r['version'],**copy.deepcopy(m['templates']['responsibility_unknown_v1'])}
        if kind=='target':
            need(r.pop('facts_ref',None)=='facts_unknown_v1' and 'facts' not in r,'facts reference')
            overrides=r.pop('facts_overrides');need(isinstance(overrides,dict) and set(overrides)<=set(FACT_TEMPLATE),'facts override domain')
            need(all(v!=FACT_TEMPLATE[k] for k,v in overrides.items()),'redundant fact override')
            r['facts']={**copy.deepcopy(m['templates']['facts_unknown_v1']),**overrides}
    refs=version_refs(r)
    for ref in refs:
        loc=ref.pop('location');need(set(loc)=={'anchor','page','record'},'compact locator shape')
        a=loc['anchor'];need(type(a) is int and a==0 or isinstance(a,str) and OID.fullmatch(a),'locator anchor selector')
        commit=m['initial_anchor'] if a==0 else a;need(commit is not None,'missing initial anchor')
        ref['locator']={'commit':commit,'page':loc['page'],'record_sha256':loc['record'],'owner':locate(ref['id'])[0]}
    return r

def page_bytes(su,pg,rows,m):
    need(len(rows)<=32,'page record limit')
    encoded=[]
    for r in sorted(rows,key=lambda x:record_sort_key(x['id'])):
        # Single record cap is on expanded logical data, not a loophole via encoding.
        need(len(canonical(r))<=8192,'record byte limit')
        e=_encode_record(r,m);encoded.append(e);bump('encoded_record_bytes',len(canonical(e)))
    b=canonical({'su':su,'page':pg,'records':encoded});bump('encoded_page_bytes',len(b));bump('pages_encoded')
    return b

def encode_su(su,records,originals,previous=None,changed_ids=None,initial_anchor=None,archives=None):
    ids=set();counts={}
    for r in records:
        own,kind,slot,_=locate(r['id']);need(own==su and r['kind']==kind and r['slot']==slot,'typed logical identity')
        need(r['id'] not in ids,'duplicate identity');ids.add(r['id'])
        need(len(canonical(r))<=8192,'record byte limit');counts[kind]=counts.get(kind,0)+1
    m=copy.deepcopy(previous) if previous else {'format':SCHEMA['format'],'su':su,'pages':[],'counts':counts,'originals':originals,'archives':copy.deepcopy(archives),'initial_anchor':initial_anchor,'templates':copy.deepcopy(TEMPLATES),'completeness':('complete_fixed_native_SU_body_coverage_and_target_note_census_raw_metadata_archival_only' if archives['source_owner']['provenance']=='host_attested_fixed_su_raw_no_approval' else 'synthetic_scale_fixture_body_coverage_and_note_census_no_native_provenance')}
    if previous:
        need(m['originals']==originals and m['counts']==counts and m['templates']==TEMPLATES,'immutable header/counts')
        need(archives is None or archives==m['archives'],'immutable archive references')
    groups={};dirty=set();initial_pages={}
    if previous:
        _check_manifest(su,m)
        for row in records:groups.setdefault(route_page(m,row['id']),[]).append(row)
        need(set(groups)=={d['page'] for d in m['pages']},'missing/empty route page')
        dirty={route_page(m,i) for i in (changed_ids if changed_ids is not None else ids)}
    else:
        pg=0
        # Canonical record bytes live only in this call. Keep fragments for the
        # current page and retain completed bytes as the eventual output, not a
        # second owner-wide record cache. Header keys are canonical sort order.
        suffix=None
        def prefix(index):return b'{"page":'+canonical(index)+b',"records":['
        def retain_page(index,body,size):
            # An over-limit input still reaches the original SU/page gates in
            # their original order. Never accumulate an unbounded output cache.
            if index>=128:initial_pages.clear()
            elif len(body)<=16384:initial_pages[index]=(body,size)
        for space in SPACES:
            current=[];encoded=[];encoded_size=0;low=None;head=prefix(pg)
            for row in sorted((r for r in records if record_space(r['id'])==space),key=lambda r:record_sort_key(r['id'])):
                e=canonical(_encode_record(row,m))
                if suffix is None:suffix=b'],"su":'+canonical(su)+b'}'
                trial=encoded+[e];body=head+b','.join(trial)+suffix
                if current and (len(trial)>32 or len(body)>SCHEMA['initial_compact_fill_bytes']):
                    groups[pg]=current;retain_page(pg,current_bytes,encoded_size)
                    m['pages'].append({'page':pg,'space':space,'low':low});pg+=1;low=row['id']
                    current=[];encoded=[];encoded_size=0;head=prefix(pg);body=head+e+suffix
                current.append(row);encoded.append(e);encoded_size+=len(e);current_bytes=body
            if current:
                groups[pg]=current;retain_page(pg,current_bytes,encoded_size)
                m['pages'].append({'page':pg,'space':space,'low':low});pg+=1
        dirty=set(groups)
    need(len(groups)<=128,'SU page limit')
    blobs={}
    for pg in sorted(dirty):
        rows=sorted(groups[pg],key=lambda r:record_sort_key(r['id']))
        if previous or pg not in initial_pages:b=page_bytes(su,pg,rows,m)
        else:
            need(len(rows)<=32,'page record limit');b,encoded_size=initial_pages.pop(pg)
            bump('encoded_record_bytes',encoded_size);bump('encoded_page_bytes',len(b));bump('pages_encoded')
        if len(b)>16384:
            need(previous is not None,'page byte limit');need(len(groups)<128,'SU page limit')
            newpg=max(groups)+1;need(newpg<128,'SU page ID capacity');candidates=[]
            for i in range(1,len(rows)):
                left=canonical({'su':su,'page':pg,'records':[_encode_record(x,m) for x in rows[:i]]})
                right=canonical({'su':su,'page':newpg,'records':[_encode_record(x,m) for x in rows[i:]]})
                if len(left)<=16384 and len(right)<=16384:candidates.append((max(len(left),len(right)),abs(len(left)-len(right)),i,left,right))
            need(bool(candidates),'no legal page split')
            _,_,i,left,right=min(candidates,key=lambda x:x[:3]);groups[pg]=rows[:i];groups[newpg]=rows[i:]
            at=next(j for j,d in enumerate(m['pages']) if d['page']==pg)
            m['pages'].insert(at+1,{'page':newpg,'space':record_space(rows[i]['id']),'low':rows[i]['id']})
            blobs[page_path(su,pg)]=left;blobs[page_path(su,newpg)]=right
            bump('page_splits');bump('split_old_page_bytes',len(b));bump('split_output_bytes',len(left)+len(right))
        else:blobs[page_path(su,pg)]=b
    _check_manifest(su,m);mb=canonical(m);bump('manifest_encoded_bytes',len(mb))
    if previous is None or m!=previous:blobs[manifest_path(su)]=mb;bump('manifests_emitted')
    return blobs

class Snapshot:
    def __init__(self,r,commit,grant):
        _grant_contract(grant);self.grant=copy.deepcopy(grant);self.index=OwnerIndex(r,commit,self.grant);self.owners=self.index;self.r=r;self.commit=commit;self.sus={};self.manifests={};self.historical={};self.reverse_groups={}
    def member_grant(self,su):return self.index.member_grant(su)
    def su(self,su):
        need(su in self.owners,'snapshot owner outside external owner-set grant')
        if su not in self.sus:
            su_groups(su);m=decode(self.r.read_path(self.commit,manifest_path(su)));_check_manifest(su,m)
            need(m['completeness']==('complete_fixed_native_SU_body_coverage_and_target_note_census_raw_metadata_archival_only' if self.grant['mode']=='real_r0_body' else 'synthetic_scale_fixture_body_coverage_and_note_census_no_native_provenance'),'manifest input mode')
            rows=[];ids=set();counts={}
            for d in m['pages']:
                b=self.r.read_path(self.commit,page_path(su,d['page']));p=decode(b)
                need(len(b)<=16384 and set(p)=={'su','page','records'} and p['su']==su and p['page']==d['page'],'page commitment')
                need(0<len(p['records'])<=32,'page record count')
                if LAYOUT=='fixed':need(len(b)==d['bytes'] and sha(b)==d['sha256'] and len(p['records'])==d['records'],'page commitment')
                last=''
                for e in p['records']:
                    x=_decode_record(e,m);own,kind,slot,_=locate(x['id'])
                    need(own==su and x['kind']==kind and x['slot']==slot and route_page(m,x['id'])==d['page'] and record_space(x['id'])==d['space'],'page range/owner')
                    need(x['id'] not in ids and x['id']>last,'duplicate/order identity');ids.add(x['id']);last=x['id']
                    need(len(canonical(x))<=8192 and _encode_record(x,m)==e,'record encoding/cap');counts[kind]=counts.get(kind,0)+1;rows.append(x)
            need(counts==m['counts'],'manifest counts completeness')
            self.sus[su]={x['id']:x for x in rows};self.manifests[su]=m;bump('SUs_loaded')
            self.reverse_groups[su]={}
            for x in rows:
                if x['kind']=='reverse':self.reverse_groups[su].setdefault(x['provider'],[]).append(x)
            if getattr(self.r,'_lazy_validate',False):_validate_lazy_owner(self,su)
        return self.sus[su]
    def record(self,ident):
        su,kind,slot,_=locate(ident);d=self.su(su);need(ident in d,'unknown record identity');return d[ident]
    def node(self,ident):
        need(locate(ident)[1] in ('source','target'),'node type');return self.record(ident)
    def note(self,ident):
        need(locate(ident)[1]=='note','note type');return self.record(ident)
    def page_of(self,ident):
        own,kind,slot,_=locate(ident);self.su(own);return route_page(self.manifests[own],ident)
    def exact_version(self,ref):
        bump('exact_version_calls');return self._exact_record_version(ref,('source','target'))
    def exact_note_version(self,ref):return self._exact_record_version(ref,('note',))
    def _version_object(self,commit,path,owner=None):
        # Parsed immutable historical input, never an admission/session credential.
        # Repo.memo is cleared at epoch entry/exit and streaming batch release.
        # The mode is part of the path identity; a service reset also invalidates
        # this cache. Keep no decoded records or cross-request owner/history cache.
        need(isinstance(commit,str) and OID.fullmatch(commit),'invalid oid')
        r=self.r;cache=None;key=(getattr(r,'_native_mode',False),commit,path,owner)
        if getattr(r,'epoch',None) is not None:
            state=_service_key(r.service_key);cache=r.memo.get('exact-version-inputs')
            if cache is None or cache['service'] is not state:
                cache={'service':state,'items':{},'bytes':0};r.memo['exact-version-inputs']=cache
            if key in cache['items']:
                bump('exact_version_input_reuse');return cache['items'][key]
        raw=r.read_path(commit,path,'direct_version');value=decode(raw)
        if owner is not None:_check_manifest(owner,value)
        if cache is not None and len(raw)<=16384:
            # A bounded disposable parse cache; eviction only repeats old work.
            if len(cache['items'])>=128 or cache['bytes']+len(raw)>512*1024:
                cache['items'].clear();cache['bytes']=0
            cache['items'][key]=value;cache['bytes']+=len(raw)
        return value
    def _exact_record_version(self,ref,kinds):
        need(locate(ref['id'])[1] in kinds,'exact version record type')
        need('locator' in ref,'version locator required');self.record(ref['id'])
        loc=ref['locator'];own,kind,slot,_=locate(ref['id'])
        need(isinstance(loc,dict) and set(loc)=={'commit','page','record_sha256','owner'},'locator shape')
        need(loc['owner']==own,'locator owner');need(type(loc['page']) is int and 0<=loc['page']<128,'locator page')
        m=self._version_object(loc['commit'],manifest_path(own),own)
        need(route_page(m,ref['id'])==loc['page'],'locator exact historical route')
        page=self._version_object(loc['commit'],page_path(own,loc['page']))
        need(set(page)=={'su','page','records'} and page['su']==own and page['page']==loc['page'],'locator page identity')
        matches=[_decode_record(v,m) for v in page['records'] if v['id']==ref['id']];need(len(matches)==1,'locator record identity');n=matches[0]
        need(n['kind']==kind and n['slot']==slot and n['version']==ref['version'] and n['digest']==ref['digest'] and sha(n['text'].encode())==ref['digest'],'locator exact version identity')
        need(sha(canonical(n))==loc['record_sha256'],'locator record hash');return n
    def exact_version_prior(self,ref):return self._exact_version_prior(ref,('source','target'))
    def exact_note_version_prior(self,ref):return self._exact_version_prior(ref,('note',))
    def _exact_version_prior(self,ref,kinds):
        need(locate(ref['id'])[1] in kinds,'prior record type');n=self.record(ref['id'])
        if n['version']==ref['version'] and n['digest']==ref['digest']:return n
        key=(ref['id'],ref['version'],ref['digest'])
        if key in self.historical:return self.historical[key]
        visited=set()
        while n.get('prior'):
            h=n['prior'];need(len(visited)<100000 and h['commit'] not in visited,'history cycle/budget');visited.add(h['commit'])
            if hasattr(self,'_admitted_ancestors'):need(h['commit'] in self._admitted_ancestors,'prior hop outside admitted ancestry')
            b=self.r.read_path(h['commit'],h['path'],'historical_record');p=decode(b)
            candidates=[x for x in p['records'] if x['id']==ref['id']];need(len(candidates)==1,'historical identity')
            n=_decode_record(candidates[0],decode(self.r.read_path(h['commit'],manifest_path(locate(ref['id'])[0]))));need(sha(canonical(n))==h['record_sha256'],'historical record digest')
            if n['version']==ref['version'] and n['digest']==ref['digest']:self.historical[key]=n;return n
        raise Rejected('version not retained')

def span_ref(n,a=0,b=None):return {'id':n['id'],'kind':n['kind'],'version':n['version'],'digest':n['digest'],'start':a,'end':len(n['text']) if b is None else b}
def validate_span(s,ref,kind):
    need(locate(ref['id'])[1]==kind and ref['kind']==kind,'span type')
    n=s.exact_version(ref);need(type(ref['start']) is int and type(ref['end']) is int and 0<=ref['start']<=ref['end']<=len(n['text']),'span codepoint bounds')
    return n

def validate_record(s,r):
    own,kind,slot,pg=locate(r['id']);need(type(r['slot']) is int and r['slot']==slot and r['kind']==kind,'record type')
    need(own in s.owners,'record owner outside external owner-set grant')
    need(kind in ('source','target','coverage','note'),'native fragment forbids dependency/reverse or fabricated actual-use')
    if kind in ('source','target'):
        fields={'id','kind','slot','order','live','version','text','digest','original','prior','responsibility','lineage'}
        if kind=='target':fields|={'facts','obligations'}
        need(set(r)==fields,'native node exact fields/no approval payload')
        need(NATIVE_ID.fullmatch(r['id']) is not None and own in s.owners and slot>0,'preserve selected native P/T identity')
        need(type(r['order']) is int and r['order']>=0 and r['live'] is True and r['lineage']==[],'fragment node lifecycle')
        need(isinstance(r['text'],str),'native text string')
        need(set(r['original'])=={'ref','span','version','current_alignment'} and r['original']['ref']==kind and type(r['original']['version']) is int and r['original']['version']==0,'fragment original metadata')
        need(r['original']['current_alignment']==(('EXACT_NATIVE_ARCHIVE_FIELD_BYTES' if s.grant['mode']=='real_r0_body' else 'EXACT_SYNTHETIC_ARCHIVE_FIELD_BYTES') if r['version']==0 else 'UNKNOWN_TEXT_CHANGED'),'derived projection exact archived field label')
        need(type(r['version']) is int and r['version']>=0 and sha(r['text'].encode())==r['digest'],'node text digest')
        need(type(r['live']) is bool and isinstance(r['lineage'],list),'node lifecycle')
        for ancestor in r['lineage']:need(locate(ancestor['id'])[1] in ('source','target') and ancestor['id']!=r['id'] and ancestor['operation'] in ('split','merge','replacement'),'explicit lineage identity')
        if not r['live']:need(r.get('retirement_reason') in ('split','merge','delete','replacement'),'tombstone reason')
        responsibility=r['responsibility'];need(isinstance(responsibility,dict) and set(responsibility)=={'for_version','status','claims'} and type(responsibility['for_version']) is int and responsibility['for_version']==r['version'] and responsibility['status']=='UNKNOWN' and responsibility['claims']==[],'exact UNKNOWN responsibility; integer version and no extra approval fields')
        if kind=='target':need(r['obligations']==[],'inline pending forbidden');need(set(r['facts'])==set(SCHEMA['domains']) and all(isinstance(f,dict) and set(f)=={'status','reason'} and f['status']=='UNKNOWN' and isinstance(f['reason'],str) for f in r['facts'].values()),'per-domain UNKNOWN no approval extras')
        o=s.manifests[own]['originals'][r['original']['ref']]
        need(o['kind']=='derived_index_projection' and o['provenance']==projection_provenance(s.grant['mode']),'derived projection type, not raw original')
    elif kind=='note':
        need(set(r)=={'id','kind','slot','version','text','digest','prior','about','approval'},'note exact fields/no body facts')
        need(type(r['version']) is int and r['version']>=0 and isinstance(r['text'],str) and sha(r['text'].encode())==r['digest'],'note version/text/digest; present empty string retained')
        approval=r['approval'];need(isinstance(approval,dict) and set(approval)=={'for_note_version','status','claims'} and type(approval['for_note_version']) is int and approval=={'for_note_version':r['version'],'status':'UNKNOWN','claims':[]},'note exact independent UNKNOWN approval; integer version')
        about=r['about'];need(isinstance(about,dict) and about.get('kind') in ('target','owner'),'native note must bind target version zero or owner')
        if about['kind']=='target':
            need(set(about)=={'id','kind','version','digest','locator'},'note about exact version shape')
            need(locate(about['id'])[:2]==(own,'target'),'note about exact owner target')
            need(type(about['version']) is int and about['version']==0,'note target version zero integer')
            s.exact_version(about)
        else:need(about=={'kind':'owner','owner':own} and own in s.owners,'owner note binding only; no target or version claim')
        prior=r['prior']
        if r['version']==0:need(prior is None,'initial note prior')
        else:
            need(isinstance(prior,dict) and set(prior)=={'commit','path','record_sha256','version'},'note prior shape')
            need(OID.fullmatch(prior['commit']) and type(prior['version']) is int and prior['version']==r['version']-1,'note prior version')
            need(isinstance(prior['record_sha256'],str) and re.fullmatch('[0-9a-f]{64}',prior['record_sha256']),'note prior hash')
            need(isinstance(prior['path'],str) and re.fullmatch(re.escape(su_dir(own))+r'/p[0-9]{4}\.json',prior['path']),'note prior page owner')
    elif kind=='coverage':
        bump('coverage_validation_calls')
        need(set(r)=={'id','kind','slot','mode','sources','targets','source_alignment','claim'},'native coverage exact fields')
        need(r['mode']=='native_structural' and r['source_alignment']=='UNKNOWN' and r['claim']=='native_structural_only_not_actual_use','native structural coverage is not approval')
        need(isinstance(r['sources'],list) and 1<=len(r['sources'])<=SCHEMA['native_limits']['coverage_sources'] and isinstance(r['targets'],list) and len(r['targets'])==1,'native coverage bounded nonempty sides')
        for ref,k in [(x,'source') for x in r['sources']]+[(x,'target') for x in r['targets']]:
            need(locate(ref['id'])[0]==own,'cross-owner coverage unsupported');n=validate_span(s,ref,k);need(ref['start']==0 and ref['end']==len(n['text']) and ref['version']==0,'native coverage exact full original version-zero span')


def check_inverse(s,edge):
    rev=s.su(locate(edge['provider'])[0]).get(edge['reverse'])
    need(rev is not None and rev['kind']=='reverse' and (rev['forward'],rev['provider'],rev['consumer'])==(edge['id'],edge['provider'],edge['consumer']),'forward/reverse completeness')

# Native CAS values below are SHA256 provenance, never Git SHA1 OIDs.
NATIVE_ROOT='1c3795a3064ca69cb43a3615107bc9cfc89143c5fdc700c9848defd86f4caf51'
NATIVE_STATE='fixed-fullbook-readonly/v1:'+NATIVE_ROOT
SYNTHETIC_ROOT=hashlib.sha256(b'bounded-su-git-v21-synthetic-scale-only').hexdigest()
SYNTHETIC_STATE='synthetic-scale-only/v1:'+SYNTHETIC_ROOT

def _origin_digest(value,label,allow_upper=False):
    need(isinstance(value,str) and re.fullmatch('[0-9a-fA-F]{64}' if allow_upper else '[0-9a-f]{64}',value),label)


GRANT_KEYS=('format','root','state','native_owner','owner','source_count','target_count','coverage_count','edge_count','note_count','target_note_count','owner_note_count','report_sha256','origin_sha256')
def _member_grant_contract(grant):
    """Host input is authority; a repo-local self-description never mints a grant."""
    need(isinstance(grant,dict) and set(grant)==set(GRANT_KEYS),'external single-owner origin grant exact fields')
    need(grant['format'] in ('host-authenticated-r0-owner/v25','synthetic-scale-single-owner-origin/v1'),'external origin grant format')
    synthetic=grant['format']=='synthetic-scale-single-owner-origin/v1'
    need((grant['root'],grant['state'])==((SYNTHETIC_ROOT,SYNTHETIC_STATE) if synthetic else (NATIVE_ROOT,NATIVE_STATE)),'member provenance root/state')
    uid=grant['native_owner'];own=grant['owner']
    need(isinstance(uid,str) and re.fullmatch(r'SU-[0-9]{6}',uid),'external native owner syntax')
    need(isinstance(own,str) and own==f'SU{int(uid[3:]):02d}' and SU.fullmatch(own),'external canonical owner mapping')
    need(synthetic or 1<=int(uid[3:])<=2079,'R0 member range')
    for field in ('source_count','target_count','coverage_count','edge_count','note_count','target_note_count','owner_note_count'):
        need(type(grant[field]) is int and grant[field]>=0,'external grant integer counts')
    need(1<=grant['source_count']<=SCHEMA['native_limits']['sources'] and 1<=grant['target_count']<=SCHEMA['native_limits']['targets'],'external grant P/T limits')
    need(grant['coverage_count']==grant['target_count'] and max(grant['source_count'],grant['target_count'])<=grant['edge_count']<=grant['source_count']*grant['target_count'],'external grant strict coverage counts')
    need(grant['target_note_count']<=grant['target_count'] and grant['owner_note_count']<=1 and grant['note_count']==grant['target_note_count']+grant['owner_note_count']<=SCHEMA['native_limits']['notes'],'external grant note counts')
    _origin_digest(grant['report_sha256'],'external A report SHA256')
    _origin_digest(grant['origin_sha256'],'external origin SHA256')
    return grant

JOINT_SCOPE=['SU192','SU408','SU1378']
def _grant_contract(grant):
    bump('compact_grant_checks')
    fields={'format','mode','root','state','scope_count','scope_sha256','indexes','origin_sha256'}
    need(isinstance(grant,dict) and set(grant)==fields,'compact external grant exact fields')
    need(grant['format']=='host-accepted-streaming-owner-roots/v25','compact root grant format')
    mode=grant['mode'];need(mode in ('real_r0_body','synthetic_scale_only'),'explicit input mode')
    need((grant['root'],grant['state'])==((NATIVE_ROOT,NATIVE_STATE) if mode=='real_r0_body' else (SYNTHETIC_ROOT,SYNTHETIC_STATE)),'compact grant provenance separation')
    cap=SCHEMA['native_limits']['owners']
    need(type(grant['scope_count']) is int and 1<=grant['scope_count']<=cap,'compact scope count bound')
    _origin_digest(grant['scope_sha256'],'compact scope digest')
    indexes=grant['indexes'];need(isinstance(indexes,dict) and set(indexes)=={'owners','origins','archives','retained'},'exact pinned indexes')
    for name,ref in indexes.items():
        need(isinstance(ref,dict) and set(ref)=={'git_tree','sha256'},'index root reference')
        need(isinstance(ref['git_tree'],str) and OID.fullmatch(ref['git_tree']),'index Git tree')
        _origin_digest(ref['sha256'],'index root SHA256')
    need(grant['origin_sha256']==indexes['origins']['sha256'],'origin index root SHA256 alias')
    size=len(canonical(grant));need(size<=SCHEMA['root_grant_bytes_max'],'bounded compact grant')
    bump('compact_grant_checked_bytes',size)
    return grant

def _grant_key(grant):
    _grant_contract(grant);return canonical(grant)

def _pure_tree(paths):
    """Pure deterministic tree commitment. Caller decides whether inputs are trusted."""
    entries={};groups={}
    for path,h in paths.items():
        head,*tail=path.split('/');groups.setdefault(head,[]).append(('/'.join(tail),h))
    for name,rows in groups.items():
        if rows[0][0]=='':
            need(len(rows)==1,'index file/directory collision');entries[name]=('100644',rows[0][1])
        else:
            need(all(tail for tail,_ in rows),'index file/directory collision')
            child,_=_pure_tree(dict(rows));entries[name]=('40000',child)
    raw=tree_bytes(entries);return oid('tree',raw),sha(raw)

def prepare_grant(scope,owner_grants,origins,archives,mode='real_r0_body'):
    """Produce candidate commitments, NOT independent native-source attestation.

    Real3 callers must separately authenticate each exact input member grant.
    Synthetic output is permanently labeled scale-only and cannot enter real3.
    """
    need(mode in ('real_r0_body','synthetic_scale_only'),'explicit input mode')
    scope_raw=scope_bytes(scope);need(len(scope)<= (3 if mode=='real_r0_body' else 2079),'scope cap')
    need(isinstance(owner_grants,dict) and isinstance(origins,dict) and isinstance(archives,dict),'input maps')
    need(set(owner_grants)==set(origins)==set(archives)==set(scope),'exact input owner membership')
    if mode=='real_r0_body':need(set(scope)<=set(JOINT_SCOPE),'real3 exact evidenced owner subset')
    paths={name:{} for name in ('owners','origins','archives')}
    for su in scope:
        member=owner_grants[su];_member_grant_contract(member)
        want='host-authenticated-r0-owner/v25' if mode=='real_r0_body' else 'synthetic-scale-single-owner-origin/v1'
        need(member['owner']==su and member['format']==want,'member mode/key mismatch')
        origin=origins[su];_member_origin_contract(origin,member['origin_sha256'],[su],member)
        paths['owners'][owner_grant_path(su)[7:]]=oid('blob',canonical(member))
        paths['origins'][origin_path(su)[8:]]=oid('blob',canonical(origin))
        need(isinstance(archives[su],dict) and set(archives[su])==set(ARCHIVE_KINDS),'member archive kinds')
        for kind,raw in archives[su].items():
            d=origin['archives'][kind]
            need(type(raw) is bytes and len(raw)==d['byte_length'] and sha(raw)==d['sha256'],'candidate archive identity')
            paths['archives'][archive_storage_path(su,kind)[9:]]=oid('blob',raw)
    roots={}
    for name,ps in paths.items():
        h,digest=_pure_tree(ps);roots[name]={'git_tree':h,'sha256':digest}
    grant={'format':'host-accepted-streaming-owner-roots/v25','mode':mode,'root':NATIVE_ROOT if mode=='real_r0_body' else SYNTHETIC_ROOT,'state':NATIVE_STATE if mode=='real_r0_body' else SYNTHETIC_STATE,'scope_count':len(scope),'scope_sha256':sha(scope_raw),'indexes':roots,'origin_sha256':roots['origins']['sha256']}
    _grant_contract(grant);return grant

class OwnerIndex:
    """No scope list or aggregate grant. Each membership proof follows one radix path."""
    def __init__(self,r,commit,grant):
        _grant_contract(grant);self.r=r;self.commit=commit;self.grant=grant;self.members={};self.origins={}
        top=r.tree(r.root(commit));self.roots={}
        for name,ref in grant['indexes'].items():
            need(top.get(name)==('40000',ref['git_tree']),'pinned index root differs from host grant')
            raw=r.get(ref['git_tree'],'tree','index_root')
            need(sha(raw)==ref['sha256'],'pinned index root SHA256')
            self.roots[name]=ref['git_tree'];bump('index_root_verifications')
    def _read(self,name,su,filename,category):
        su_groups(su);h=self.roots[name]
        for part in owner_radix_path(su).split('/'):
            tree=self.r.tree(h);need(part in tree and tree[part][0]=='40000','owner absent from authenticated radix scope')
            h=tree[part][1];bump('owner_radix_hops')
        tree=self.r.tree(h);need(filename in tree and tree[filename][0]=='100644','owner indexed file missing')
        return self.r.get(tree[filename][1],'blob',category)
    def member_grant(self,su):
        if su not in self.members:
            raw=self._read('owners',su,'grant.json','owner_grant');member=decode(raw);_member_grant_contract(member)
            want='host-authenticated-r0-owner/v25' if self.grant['mode']=='real_r0_body' else 'synthetic-scale-single-owner-origin/v1'
            need(member['owner']==su and member['format']==want and (member['root'],member['state'])==(self.grant['root'],self.grant['state']),'radix member owner/mode/root')
            self.members[su]=member;bump('owner_grant_leaf_reads');bump('owner_grant_logical_bytes',len(raw))
        return self.members[su]
    def __contains__(self,su):
        self.member_grant(su);return True
    def origin(self,su):
        if su not in self.origins:
            member=self.member_grant(su);raw=self._read('origins',su,'origin.json','origin')
            value=decode(raw);_member_origin_contract(value,member['origin_sha256'],[su],member)
            self.origins[su]=value;bump('origin_access_calls');bump('origin_owner_reads');bump('origin_logical_bytes',len(raw))
        return self.origins[su]
    def enumerate_scope(self):
        bump('scope_enumeration_calls');found=[];visited_paths=0
        def walk(h,prefix=()):
            nonlocal visited_paths
            visited_paths+=1;need(visited_paths<=16*self.grant['scope_count']+1,'owner index traversal budget')
            for name,(mode,child) in self.r.tree(h).items():
                if re.fullmatch(r'u[0-9]{2}',name):
                    need(mode=='40000','owner leaf directory')
                    digits=''.join(prefix)+(name[1:]);su=f'SU{int(digits):02d}'
                    need(owner_radix_path(su)=='/'.join(prefix+(name,)),'noncanonical radix owner path')
                    leaf=self.r.tree(child);need(set(leaf)=={'grant.json'} and leaf['grant.json'][0]=='100644','exact grant leaf namespace')
                    need(len(found)<self.grant['scope_count'],'extra owner beyond committed scope count')
                    self.member_grant(su);found.append(su)
                else:
                    need(mode=='40000' and re.fullmatch(r'[0-9]{2}',name) and len(prefix)<15,'bounded radix directory')
                    walk(child,prefix+(name,))
        walk(self.roots['owners']);found.sort(key=lambda su:(len(su),su))
        need(len(found)==len(set(found))==self.grant['scope_count'],'scope count/collision')
        need(sha(scope_bytes(found))==self.grant['scope_sha256'],'complete scope commitment')
        return found

def _archive_descriptor_contract(su,kind,d):
    keys={'kind','path','sha256','byte_length','media_type','representation'}
    need(kind in ARCHIVE_KINDS and isinstance(d,dict) and set(d)==keys,'archive descriptor exact fields')
    need(d['kind']==kind and d['path']==archive_path(su,kind),'archive descriptor fixed kind/path')
    need(d['media_type']=='application/json' and d['representation']==ARCHIVE_REPRESENTATIONS[kind],'archive descriptor representation')
    _origin_digest(d['sha256'],'archive descriptor raw SHA256')
    need(type(d['byte_length']) is int and 0<d['byte_length']<=SCHEMA['object_bytes_max'],'archive descriptor bounded raw byte length')

def _archive_ref_contract(su,kind,ref):
    keys={'kind','path','sha256','byte_length','media_type','representation','commit','git_blob','origin_sha256','provenance','storage_path'}
    need(isinstance(su,str) and SU.fullmatch(su) and isinstance(ref,dict) and set(ref)==keys,'manifest archive exact reference')
    _archive_descriptor_contract(su,kind,{k:ref[k] for k in keys-{'commit','git_blob','origin_sha256','provenance','storage_path'}})
    need(isinstance(ref['commit'],str) and OID.fullmatch(ref['commit']) and isinstance(ref['git_blob'],str) and OID.fullmatch(ref['git_blob']),'archive typed Git reference')
    _origin_digest(ref['origin_sha256'],'archive host origin grant')
    need(ref['storage_path']==archive_storage_path(su,kind),'archive bounded physical path')
    need(ref['provenance'] in ('host_attested_fixed_su_raw_no_approval','synthetic_test_raw_no_native_provenance'),'archive provenance does not confer approval')

def _member_origin_contract(origin,expected_sha256,scope,expected_grant):
    """Validate externally granted raw/field mapping, not the old R2 database."""
    _member_grant_contract(expected_grant);grant=expected_grant
    need(expected_sha256==grant['origin_sha256'],'origin SHA256 differs from external grant')
    _origin_digest(expected_sha256,'explicit host origin SHA256 required')
    need(isinstance(origin,dict) and set(origin)=={'format','source','selection','archives','records','coverage','notes','owner_note'},'origin exact envelope')
    raw=canonical(origin);need(len(raw)<=SCHEMA['native_limits']['origin_bytes'] and sha(raw)==expected_sha256,'host origin-map canonical SHA256/limit')
    synthetic=grant['format']=='synthetic-scale-single-owner-origin/v1'
    need(origin['format']==('synthetic-scale-su-origin/v1' if synthetic else 'native-complete-su-origin/r0-stream-v25'),'origin format/mode')
    legacy=False
    source=origin['source']
    if synthetic:
        source_keys={'root','state','manifest_sha256','launcher_sha256','reader_sha256','decoder_sha256','source_owner_sha256','native_target_sha256','source_basis_sha256','native_status_exact_old_document','inventory_report_sha256','field_census_sha256','expanded_source_sha256','directory_sha256','authenticated_directory_entry_sha256'}
        need(isinstance(source,dict) and set(source)==source_keys,'synthetic source fields')
        need(source['inventory_report_sha256']==grant['report_sha256'],'synthetic report binding')
        for key in source_keys-{'root','state','native_status_exact_old_document'}:_origin_digest(source[key],'synthetic source digest',key=='source_basis_sha256')
    else:
        required={'root','state','report_sha256','owner_receipt_sha256','expanded_source_sha256','source_owner_sha256','native_target_sha256','pins','source_basis_sha256','native_status_exact_old_document','responsibility','approval','actual_use'}
        optional={'field_census_sha256','prior_archive_receipt_sha256','metadata_owner_receipt_sha256'}
        need(isinstance(source,dict) and required<=set(source)<=required|optional,'R0 source exact provenance')
        need(source['report_sha256']==grant['report_sha256'],'R0 frozen report binding')
        need(all(source[x]=='UNKNOWN' for x in ('responsibility','approval','actual_use')),'R0 no approval inheritance')
        for key in (required|optional)&set(source)-{'root','state','pins','native_status_exact_old_document','responsibility','approval','actual_use'}:_origin_digest(source[key],'R0 source digest '+key,key=='source_basis_sha256')
        need(isinstance(source['pins'],dict) and 1<=len(source['pins'])<=32,'R0 exact code pins')
        for key,value in source['pins'].items():need(type(key) is str and 1<=len(key)<=128,'R0 pin name');_origin_digest(value,'R0 pin digest')
    need(source['root']==grant['root'] and source['state']==grant['state'],'origin exact member provenance root/state')
    need(isinstance(source['native_status_exact_old_document'],str) and 0<len(source['native_status_exact_old_document'])<=64,'historical native status string only')
    selection=origin['selection']
    need(isinstance(selection,dict) and set(selection)=={'native_owner','owner','source_ids','target_ids','scope'},'origin exact selection')
    need(selection['native_owner']==grant['native_owner'] and selection['owner']==grant['owner'] and scope==[grant['owner']],'one externally authorized complete native owner')
    need(selection['scope']==('SYNTHETIC_SCALE_ONLY_NO_NATIVE_PROVENANCE' if synthetic else SCHEMA['native_scope']),'explicit real/synthetic member scope')
    for field,tag,key in (('source_ids','P','sources'),('target_ids','T','targets')):
        values=selection[field];need(isinstance(values,list) and len(values)==grant['source_count' if key=='sources' else 'target_count'] and len(values)<=SCHEMA['native_limits'][key],'complete fixed SU exact count/cap')
        need(all(isinstance(v,str) and re.fullmatch(re.escape(grant['native_owner'])+'-'+tag+'[0-9]{4}',v) and int(v[-4:])>0 for v in values),'original native P/T spelling, no X overlay')
        need(values==sorted(set(values)),'canonical unique complete native IDs')
    archives=origin['archives'];need(isinstance(archives,dict) and set(archives)==set(ARCHIVE_KINDS),'origin exact archive kinds')
    for kind,d in archives.items():
        _archive_descriptor_contract(grant['owner'],kind,d)
        field='source_owner_sha256' if kind=='source_owner' else 'native_target_sha256'
        need(d['sha256']==source[field],'archive raw SHA256 bound to host-authenticated old root entry')
    records=origin['records'];selected=selection['source_ids']+selection['target_ids']
    need(isinstance(records,dict) and set(records)==set(selected),'origin exact complete record mapping')
    for ident,mapping in records.items():
        need(isinstance(mapping,dict) and set(mapping)=={'kind','text_sha256','text_utf8_bytes','original_span','native_locator'},'origin exact record map')
        kind=locate(ident)[1];need(mapping['kind']==kind,'origin native record kind')
        _origin_digest(mapping['text_sha256'],'origin exact text SHA256')
        need(type(mapping['text_utf8_bytes']) is int and 0<=mapping['text_utf8_bytes']<=8192,'origin text byte length')
        span=mapping['original_span'];need(isinstance(span,list) and len(span)==2 and all(type(i) is int for i in span) and 0<=span[0]<=span[1]<2**31,'local Unicode projection span')
        loc=mapping['native_locator'];fields={'representation','json_pointer','record_index'}|(({'compact_json_pointer'} if legacy else {'compact_json_pointer','source_line_json_pointer','diplomatic_json_pointer','patch_ids_json_pointer','split_part_json_pointer'}) if kind=='source' else set())
        need(isinstance(loc,dict) and set(loc)==fields,'native logical locator exact shape')
        need(type(loc['record_index']) is int and 0<=loc['record_index']<SCHEMA['native_limits']['sources' if kind=='source' else 'targets'],'native logical array index')
        pointer=loc['json_pointer'];need(isinstance(pointer,str) and len(pointer)<=160,'native logical pointer bound')
        if kind=='source':
            need(loc['representation']=='authenticated_expanded_source' and re.fullmatch(r'/source_paragraphs/(0|[1-9][0-9]*)/critical',pointer),'derived expanded-source critical locator')
            need(isinstance(loc['compact_json_pointer'],str) and re.fullmatch(r'/rows/(0|[1-9][0-9]*)/1',loc['compact_json_pointer']),'authenticated compact critical row locator')
            row_base=loc['compact_json_pointer'][:-1]
            for field,slot in (() if legacy else (('source_line_json_pointer',0),('diplomatic_json_pointer',2),('patch_ids_json_pointer',3),('split_part_json_pointer',4))):
                need(loc[field]==row_base+str(slot),'archival-only source row coordinate')
        else:need(loc['representation']=='native_target_json' and re.fullmatch(r'/segments/(0|[1-9][0-9]*)/en',pointer),'native target logical field locator')
        need(int(pointer.split('/')[2])==loc['record_index'],'native locator pointer/index agreement')
    coverage=origin['coverage'];need(isinstance(coverage,list) and len(coverage)==len(selection['target_ids'])==grant['coverage_count'],'native coverage exact target count')
    need(all(isinstance(row,dict) and set(row)=={'target_id','source_ids'} for row in coverage),'origin coverage shape')
    need([row['target_id'] for row in coverage]==selection['target_ids'],'origin coverage target order/identity')
    used=set()
    for row in coverage:
        refs=row['source_ids'];need(isinstance(refs,list) and 1<=len(refs)<=SCHEMA['native_limits']['coverage_sources'] and all(isinstance(v,str) and v in selection['source_ids'] for v in refs) and len(refs)==len(set(refs)),'native coverage source identities/order')
        used.update(refs)
    need(used==set(selection['source_ids']),'fixed old strict coverage complete source membership; never drop P nodes')
    need(sum(len(row['source_ids']) for row in coverage)==grant['edge_count'],'externally granted exact coverage edge count')
    notes=origin['notes'];need(isinstance(notes,dict) and set(notes)==set(selection['target_ids']),'complete per-target notes census')
    note_ids=set()
    for target,spec in notes.items():
        need(isinstance(spec,dict),'notes census item shape')
        base={'presence','type','json_pointer'}
        pointer=records[target]['native_locator']['json_pointer'][:-3]+'/notes'
        need(spec.get('json_pointer')==pointer,'native note exact same target logical field')
        if spec.get('type') in ('missing','null'):
            need(set(spec)==base and spec['presence']==('absent' if spec['type']=='missing' else 'present'),'distinct missing/null note disposition')
        else:
            need(set(spec)==base|{'id','text_sha256','text_utf8_bytes'} and spec.get('type')=='string' and spec['presence']=='present','only native string notes are typed; unsupported shape blocks')
            need(isinstance(spec['id'],str) and ID.fullmatch(spec['id']) is not None and locate(spec['id'])[:2]==(grant['owner'],'note') and spec['id'] not in note_ids,'unique local typed note identity')
            note_ids.add(spec['id']);_origin_digest(spec['text_sha256'],'native note string SHA256')
            need(type(spec['text_utf8_bytes']) is int and 0<=spec['text_utf8_bytes']<=8192,'native string note UTF8 byte length including empty')
    need(len(note_ids)==grant['target_note_count'],'externally granted target note count')
    spec=origin['owner_note'];base={'presence','type','json_pointer'}
    need(isinstance(spec,dict) and spec.get('json_pointer')=='/notes','owner notes exact native field')
    if spec.get('type') in ('missing','null'):
        need(set(spec)==base and spec['presence']==('absent' if spec['type']=='missing' else 'present'),'distinct owner missing/null note disposition')
    else:
        need(set(spec)==base|{'id','text_sha256','text_utf8_bytes'} and spec.get('type')=='string' and spec['presence']=='present','only native owner string note supported')
        need(spec['id']==grant['owner']+':note:9999' and spec['id'] not in note_ids,'reserved local owner note identity')
        note_ids.add(spec['id']);_origin_digest(spec['text_sha256'],'native owner note SHA256')
        need(type(spec['text_utf8_bytes']) is int and 0<=spec['text_utf8_bytes']<=8192,'owner note UTF8 byte length including empty')
    need(int(spec['type']=='string')==grant['owner_note_count'],'externally granted owner note count')
    need(len(note_ids)==grant['note_count'] and len(note_ids)<=SCHEMA['native_limits']['notes'],'externally granted typed note count/limit')
    return origin

def _decode_archive(raw):
    """Parse for bounded field verification; never reserialize or replace raw bytes."""
    from decimal import Decimal
    def unique(pairs):
        out={}
        for key,value in pairs:need(key not in out,'raw archive duplicate JSON key');out[key]=value
        return out
    def nonfinite(value):raise Rejected('raw archive nonfinite JSON scalar')
    try:obj=json.loads(raw.decode('utf-8','strict'),object_pairs_hook=unique,parse_float=Decimal,parse_constant=nonfinite)
    except (ValueError,UnicodeError,RecursionError) as e:raise Rejected('raw archive invalid UTF8/JSON') from e
    seen=0
    def visit(value,depth=0):
        nonlocal seen
        seen+=1;need(seen<=65536 and depth<=64,'raw archive JSON shape resource limit')
        if isinstance(value,dict):
            for key,child in value.items():
                try:key.encode('utf-8','strict')
                except UnicodeError as e:raise Rejected('raw archive invalid key Unicode') from e
                visit(child,depth+1)
        elif isinstance(value,list):
            for child in value:visit(child,depth+1)
        elif isinstance(value,str):
            try:value.encode('utf-8','strict')
            except UnicodeError as e:raise Rejected('raw archive invalid string Unicode') from e
        else:need(value is None or type(value) in (bool,int,Decimal),'raw archive JSON scalar type')
    visit(obj);bump('archive_decode_calls');bump('archive_decoded_bytes',len(raw));return obj

def _verify_archive_fields(raws,origin):
    """Verify the fixed raw shape and full P/T/note inventory, not the old DB."""
    need(set(raws)==set(ARCHIVE_KINDS),'raw archive input kinds')
    parsed={}
    for kind,raw in raws.items():
        desc=origin['archives'][kind]
        need(type(raw) is bytes and len(raw)==desc['byte_length'] and sha(raw)==desc['sha256'],'archive raw exact SHA256/length')
        parsed[kind]=_decode_archive(raw)
    compact=parsed['source_owner'];doc=parsed['native_target'];selection=origin['selection'];uid=selection['native_owner']
    need(isinstance(compact,dict) and set(compact)=={'domain','kind','encoding','shell','rows'},'supported complete source compact envelope')
    encoding='rows:[source_line,critical,diplomatic_or_null_same,patch_ids,split_part];record_index=trim_start+position;paragraph_id=SU-P+nonblank_ordinal'
    need(compact['domain']=='fixed-fullbook-readonly/v1' and compact['kind']=='compact-source' and compact['encoding']==encoding,'supported fixed source compact encoding')
    shell=compact['shell'];rows=compact['rows']
    need(isinstance(shell,dict) and shell.get('domain')=='fixed-independent-source-owner/v1' and shell.get('certificate_contract')=='fixed-independent-source-certificate/v1','source shell fixed certificate representation')
    unit=shell.get('source_unit');span=shell.get('span');heading=shell.get('heading')
    need(isinstance(unit,dict) and unit.get('source_unit_id')==uid and isinstance(span,dict) and isinstance(heading,dict),'archive source owner/shell')
    need(isinstance(rows,list) and len(rows)<=SCHEMA['native_limits']['source_rows'],'source compact row bound')
    trim=span.get('trim_start');end=span.get('trim_end')
    need(type(trim) is int and type(end) is int and 0<=trim<=end and end-trim==len(rows),'compact row count/global span')
    need(type(heading.get('critical')) is str,'source heading critical type')
    texts={};basis=[heading['critical']];pids=[]
    for j,row in enumerate(rows):
        need(isinstance(row,list) and len(row)==5,'supported compact five-slot row')
        line,critical,diplomatic,patches,part=row
        need(type(line) is int and line>0 and type(critical) is str and (diplomatic is None or type(diplomatic) is str) and type(part) is int and part>=0,'compact row scalar types')
        need('\n' not in critical and '\r' not in critical and (diplomatic is None or '\n' not in diplomatic and '\r' not in diplomatic),'compact line text domain')
        need(isinstance(patches,list) and all(type(x) is str and x for x in patches) and len(patches)==len(set(patches)),'compact patch identifiers')
        basis.append(critical)
        if critical=='':continue  # Exact legacy expansion: whitespace is NOT skipped.
        i=len(pids);ident=f'{uid}-P{i+1:04d}';pids.append(ident);texts[ident]=critical
        need(ident in origin['records'],'raw P missing from complete origin')
        loc=origin['records'][ident]['native_locator']
        expected_locator={'representation':'authenticated_expanded_source','json_pointer':f'/source_paragraphs/{i}/critical','record_index':i,'compact_json_pointer':f'/rows/{j}/1','source_line_json_pointer':f'/rows/{j}/0','diplomatic_json_pointer':f'/rows/{j}/2','patch_ids_json_pointer':f'/rows/{j}/3','split_part_json_pointer':f'/rows/{j}/4'}
        if origin['format']=='native-complete-su-origin/v1':
            expected_locator={k:v for k,v in expected_locator.items() if k in ('representation','json_pointer','record_index','compact_json_pointer')}
        need(loc==expected_locator,'raw compact exact versioned locator')
    need(pids==selection['source_ids'] and type(unit.get('paragraph_count')) is int and unit['paragraph_count']==len(pids),'raw complete P inventory/count')
    source_basis=sha('\n'.join(basis).encode('utf-8')).upper()
    need(unit.get('critical_sha256')==source_basis and origin['source']['source_basis_sha256']==source_basis,'raw source heading/body LF basis')
    need(isinstance(doc,dict) and doc.get('source_unit_id')==uid and type(doc.get('schema_version')) is int and doc['schema_version']==1,'supported native target owner/schema')
    need(doc.get('source_critical_sha256')==source_basis and doc.get('status')==origin['source']['native_status_exact_old_document'],'native target basis/status provenance')
    segments=doc.get('segments');need(isinstance(segments,list) and len(segments)==len(selection['target_ids']),'raw complete target count')
    tids=[];coverage=[];note_values={};allowed_notes=set();used=set();last_source=0
    for i,segment in enumerate(segments):
        need(isinstance(segment,dict),'native target segment shape')
        ident=segment.get('target_segment_id');need(ident==f'{uid}-T{i+1:04d}','fixed strict target ID/order')
        tids.append(ident);need(ident in origin['records'],'raw target missing from complete origin')
        loc=origin['records'][ident]['native_locator']
        need(loc=={'representation':'native_target_json','json_pointer':f'/segments/{i}/en','record_index':i},'raw target field exact locator')
        value=segment.get('en');need(type(value) is str,'native target en string');texts[ident]=value
        refs=segment.get('source_paragraph_ids')
        need(isinstance(refs,list) and 1<=len(refs)<=SCHEMA['native_limits']['coverage_sources'] and all(type(x) is str and x in pids for x in refs) and len(refs)==len(set(refs)),'raw target structural coverage')
        nums=[int(x[-4:]) for x in refs];need(nums==sorted(nums) and nums[0]>=last_source,'fixed strict coverage source order');last_source=nums[-1];used.update(refs)
        coverage.append({'target_id':ident,'source_ids':refs})
        if 'source_critical_sha256' in segment:need(len(refs)==1 and segment['source_critical_sha256']==sha(texts[refs[0]].encode()).upper(),'native segment source basis')
        spec=origin['notes'][ident];pointer=f'/segments/{i}/notes'
        if 'notes' not in segment:need(spec=={'presence':'absent','type':'missing','json_pointer':pointer},'raw missing notes exact census')
        else:
            allowed_notes.add(pointer);value=segment['notes']
            if value is None:need(spec=={'presence':'present','type':'null','json_pointer':pointer},'raw null notes exact census')
            else:
                need(type(value) is str,'unsupported native notes shape blocks complete typed import')
                need(spec['type']=='string' and spec['presence']=='present' and spec['json_pointer']==pointer,'raw string notes exact census')
                encoded=value.encode('utf-8');need(spec['text_sha256']==sha(encoded) and spec['text_utf8_bytes']==len(encoded),'raw note string exact bytes including empty')
                note_values[ident]=value
    need(tids==selection['target_ids'] and used==set(pids) and coverage==origin['coverage'],'raw complete target IDs/strict structural coverage')
    owner_spec=origin['owner_note'];owner_value=None
    if 'notes' not in doc:need(owner_spec=={'presence':'absent','type':'missing','json_pointer':'/notes'},'raw missing owner note census')
    else:
        allowed_notes.add('/notes');owner_value=doc['notes']
        if owner_value is None:need(owner_spec=={'presence':'present','type':'null','json_pointer':'/notes'},'raw null owner note census')
        else:
            need(type(owner_value) is str and owner_spec['type']=='string' and owner_spec['presence']=='present','unsupported native owner note shape blocks typed import')
            encoded=owner_value.encode('utf-8');need(owner_spec['text_sha256']==sha(encoded) and owner_spec['text_utf8_bytes']==len(encoded),'raw owner note exact string bytes')
    # A note outside the supported target/owner-field contract is not silently archived
    # and then counted as an editable typed note.
    def check_note_locations(value,prefix,allow):
        if isinstance(value,dict):
            for key,child in value.items():
                pointer=prefix+'/'+key.replace('~','~0').replace('/','~1')
                if key in ('note','notes'):need(pointer in allow,'unsupported native notes location blocks typed import')
                check_note_locations(child,pointer,allow)
        elif isinstance(value,list):
            for i,child in enumerate(value):check_note_locations(child,prefix+'/'+str(i),allow)
    check_note_locations(compact,'',set());check_note_locations(doc,'',allowed_notes)
    for ident,value in texts.items():
        encoded=value.encode('utf-8');mapping=origin['records'][ident]
        need(sha(encoded)==mapping['text_sha256'] and len(encoded)==mapping['text_utf8_bytes'],'raw archived field digest/length equals origin')
    bump('native_archive_sets_verified');bump('native_target_notes_census_verified',len(tids));bump('native_owner_notes_census_verified');bump('native_notes_census_verified',len(tids)+1)
    return {'text':texts,'notes':note_values,'owner_note':owner_value}

def _verify_origin_records(snapshot,origin,original_texts,origin_sha256,baseline,archive_fields=None):
    selection=origin['selection'];su=selection['owner'];rows=snapshot.su(su);manifest=snapshot.manifests[su]
    mapped=origin['records'];note_specs=origin['notes']
    body={i:r for i,r in rows.items() if r['kind'] in ('source','target')}
    links=[r for r in rows.values() if r['kind']=='coverage'];notes={r['id']:r for r in rows.values() if r['kind']=='note'}
    need(set(body)==set(mapped) and len(rows)==len(body)+len(links)+len(notes),'exact complete SU records; no hidden relationships')
    native_text={}
    for kind,field in (('source','source_ids'),('target','target_ids')):
        original=manifest['originals'][kind]
        need(original['kind']=='derived_index_projection' and original['provenance']==projection_provenance(snapshot.grant['mode']) and original['origin_sha256']==origin_sha256,'derived projection host grant/provenance')
        text=original_texts[(original['commit'],original['path'])];parts=[];offset=0
        for ident in selection[field]:
            node=body[ident];mapping=mapped[ident];a,z=mapping['original_span']
            need(node['original']['ref']==kind and node['original']['span']==[a,z] and a==offset and z<=len(text),'exact local projection Unicode span')
            need(node['order']==mapping['native_locator']['record_index'],'native node original logical array order')
            value=text[a:z];encoded=value.encode('utf-8')
            need(len(encoded)==mapping['text_utf8_bytes'] and sha(encoded)==mapping['text_sha256'],'host-granted native text exact bytes')
            if archive_fields is not None:need(value==archive_fields['text'][ident],'projection exactly equals raw archived field')
            native_text[ident]=value;parts.append(value);offset=z+1
            if baseline:need(node['version']==0 and node['prior'] is None,'origin baseline node version zero')
            if node['version']==0:need(node['text']==value and node['digest']==mapping['text_sha256'],'origin baseline node exact field text')
        need(text==''.join(value+'\n' for value in parts),'complete LF-separated index projection; no extra fields')
    need(len(links)==len(origin['coverage']),'native structural coverage exact count')
    by_target={}
    for link in links:
        target=link['targets'][0]['id'];need(target not in by_target,'one native structural relation per target');by_target[target]=link
    for declared in origin['coverage']:
        target=declared['target_id'];need(target in by_target,'native coverage target missing');link=by_target[target]
        need([ref['id'] for ref in link['sources']]==declared['source_ids'],'native coverage exact ordered source IDs')
        for ref in link['sources']+link['targets']:
            ident=ref['id'];need(ident in mapped and ref['version']==0 and ref['digest']==mapped[ident]['text_sha256'] and ref['start']==0 and ref['end']==len(native_text[ident]),'native coverage whole authenticated field version')
    expected_notes={spec['id']:target for target,spec in note_specs.items() if spec['type']=='string'}
    if origin['owner_note']['type']=='string':expected_notes[origin['owner_note']['id']]=None
    need(set(notes)==set(expected_notes),'complete typed notes exactly equal all string fields; no invented missing/null notes')
    for noteid,target in expected_notes.items():
        spec=note_specs[target] if target is not None else origin['owner_note'];note=notes[noteid]
        if baseline:need(note['version']==0 and note['prior'] is None,'native baseline note version zero')
        first=note if note['version']==0 else snapshot.exact_note_version_prior({'id':noteid,'version':0,'digest':spec['text_sha256']})
        need(first['version']==0 and first['prior'] is None and len(first['text'].encode('utf-8'))==spec['text_utf8_bytes'] and sha(first['text'].encode('utf-8'))==spec['text_sha256'],'native note original string exact bytes')
        if archive_fields is not None:need(first['text']==(archive_fields['notes'][target] if target is not None else archive_fields['owner_note']),'note v0 exactly equals archived native string')
        about=note['about']
        need(about==first['about'],'native note immutable original binding')
        if target is not None:need(about['id']==target and about['kind']=='target' and type(about['version']) is int and about['version']==0 and about['digest']==mapped[target]['text_sha256'],'native note immutable exact original target binding')
        else:need(about=={'kind':'owner','owner':su},'native note immutable owner binding; no invented target')
    bump('native_origin_records_verified',len(body)+len(notes));bump('native_origin_maps_verified')

def _build_initial(r,models,originals,expected_scope,origin_map,expected_origin_sha256,archives,expected_grant,owner_grants):
    raise Rejected('v25 requires build_initial_streaming_session')
    _grant_contract(expected_grant);mode=expected_grant['mode']
    fmt='native-complete-owner-set-origin/v1' if mode=='real_r0_body' else 'synthetic-scale-owner-set-origin/v1'
    need(isinstance(origin_map,dict) and set(origin_map)=={'format','owners'} and origin_map['format']==fmt,'initial origin input mode')
    need(expected_origin_sha256==expected_grant['origin_sha256'],'external origin index digest')
    need(prepare_grant(expected_scope,owner_grants,origin_map['owners'],archives,mode)==expected_grant,'initial inputs differ from externally accepted root grant')
    scope=canonical(scope_descriptor(expected_grant))
    need(set(models)==set(originals)==set(expected_scope),'external initial scope mismatch')
    need(all(set(raws)=={'source','target'} for raws in originals.values()),'original kinds')
    originals_blobs={'grant.json':r.stage('blob',canonical(expected_grant))}
    for su in expected_scope:
        originals_blobs[owner_grant_path(su)]=r.stage('blob',canonical(owner_grants[su]))
        originals_blobs[origin_path(su)]=r.stage('blob',canonical(origin_map['owners'][su]))
        for kind,b in archives[su].items():originals_blobs[archive_storage_path(su,kind)]=r.stage('blob',b)
    for su,raws in originals.items():
        for kind,b in raws.items():originals_blobs[original_path(su,kind)]=r.stage('blob',b)
    raw_tree=r.update_tree(None,originals_blobs);raw_anchor=r.stage('commit',commit_bytes(raw_tree,None,'explicit '+mode+' immutable archives and origin objects; no approval inheritance'))
    archive_refs={su:{kind:{**copy.deepcopy(d),'storage_path':archive_storage_path(su,kind),'commit':raw_anchor,'git_blob':originals_blobs[archive_storage_path(su,kind)],'origin_sha256':owner_grants[su]['origin_sha256'],'provenance':archive_provenance(mode)} for kind,d in origin_map['owners'][su]['archives'].items()} for su in expected_scope}
    refs_by_su={};node_changes={'schema.json':r.stage('blob',canonical(SCHEMA)),'scope.json':r.stage('blob',scope)}
    node_map={};node_routes={}
    for su,rows in models.items():
        refs={}
        for kind,b in originals[su].items():refs[kind]={'kind':'derived_index_projection','provenance':projection_provenance(mode),'origin_sha256':owner_grants[su]['origin_sha256'],'commit':raw_anchor,'path':original_path(su,kind),'git_blob':originals_blobs[original_path(su,kind)],'sha256':sha(b),'byte_length':len(b),'media_type':'text/plain;charset=utf-8'}
        refs_by_su[su]=refs;nodes=[n for n in rows if n['kind'] in ('source','target')]
        need(all(n['version']==0 and n['prior'] is None for n in nodes),'genesis version zero')
        need(all(n['version']==0 and n['prior'] is None for n in rows if n['kind']=='note'),'genesis note version zero')
        node_map.update({n['id']:n for n in nodes})
        encoded=encode_su(su,nodes,refs,archives=archive_refs[su]);node_routes[su]=decode(encoded[manifest_path(su)])
        for path,b in encoded.items():node_changes[path]=r.stage('blob',b)
    version_tree=r.update_tree(raw_tree,node_changes)
    version_anchor=r.stage('commit',commit_bytes(version_tree,raw_anchor,mode+' complete fixed owner initial mapped versions; not legacy revision history'))
    changes={};located=0
    for su,rows in copy.deepcopy(models).items():
        for row in rows:
            refs_to_bind=version_refs(row)
            for ref in refs_to_bind:
                own,kind,slot,pg=locate(ref['id']);n=node_map[ref['id']]
                need(n['version']==ref['version'] and n['digest']==ref['digest'],'initial exact version reference')
                pg=route_page(node_routes[own],ref['id']);ref['locator']={'commit':version_anchor,'page':pg,'record_sha256':sha(canonical(n)),'owner':own};located+=1
        for path,b in encode_su(su,rows,refs_by_su[su],initial_anchor=version_anchor,archives=archive_refs[su]).items():
            if oid('blob',b)!=node_changes.get(path):changes[path]=r.stage('blob',b)
    tree=r.update_tree(version_tree,changes);commit=r.stage('commit',commit_bytes(tree,version_anchor,'host admitted bounded radix owner-set baseline; provenance mode in grant; not whole book'))
    admission=cold(r,commit,expected_scope,expected_origin_sha256=expected_origin_sha256,require_origin_baseline=True,expected_grant=expected_grant);r.flush();r.cas(commit,None)
    return {'anchor':raw_anchor,'version_anchor':version_anchor,'commit':commit,'admission':admission,'initial_locators':located,'origin_sha256':expected_origin_sha256,'scope':public_scope(expected_grant)}


def build_initial(r,models,originals,expected_scope,*,origin_map,expected_origin_sha256,archives,expected_grant,owner_grants):
    with r.integrity_operation():
        code_pin()
        return _build_initial(r,models,originals,expected_scope,origin_map,expected_origin_sha256,archives,expected_grant,owner_grants)

def authenticate(parent,request,code,schema):
    check_pins(code,schema);need(OID.fullmatch(parent),'trusted parent format')
    b=canonical(request);bump('request_read_bytes',len(b))
    need(set(request)=={'op','id','expected_version','text','reason'} and request['op']=='revise_text','exact request shape')
    need(type(request['expected_version']) is int and request['expected_version']>=0,'expected_version must be a nonnegative integer (bool forbidden)')
    need(type(request['text']) is str and request['text']!='' and request['reason']=='local_technical_revision','local fragment technical request')
    return decode(b),sha(b)

def _pure_text_relation_guard(before,after,dirty,seed):
    """Only inspect already loaded records and the encoder's existing dirty set.

    The authenticated parent certified every coverage locator and full v0 span.
    Equal IDs plus no dirty relation/note preserve those exact historical bytes;
    changing a current node's text does not change its immutable v0 referent.
    This is deliberately not a proof for dependency/reverse/cross-SU formats.
    """
    if before.keys()!=after.keys():return False
    for ident in dirty:
        old=before.get(ident);new=after.get(ident)
        if old is None or new is None or old.keys()!=new.keys():return False
        if old['kind'] not in ('source','target'):return False
        if ident==seed:
            mutable={'version','text','digest','prior','responsibility','original'}
            if old['kind']=='target':mutable.add('facts')
            a=old['original'];b=new['original']
            if not isinstance(b,dict) or a.keys()!=b.keys():return False
            if any(b[k]!=v for k,v in a.items() if k!='current_alignment'):return False
        elif old['kind']=='target':
            mutable={'facts'}
            a=old['facts'];b=new['facts']
            if not isinstance(b,dict) or a.keys()!=b.keys():return False
            if any(b[k]!=v for k,v in a.items() if k!='source_alignment'):return False
        else:return False
        if any(new[k]!=v for k,v in old.items() if k not in mutable):return False
    return True

def _reconstruct_revision(r,parent,request,code,schema,session):
    _reconstruction_session_check(r,session,parent,code,schema)
    request,request_hash=authenticate(parent,request,code,schema);bump('reconstructions')
    s=Snapshot(r,parent,session.origin_grant);old=s.node(request['id']);need(old['version']==request['expected_version'],'expected version');need(old['text']!=request['text'],'non-noop revision')
    reuse_eligible=session in _VALIDATION_REUSE
    if reuse_eligible:bump('validation_reuse_eligible')
    own,kind,slot,_=locate(old['id']);pg=s.page_of(old['id']);new=copy.deepcopy(old);new['version']+=1;new['text']=request['text'];new['digest']=sha(new['text'].encode())
    new['prior']={'commit':parent,'path':page_path(own,pg),'record_sha256':sha(canonical(old)),'version':old['version']}
    new['responsibility']={'for_version':new['version'],'status':'UNKNOWN','claims':[]}
    new['original']['current_alignment']='UNKNOWN_TEXT_CHANGED'
    if kind=='target':new['facts']=empty_facts('new_version_not_attested')
    event=sha(canonical({'parent':parent,'request':request_hash}));queue=[old['id']];seen=set(queue);affected=set();edge_count=0
    coverage_affected=set();coverage_count=0;coverage_only=True
    for rec in s.su(own).values():
        # Piggyback on the required affected-target walk, not a new store scan.
        if rec['kind'] not in ('source','target','coverage','note'):coverage_only=False
        if rec['kind']=='coverage':
            coverage_count+=1
            if any(x['id']==old['id'] for x in rec['sources']+rec['targets']):coverage_affected.update(x['id'] for x in rec['targets'])
    # Follow complete reverse records of an externally trusted admitted parent, not whole repository discovery.
    for ident in queue:
        su=locate(ident)[0]
        s.su(su)
        for rev in s.reverse_groups[su].get(ident,[]):
            f=s.su(locate(rev['forward'])[0]).get(rev['forward']);need(f is not None and f['kind']=='dependency','reverse forward missing')
            check_inverse(s,f);need((f['provider'],f['consumer'])==(rev['provider'],rev['consumer']),'reverse mismatch');edge_count+=1
            affected.add(f['consumer'])
            if f['consumer'] not in seen:seen.add(f['consumer']);queue.append(f['consumer'])
    opened=[]
    edited={own:copy.deepcopy(s.su(own))};edited[own][new['id']]=new
    for ident in sorted(affected|coverage_affected):
        su=locate(ident)[0]
        if su not in edited:edited[su]=copy.deepcopy(s.su(su))
        n=edited[su][ident]
        if ident==new['id']:n=new
        if ident in affected:n['facts']['actual_use']={'status':'UNKNOWN','reason':'known_dependency_changed'}
        n['facts']['source_alignment']={'status':'UNKNOWN','reason':'known_dependency_changed' if ident in affected else 'coverage_relation_changed'}
        obligation={'event':event,'seed':old['id'],'old_version':old['version'],'new_version':new['version']}
        need(n['obligations']==[],'inline pending forbidden')
        opened.append({**obligation,'owner':su,'target':ident,'target_version':n['version'],'responsibility':{'for_version':n['version'],'status':'UNKNOWN','claims':[]}})
    # Current text changes do not rebase coverage or edge basis; their old versions remain explicit.
    changes={};changed_paths=[];dirty_by_su={}
    relation_guard=(own in s.owners and set(edited)=={own} and set(s.sus)=={own} and coverage_only and not affected and edge_count==0 and coverage_count==s.member_grant(own)['coverage_count'])
    for su,records in sorted(edited.items()):
        before=s.su(su);dirty={i for i,n in records.items() if n!=before.get(i)};dirty_by_su[su]=dirty
        if reuse_eligible and not _pure_text_relation_guard(before,records,dirty,old['id']):relation_guard=False
        for p,b in encode_su(su,list(records.values()),s.manifests[su]['originals'],previous=s.manifests[su],changed_ids=dirty).items():
            h=oid('blob',b)
            prior_paths={manifest_path(su)}|{page_path(su,d['page']) for d in s.manifests[su]['pages']}
            if p not in prior_paths or h!=r.path_oid(parent,p):
                changes[p]=r.stage('blob',b);changed_paths.append(p)
                is_manifest=p==manifest_path(su)
                bump('changed_manifest_bytes' if is_manifest else 'changed_page_bytes',len(b))
                bump('changed_manifests' if is_manifest else 'changed_pages')
    # Full cold/replay retain all coverage validation. Runtime reuse is an
    # induction over a separately authenticated parent, not a parsed-object cache.
    reuse=reuse_eligible and relation_guard
    if reuse_eligible and not relation_guard:
        bump('relation_integrity_guard_rejections');_VALIDATION_REUSE.discard(session)
    child_view=Snapshot(r,parent,session.origin_grant);child_view.sus={**s.sus,**edited};child_view.manifests=s.manifests.copy()
    for su in edited:
        for record in edited[su].values():
            changed=record['id'] in dirty_by_su[su]
            if changed or (record['kind']=='coverage' and not reuse):
                validate_record(child_view,record)
                if changed:bump('changed_records_validated')
            elif record['kind']=='coverage':bump('unchanged_coverage_reused')
    if reuse:bump('validation_reuse_applied')
    root=r.update_tree(r.root(parent),changes)
    message,delta=log_message(parent,request,code,schema,opened,[])
    candidate=r.stage('commit',commit_bytes(root,parent,message))
    return {'candidate':candidate,'tree':root,'parent':parent,'request':request,'request_hash':request_hash,'code':code,'schema':schema,'affected':sorted(affected),'coverage_affected':sorted(coverage_affected),'changed_paths':changed_paths,'loaded_sus':sorted(s.sus),'known_edges_visited':edge_count,'event':event,'message':message,'delta':delta}

def _reconstruct_note_revision(r,parent,request,code,schema,session):
    _reconstruction_session_check(r,session,parent,code,schema)
    check_pins(code,schema);need(OID.fullmatch(parent),'trusted parent format')
    raw=canonical(request);bump('request_read_bytes',len(raw));bump('reconstructions');request=decode(raw)
    need(set(request)=={'op','id','expected_version','text','reason'} and request['op']=='revise_note_text','exact note request shape')
    need(type(request['text']) is str and request['reason']=='local_technical_revision','local technical string note request including empty')
    s=Snapshot(r,parent,session.origin_grant);old=s.note(request['id']);validate_record(s,old)
    need(type(request['expected_version']) is int and old['version']==request['expected_version'],'expected note version')
    need(old['text']!=request['text'],'non-noop note revision')
    own=locate(old['id'])[0];pg=s.page_of(old['id']);new=copy.deepcopy(old)
    new.update(version=old['version']+1,text=request['text'],digest=sha(request['text'].encode()))
    new['prior']={'commit':parent,'path':page_path(own,pg),'record_sha256':sha(canonical(old)),'version':old['version']}
    new['approval']={'for_note_version':new['version'],'status':'UNKNOWN','claims':[]}
    need(new['about']==old['about'],'immutable note target version');validate_record(s,new)
    rows=dict(s.su(own));rows[new['id']]=new;changes={};changed_paths=[]
    previous=s.manifests[own];prior_paths={manifest_path(own)}|{page_path(own,d['page']) for d in previous['pages']}
    for path,b in encode_su(own,list(rows.values()),previous['originals'],previous=previous,changed_ids={new['id']}).items():
        if path not in prior_paths or oid('blob',b)!=r.path_oid(parent,path):
            changes[path]=r.stage('blob',b);changed_paths.append(path)
            manifest=path==manifest_path(own);bump('changed_manifest_bytes' if manifest else 'changed_page_bytes',len(b));bump('changed_manifests' if manifest else 'changed_pages')
    root=r.update_tree(r.root(parent),changes);request_hash=sha(raw)
    message,delta=log_message(parent,request,code,schema,[],[])
    candidate=r.stage('commit',commit_bytes(root,parent,message))
    return {'candidate':candidate,'tree':root,'parent':parent,'request':request,'request_hash':request_hash,'code':code,'schema':schema,'affected':[],'coverage_affected':[],'changed_paths':changed_paths,'loaded_sus':sorted(s.sus),'known_edges_visited':0,'event':sha(canonical({'parent':parent,'request':request_hash})),'message':message,'delta':delta}

def intent_path(r,plan):return r.path/'intents'/(sha(canonical({'parent':plan['parent'],'request':plan['request_hash']}))+'.json')
def _publish(r,plan,failpoint=None,competing=None,session=None):
    capacity_gate.check_plan_capacity(_MODULE,r,session,plan)
    need(competing is None,"competing publication requires its own authenticated capacity context")
    r.flush();p=intent_path(r,plan);b=canonical(plan)
    if p.exists():need(p.read_bytes()==b,'intent changed')
    else:durable_file(p,b,True)
    pending='refs/intents/'+p.stem
    existing=r.git('rev-parse','--verify',pending,ok=False)
    if existing.returncode==0:need(existing.stdout.strip().decode()==plan['candidate'],'pending ref collision')
    else:r.git('-c','core.fsync=all','update-ref',pending,plan['candidate'],'0'*40)
    if failpoint=='before_cas':return {'interrupted':'before_cas','plan':plan}
    if competing:r.cas(competing,plan['parent'])
    r.cas(plan['candidate'],plan['parent'])
    if failpoint=='after_cas':return {'interrupted':'after_cas','plan':plan}
    return plan

def apply(r,parent,request,code,schema,failpoint=None,competing=None,session=None):
    session_check(session,parent,code,schema)
    with r.integrity_operation():
        session_check(session,parent,code,schema);need(session.repo_path==str(r.path),'session repository')
        plan=_reconstruct(r,parent,request,code,schema,session);delta_check(session,plan['delta']);out=_publish(r,plan,failpoint,competing,session)
        if not out.get('interrupted'):session_advance(session,plan)
        return out
def recover(r,parent,request,code,schema,session=None):
    session_check(session,parent,code,schema)
    with r.integrity_operation():
        session_check(session,parent,code,schema);need(session.repo_path==str(r.path),'session repository')
        plan=_reconstruct(r,parent,request,code,schema,session);p=intent_path(r,plan);need(p.exists(),'missing intent')
        b=p.read_bytes();bump('intent_read_bytes',len(b));need(decode(b)==plan,'intent authentication')
        current=r.ref();need(current in (parent,plan['candidate']),'third-state recovery')
        capacity_gate.check_plan_capacity(_MODULE,r,session,plan)
        r.flush()
        if current==parent:r.cas(plan['candidate'],parent)
        else:_durable_ref_fence(r,plan['candidate'])
        session_advance(session,plan)
        return {'candidate':plan['candidate'],'already_published':current==plan['candidate']}

def receive(r,parent,request,code,schema,received,session=None):
    session_check(session,parent,code,schema)
    with r.integrity_operation():
        session_check(session,parent,code,schema);need(session.repo_path==str(r.path),'session repository')
        # Pack indexing happens separately and cannot confer authorization.
        need(r.ref()==parent,'receiver trusted parent ref')
        r.git('rev-list','--objects','--missing=error',received,'^'+parent)
        received_bytes=r.git('cat-file','commit',received)
        plan=_reconstruct(r,parent,request,code,schema,session);need(received==plan['candidate'],'receiver reconstruction mismatch')
        need(received_bytes==commit_bytes(plan['tree'],parent,plan['message']),'received commit identity')
        out=_publish(r,plan,session=session);session_advance(session,plan);return out


def query(r,request,trusted_commit,code,schema,cache=False,session=None):
    """Caller supplies an externally trusted root separately from the request selector.

    This API cannot create authorization: the trusted host must obtain trusted_commit
    and pins outside untrusted request/content. Historical fixed roots are allowed;
    neither equality to a self-reported root nor current HEAD confers trust.
    """
    check_pins(code,schema)
    need(isinstance(request,dict) and set(request)=={'commit','id'},'query request shape')
    request=decode(canonical(request));bump('request_read_bytes',len(canonical(request)))
    need(isinstance(trusted_commit,str) and OID.fullmatch(trusted_commit),'external trusted query root')
    need(request['commit']==trusted_commit,'query root differs from external grant')
    need(isinstance(request['id'],str) and locate(request['id'])[1]=='target','query target id')
    commit,ident=trusted_commit,request['id']
    session_check(session,commit,code,schema)
    with r.integrity_operation():
        session_check(session,commit,code,schema);need(session.repo_path==str(r.path),'session repository')
        need(decode(r.read_path(commit,'schema.json'))==SCHEMA,'query root schema bytes')
        s=Snapshot(r,commit,session.origin_grant);n=s.node(ident);need(n['kind']=='target','query target')
        coverage=[];direct=[]
        for rec in s.su(locate(ident)[0]).values():
            if rec['kind']=='coverage' and any(x['id']==ident for x in rec['targets']):
                refs=rec['sources']+rec['targets'];matches=all(s.node(x['id'])['version']==x['version'] and s.node(x['id'])['digest']==x['digest'] for x in refs)
                coverage.append({'id':rec['id'],'exact_current_basis_matches':matches,'source_versions':[x['version'] for x in rec['sources']]})
            if rec['kind']=='dependency' and rec['consumer']==ident:
                p=s.node(rec['provider']);direct.append({'id':rec['id'],'basis_matches':p['version']==rec['basis']['version'] and p['digest']==rec['basis']['digest']})
        out={'commit':commit,'target':ident,'version':n['version'],'text':n['text'],'digest':n['digest'],'facts':n['facts'],'known_obligations':session.records(ident),'coverage':coverage,'direct_dependencies':direct,'global_clearance':'UNKNOWN','unrecorded_actual_use':'UNKNOWN','responsibility':n['responsibility']}
        r.admit_existing_required()
        out['authentication']={'trusted_commit':trusted_commit,'code_pin':code,'schema_pin':schema,'root_mode':'EXTERNALLY_FIXED_NOT_LATEST','persistence':'NORMAL_APPEND_ONLY_SERVICE_DURABLE_ADMISSION','origin_sha256':session.origin_sha256,'scope':public_scope(session.origin_grant),'input_mode':session.origin_grant['mode']}
        # Cache rows are expendable. Current state uses verified immutable Git objects; pending comes only from the authenticated process-local session.
        if cache:
            try:
                db=sqlite3.connect(r.path/'query-cache.sqlite');db.execute('CREATE TABLE IF NOT EXISTS query (commit_id TEXT, target TEXT, result BLOB, PRIMARY KEY(commit_id,target))')
                b=canonical(out);db.execute('INSERT OR REPLACE INTO query VALUES (?,?,?)',(commit,ident,b));db.commit();db.close();bump('cache_write_bytes',len(b));bump('cache_transactions')
            except sqlite3.Error:bump('cache_errors')
        return out


def query_note(r,request,trusted_commit,code,schema,cache=False,session=None):
    """Independent note view. Never grants body facts or transfers approval."""
    check_pins(code,schema)
    need(isinstance(request,dict) and set(request)=={'commit','id'},'note query request shape')
    raw=canonical(request);request=decode(raw);bump('request_read_bytes',len(raw))
    need(isinstance(trusted_commit,str) and OID.fullmatch(trusted_commit) and request['commit']==trusted_commit,'external trusted note root')
    need(locate(request['id'])[1]=='note','query note type');session_check(session,trusted_commit,code,schema)
    with r.integrity_operation():
        session_check(session,trusted_commit,code,schema);need(session.repo_path==str(r.path),'session repository')
        need(decode(r.read_path(trusted_commit,'schema.json'))==SCHEMA,'note query schema')
        s=Snapshot(r,trusted_commit,session.origin_grant);n=s.note(request['id']);validate_record(s,n)
        binding='owner-bound' if n['about']['kind']=='owner' else 'target-version-bound';matches='UNKNOWN'
        if n['about']['kind']=='target':
            target=s.node(n['about']['id']);matches=target['version']==n['about']['version'] and target['digest']==n['about']['digest']
        r.admit_existing_required()
        return {'commit':trusted_commit,'note':n['id'],'kind':'note','version':n['version'],'text':n['text'],'digest':n['digest'],'about':copy.deepcopy(n['about']),'approval':copy.deepcopy(n['approval']),'binding':binding,'target_current_matches':matches,'global_clearance':'UNKNOWN','authentication':{'trusted_commit':trusted_commit,'code_pin':code,'schema_pin':schema,'root_mode':'EXTERNALLY_FIXED_NOT_LATEST','persistence':'NORMAL_APPEND_ONLY_SERVICE_DURABLE_ADMISSION','origin_sha256':session.origin_sha256,'scope':public_scope(session.origin_grant),'input_mode':session.origin_grant['mode']}}

def query_archive(r,request,trusted_commit,code,schema,cache=False,session=None):
    """Explicit measured raw read; never scans origin, other archives or old R2."""
    check_pins(code,schema)
    need(cache is False,'archive API has no persistent plaintext query cache')
    need(isinstance(request,dict) and set(request)=={'commit','owner','kind'},'archive query request shape')
    request=decode(canonical(request));bump('request_read_bytes',len(canonical(request)))
    need(isinstance(trusted_commit,str) and OID.fullmatch(trusted_commit) and request['commit']==trusted_commit,'external trusted archive root')
    need(isinstance(request['kind'],str) and request['kind'] in ARCHIVE_KINDS,'archive query fixed kind')
    session_check(session,trusted_commit,code,schema)
    with r.integrity_operation():
        session_check(session,trusted_commit,code,schema);need(session.repo_path==str(r.path),'session repository')
        s=Snapshot(r,trusted_commit,session.origin_grant);member_grant=s.member_grant(request['owner'])
        s.su(request['owner']);descriptor=s.manifests[request['owner']]['archives'][request['kind']]
        need(descriptor['origin_sha256']==member_grant['origin_sha256'] and descriptor['provenance']==archive_provenance(session.origin_grant['mode']),'owner archive grant/mode')
        raw=_read_archive(r,trusted_commit,descriptor);r.admit_existing_required();bump('archive_query_calls');bump('archive_query_output_bytes',len(raw))
        return {'bytes':raw,'sha256':descriptor['sha256'],'byte_length':len(raw),'kind':request['kind'],'authentication':{'trusted_commit':trusted_commit,'archive_anchor':descriptor['commit'],'archive_path':descriptor['storage_path'],'origin_descriptor_path':descriptor['path'],'archive_git_blob':descriptor['git_blob'],'code_pin':code,'schema_pin':schema,'origin_sha256':session.origin_sha256,'provenance_root':session.origin_grant['root'],'provenance_state':session.origin_grant['state'],'member_origin_sha256':member_grant['origin_sha256'],'native_owner':member_grant['native_owner'],'scope':public_scope(session.origin_grant),'input_mode':session.origin_grant['mode'],'media_type':descriptor['media_type'],'representation':descriptor['representation'],'semantics':('ARCHIVAL_ONLY_NO_APPROVAL' if session.origin_grant['mode']=='real_r0_body' else 'SYNTHETIC_ARCHIVAL_TEST_ONLY_NO_NATIVE_PROVENANCE'),'root_mode':'EXTERNALLY_FIXED_BASELINE_ARCHIVE_NOT_CURRENT_EDITED_JSON','persistence':'NORMAL_APPEND_ONLY_SERVICE_DURABLE_ADMISSION'}}

def query_origin(r,request,trusted_commit,code,schema,session=None):
    need(isinstance(request,dict) and set(request)=={'commit','owner'} and request['commit']==trusted_commit,'origin query selector')
    _reconstruction_session_check(r,session,trusted_commit,code,schema)
    with r.integrity_operation():
        _reconstruction_session_check(r,session,trusted_commit,code,schema)
        index=OwnerIndex(r,trusted_commit,session.origin_grant);origin=index.origin(request['owner']);member=index.member_grant(request['owner'])
        r.admit_existing_required()
        return {'bytes':canonical(origin),'sha256':member['origin_sha256'],'owner':request['owner'],'authentication':{'scope':public_scope(session.origin_grant),'input_mode':session.origin_grant['mode'],'trusted_commit':trusted_commit,'origin_index_sha256':session.origin_sha256,'member_origin_sha256':member['origin_sha256'],'code_pin':code,'schema_pin':schema}}

def cold(r,commit,expected_scope,verify_originals=True,require_empty_obligations=False,*,expected_origin_sha256=None,require_origin_baseline=False,expected_grant):
    _grant_contract(expected_grant)
    need(expected_origin_sha256==expected_grant['origin_sha256'],'external cold origin index digest')
    need(verify_originals is True,'origin cold requires original verification')
    index=OwnerIndex(r,commit,expected_grant);sus=index.enumerate_scope()
    if isinstance(expected_scope,list):need(expected_scope==sus,'external cold exact owner list')
    else:need(expected_scope==scope_descriptor(expected_grant),'external cold compact scope')
    need(r.read_path(commit,'scope.json')==canonical(scope_descriptor(expected_grant)),'external cold scope commitment')
    need(r.read_path(commit,'grant.json')==canonical(expected_grant),'persisted compact grant exact bytes')
    members={su:index.origin(su) for su in sus};owner_grants={su:index.member_grant(su) for su in sus}
    s=Snapshot(r,commit,expected_grant);s.index=index;s.owners=index
    root=r.root(commit);paths={};directories=set();tree_seen=set();ancestors=set();ancestor=commit
    while ancestor:
        need(ancestor not in ancestors,'commit ancestry cycle');ancestors.add(ancestor)
        cb=r.get(ancestor,'commit','history_commit');parents=[line[7:].decode() for line in cb.split(b'\n') if line.startswith(b'parent ')]
        need(len(parents)<=1,'single-parent format');ancestor=parents[0] if parents else None
    traversal_budget=len(sus)*(SCHEMA['su_pages']+128)+32;walk_count=0
    def walk(h,prefix=''):
        nonlocal walk_count
        walk_count+=1;need(walk_count<=traversal_budget and len(paths)<=traversal_budget,'cold namespace traversal budget')
        need(prefix.count('/')<=20,'cold namespace depth limit')
        # Once per path, tree parsing cached once per OID. Shared trees still have distinct namespaces.
        tree_seen.add(h)
        for n,(mode,v) in r.tree(h).items():
            p=prefix+n
            if mode=='40000':directories.add(p);walk(v,p+'/')
            else:need(p not in paths,'duplicate path');paths[p]=v
    walk(root);need(decode(r.get(paths['schema.json'],'blob'))==SCHEMA,'schema bytes')
    nodes={};edges={};reverse={};coverage=[];notes=[];all_records=0;original_bytes=0;original_seen=set();original_texts={};archive_raws={};archive_descriptors={};expected={'schema.json','scope.json','grant.json'}
    # First load/group all SUs, then validate records and edges. No per-node whole-tree traversal.
    joint_archive_anchors=set()
    for su in sus:
        member=members[su];member_sha=owner_grants[su]['origin_sha256']
        archive_raws[su]={};archive_descriptors[su]={}
        rows=s.su(su);m=s.manifests[su];expected.update((manifest_path(su),owner_grant_path(su),origin_path(su)))
        need(set(m['originals'])=={'source','target'},'original kinds')
        archive_anchors={ref['commit'] for ref in m['archives'].values()}
        need(len(archive_anchors)==1,'one immutable archive anchor');joint_archive_anchors.update(archive_anchors)
        for kind,ref in m['archives'].items():
            descriptor=member['archives'][kind]
            need({k:ref[k] for k in descriptor}==descriptor and ref['origin_sha256']==member_sha,'manifest archives equal host origin descriptors')
            need(ref['commit'] in ancestors,'raw archive ancestor retention')
            need(paths.get(ref['storage_path'])==ref['git_blob'] and r.path_oid(ref['commit'],ref['storage_path'])==ref['git_blob'],'raw archive current and anchor paths unchanged')
            need(ref['provenance']==archive_provenance(expected_grant['mode']),'archive provenance mode')
            expected.add(ref['storage_path']);archive_raws[su][kind]=_read_archive(r,commit,ref);archive_descriptors[su][kind]=copy.deepcopy(ref)
        for kind,ref in m['originals'].items():need(ref['path']==original_path(su,kind),'canonical original path')
        expected.update(page_path(su,d['page']) for d in m['pages'])
        for ref in m['originals'].values():
            expected.add(ref['path']);key=(ref['commit'],ref['path'])
            need(ref['commit'] in archive_anchors,'derived projection and raw share immutable baseline anchor')
            if verify_originals and key not in original_seen:
                need(ref['commit'] in ancestors,'original ancestor retention')
                h=r.path_oid(ref['commit'],ref['path']);b=r.get(h,'blob','original');original_seen.add(key);original_bytes+=len(b)
                need(paths.get(ref['path'])==ref['git_blob'],'current original bytes unchanged')
                need(h==ref['git_blob'] and sha(b)==ref['sha256'] and len(b)==ref['byte_length'],'original bytes identity')
                original_texts[key]=b.decode('utf-8');bump('original_decodes');bump('original_decoded_bytes',len(b))
        for ident,rec in rows.items():
            all_records+=1
            if require_empty_obligations:need(rec.get('obligations',[])==[],'baseline pending must be empty')
            if rec['kind'] in ('source','target'):need(ident not in nodes,'duplicate node');nodes[ident]=rec
            elif rec['kind']=='dependency':edges[ident]=rec
            elif rec['kind']=='reverse':reverse[ident]=rec
            elif rec['kind']=='coverage':coverage.append(rec)
            elif rec['kind']=='note':notes.append(rec)
            else:raise Rejected('unknown record kind')
    need(len(joint_archive_anchors)==1,'one joint immutable archive anchor')
    need(set(paths)==expected,'exact current path namespace')
    expected_directories={'/'.join(p.split('/')[:i]) for p in expected for i in range(1,len(p.split('/')))}
    need(directories==expected_directories,'exact current directory namespace')
    for rows in s.sus.values():
        for rec in rows.values():
            refs=version_refs(rec)
            for ref in refs:need(ref.get('locator',{}).get('commit') in ancestors,'locator admitted ancestry')
            validate_record(s,rec)
    paired=set()
    for e in edges.values():check_inverse(s,e);paired.add(e['reverse'])
    need(paired==set(reverse) and len(paired)==len(edges),'reverse set completeness')
    for rev in reverse.values():need(rev['forward'] in edges and edges[rev['forward']]['reverse']==rev['id'],'reverse exact inverse')
    for n in nodes.values():
        o=s.manifests[locate(n['id'])[0]]['originals'][n['original']['ref']]
        if verify_originals:
            text=original_texts[(o['commit'],o['path'])];a,z=n['original']['span']
            need(0<=a<=z<=len(text),'original codepoint span')
            if n['version']==0:need(text[a:z]==n['text'],'baseline original alignment')
    for su in sus:
        member=members[su];archive_fields=_verify_archive_fields(archive_raws[su],member)
        _verify_origin_records(s,member,original_texts,owner_grants[su]['origin_sha256'],require_origin_baseline,archive_fields)
    return {'origin_grant':copy.deepcopy(expected_grant),'origin_sha256':expected_origin_sha256,'origin_blob':expected_grant['indexes']['origins']['git_tree'],'scope':public_scope(expected_grant),'sus':len(sus),'nodes':len(nodes),'records':all_records,'edges':len(edges),'reverse':len(reverse),'coverage':len(coverage),'notes':len(notes),'target_notes':sum(x['about']['kind']=='target' for x in notes),'owner_notes':sum(x['about']['kind']=='owner' for x in notes),'paths':len(paths),'directories':len(directories),'scope_count':len(sus),'scope_blob':r.path_oid(commit,'scope.json'),'unique_trees':len(tree_seen),'projection_objects_verified':len(original_seen),'projection_payload_bytes':original_bytes,'archive_objects_verified':sum(len(raws) for raws in archive_raws.values()),'archive_payload_bytes':sum(len(raw) for raws in archive_raws.values() for raw in raws.values()),'archive_descriptors':archive_descriptors,'owner_origin_objects_verified':len(sus),'origin_payload_bytes':sum(len(canonical(m)) for m in members.values()),'indexes':copy.deepcopy(expected_grant['indexes']),'input_mode':expected_grant['mode'],'ancestor_commit_headers_read':len(ancestors),'all_history_transitions_audited':False,'unknown_domains':SCHEMA['domains'],'complexity':'one current path/group pass and bounded complete raw-field census; history/locator/projection reads separately charged'}

# Session contents are derived only by verified transitions, never by SQLite.
_SESSION_TOKEN=object()
# Registry entries are independent of mutable public session attributes. The
# binding admits a cold-verified baseline/replayed prefix; the separate reuse
# credential is minted only after the ENTIRE requested checkpoint is restored.
# Weak keys keep abandoned sessions from accumulating service-global state.
_SESSION_BINDINGS=weakref.WeakKeyDictionary()
_VALIDATION_REUSE=weakref.WeakSet()
_SESSION_PROVENANCE=weakref.WeakKeyDictionary()
class LogSession:
    def __init__(self,token,admission,root,code,schema):
        need(token is _SESSION_TOKEN,'session factory required')
        self._token=token;self.admission=admission;self.root=root;self.code=code;self.schema=schema;self._active={};self._seen=set();self.transitions=0
    def records(self,ident):
        session_check(self,self.root,self.code,self.schema)
        return [copy.deepcopy(self._active[key]) for key in sorted(self._active) if self._active[key]['target']==ident]

def _session_binding(s):
    # No owner list, origin map or archive collection. Pending/history are
    # intentionally O(active+seen) and are protected independently of public fields.
    return (s.repo_path,s.admission,s.root,s.code,s.schema,s.origin_sha256,s.origin_blob,_grant_key(s.origin_grant),s.transitions,_pending_fingerprint(s))

def session_check(s,parent,code,schema):
    need(isinstance(s,LogSession) and s._token is _SESSION_TOKEN,'authenticated session required')
    need((s.root,s.code,s.schema)==(parent,code,schema),'session root/pin mismatch')
    _grant_contract(getattr(s,'origin_grant',None))
    need(s.origin_grant['origin_sha256']==getattr(s,'origin_sha256',None),'session compact origin index identity')
    need(getattr(s,'origin_blob',None)==s.origin_grant['indexes']['origins']['git_tree'],'session immutable origin index root')
    need(isinstance(getattr(s,'repo_path',None),str) and _SESSION_BINDINGS.get(s)==_session_binding(s),'session authenticated root/repository/pin/index binding')

def _reconstruction_session_check(r,s,parent,code,schema):
    check_pins(code,schema);session_check(s,parent,code,schema)
    need(s.repo_path==str(r.path)==r.service_key,'session repository')

def fork_session(source):
    """Fork an authenticated in-memory view, never authenticate an arbitrary copy.

    Historical/idempotent callers need independent pending state without paying
    for a second cold replay. This does not authorize any different root or repo.
    """
    need(isinstance(source,LogSession),'authenticated session required')
    check_pins(source.code,source.schema);session_check(source,source.root,source.code,source.schema)
    clone=copy.copy(source);clone._active=copy.deepcopy(source._active);clone._seen=set(source._seen);clone.origin_grant=copy.deepcopy(source.origin_grant)
    _SESSION_BINDINGS[clone]=_SESSION_BINDINGS[source]
    _SESSION_PROVENANCE[clone]=copy.deepcopy(_SESSION_PROVENANCE.get(source,{'mode':'FULL_COLD_AND_REPLAY','checkpoint_root':None}))
    if source in _VALIDATION_REUSE:_VALIDATION_REUSE.add(clone)
    return clone

def delta_check(s,delta):
    session_check(s,delta['parent'],delta['code'],delta['schema'])
    keys=set(s._active);seen=set(s._seen)
    for e in delta['opened']:
        key=(e['event'],e['target']);need(key not in seen,'duplicate obligation identity');seen.add(key);keys.add(key)
    for e in delta['resolved']:
        key=(e['event'],e['target']);need(key in keys and s._active.get(key)==e,'resolve exact active identity');keys.remove(key)

def session_advance(s,plan):
    delta=plan['delta'];delta_check(s,delta)
    for e in delta['opened']:
        key=(e['event'],e['target']);s._active[key]=copy.deepcopy(e);s._seen.add(key)
    for e in delta['resolved']:del s._active[(e['event'],e['target'])]
    s.root=plan['candidate'];s.transitions+=1
    # delta_check above requires an existing authenticated binding. Updating it
    # never grants a missing reuse credential, especially during cold replay.
    _SESSION_BINDINGS[s]=_session_binding(s)

def log_message(parent,request,code,schema,opened,resolved):
    d={'format':'pending-commit-log-v1','parent':parent,'request':request,'code':code,'schema':schema,'opened':opened,'resolved':resolved}
    raw=canonical(d);need(len(raw)<=65536,'transition log byte limit');return raw.decode(),d

def parse_log(r,commit):
    body=r.get(commit,'commit','log_commit')
    need(len(body)<=66560,'commit log byte limit')
    try:header,message=body.split(b'\n\n',1);need(message.endswith(b'\n'),'log message newline');d=decode(message[:-1])
    except (ValueError,Rejected):raise Rejected('missing or invalid canonical log')
    need(set(d)=={'format','parent','request','code','schema','opened','resolved'} and d['format']=='pending-commit-log-v1','log envelope')
    parents=[x[7:].decode() for x in header.split(b'\n') if x.startswith(b'parent ')]
    need(parents==[d['parent']],'log parent commitment');return body,d

def _reconstruct(r,parent,request,code,schema,session=None):
    _reconstruction_session_check(r,session,parent,code,schema)
    if request.get('op')=='revise_note_text':return _reconstruct_note_revision(r,parent,request,code,schema,session)
    if request.get('op')!='resolve_pending':return _reconstruct_revision(r,parent,request,code,schema,session)
    check_pins(code,schema);session_check(session,parent,code,schema);raw=canonical(request);bump('request_read_bytes',len(raw));bump('reconstructions');request=decode(raw)
    need(set(request)=={'op','items','reason'} and request['reason']=='local_technical_resolution','resolve request shape')
    items=request['items'];need(isinstance(items,list) and 0<len(items)<=16,'resolve request bounds')
    need(all(isinstance(e,dict) and set(e)=={'event','target','owner','target_version','seed','old_version','new_version','responsibility'} for e in items),'resolve item shape')
    keys=[(e['event'],e['target']) for e in items];need(keys==sorted(set(keys)),'resolve duplicate/order')
    for e in items:
        need(locate(e['target'])[0]==e['owner'] and locate(e['target'])[1]=='target','resolve owner')
        need(session._active.get((e['event'],e['target']))==e,'resolve exact active identity')
    message,delta=log_message(parent,request,code,schema,[],items);request_hash=sha(raw);root=r.root(parent)
    candidate=r.stage('commit',commit_bytes(root,parent,message))
    return {'candidate':candidate,'tree':root,'parent':parent,'request':request,'request_hash':request_hash,'code':code,'schema':schema,'affected':[],'coverage_affected':[],'changed_paths':[],'loaded_sus':[],'known_edges_visited':0,'event':sha(canonical({'parent':parent,'request':request_hash})),'message':message,'delta':delta}

def _restore_checkpoint(r,checkpoint,requested_root,code,schema,expected_latest=None,publish=False):
    raise Rejected('v25 requires streaming restore')
    check_pins(code,schema)
    need(isinstance(checkpoint,dict),'external checkpoint required')
    need(set(checkpoint)=={'kind','baseline','final','code','schema','scope','origin_sha256','origin_grant'} and checkpoint['kind']=='trusted_host_admitted_chain_not_user_signature','checkpoint shape')
    _grant_contract(checkpoint['origin_grant'])
    need(checkpoint['scope']==scope_descriptor(checkpoint['origin_grant']) and checkpoint['origin_sha256']==checkpoint['origin_grant']['origin_sha256'],'checkpoint external complete owner-set grant')
    need(checkpoint['code']==code and checkpoint['schema']==schema,'checkpoint execution pins')
    need(requested_root==checkpoint['final'],'request not anchored by checkpoint')
    if expected_latest is not None:need(requested_root==expected_latest,'checkpoint differs from externally expected latest')
    admission=checkpoint['baseline'];need(OID.fullmatch(admission) and OID.fullmatch(requested_root),'checkpoint roots')
    with r.integrity_operation():
        current=r.ref() if publish else None
        if publish:need(current in (admission,requested_root),'receiver checkpoint parent conflict')
        need(r.get(admission,'commit').endswith(b'\n\nhost admitted bounded radix owner-set baseline; provenance mode in grant; not whole book\n'),'complete baseline admission role')
        started=time.perf_counter_ns();verified=cold(r,admission,checkpoint['scope'],require_empty_obligations=True,expected_origin_sha256=checkpoint['origin_sha256'],require_origin_baseline=True,expected_grant=checkpoint['origin_grant'])
        bump('cold_baseline_ns',time.perf_counter_ns()-started);started=time.perf_counter_ns()
        chain=[];head=requested_root;visited=set()
        while head!=admission:
            need(head not in visited,'log ancestry cycle');visited.add(head);raw,d=parse_log(r,head)
            need(d['code']==code and d['schema']==schema,'single-format historical pins')
            chain.append((head,raw,d));head=d['parent']
        s=LogSession(_SESSION_TOKEN,admission,admission,code,schema);s.repo_path=str(r.path);s.origin_sha256=checkpoint['origin_sha256'];s.origin_blob=verified['origin_blob'];s.origin_grant=copy.deepcopy(verified['origin_grant'])
        _SESSION_BINDINGS[s]=_session_binding(s)
        for child,actual,d in reversed(chain):
            # Requests inherit host admission solely from the external final root.
            # Neither the request nor an untrusted ref can mint that admission.
            plan=_reconstruct(r,s.root,d['request'],code,schema,s)
            need(child==plan['candidate'] and actual==commit_bytes(plan['tree'],s.root,plan['message']),'replayed transition mismatch')
            session_advance(s,plan);bump('log_transitions_replayed')
        need(s.root==requested_root,'session final root')
        OwnerIndex(r,requested_root,s.origin_grant)  # Constant-root retention; cold + replay establish all leaves.
        bump('cold_replay_ns',time.perf_counter_ns()-started)
        started=time.perf_counter_ns();r.admit_existing_required();bump('cold_admission_ns',time.perf_counter_ns()-started)
        if publish:
            intent=canonical({'kind':'checkpoint-receive','parent':admission,'checkpoint':checkpoint});path=r.path/'checkpoint-intents'/(sha(intent)+'.json')
            if path.exists():need(path.read_bytes()==intent,'checkpoint receive intent changed')
            else:durable_file(path,intent,True)
            if current==admission:r.cas(requested_root,admission)
        # Only a completed cold + full deterministic replay + durable admission
        # can certify unchanged coverage. No per-transition path grants this.
        _VALIDATION_REUSE.add(s)
        _SESSION_PROVENANCE[s]={'mode':'FULL_COLD_AND_REPLAY','checkpoint_root':None}
        return s

def start_session(r,checkpoint,requested_root,code,schema,expected_latest=None):
    return _restore_checkpoint(r,checkpoint,requested_root,code,schema,expected_latest,False)

def receive_checkpoint(r,checkpoint,code,schema):
    return _restore_checkpoint(r,checkpoint,checkpoint['final'],code,schema,checkpoint['final'],True)


def rebuild_locator(r,session):
    """Derived SQLite locator only. Query never trusts these rows or their absence."""
    _reconstruction_session_check(r,session,session.root,session.code,session.schema)
    db=sqlite3.connect(r.path/'pending-locator.sqlite')
    try:
        db.execute('DROP TABLE IF EXISTS locator');db.execute('CREATE TABLE locator (event TEXT,target TEXT,root TEXT,PRIMARY KEY(event,target))')
        db.executemany('INSERT INTO locator VALUES (?,?,?)',[(e,t,session.root) for e,t in session._active]);db.commit()
        bump('locator_rows_written',len(session._active));bump('locator_rebuilds')
    finally:db.close()
    return len(session._active)


# v22: checkpoint authority is an authenticated HOST input. No file in this
# repository, ref, cache, SQLite row, hash beside a file, or this serializer can
# supply that authority. A hostile caller controlling this Python module is
# outside the trusted execution boundary, as in all preceding kernels.
RESTART_FORMAT='external-host-lazy-restart/v1'

def _pending_state(s):
    need(isinstance(s._active,dict) and isinstance(s._seen,set),'session pending containers')
    need(all(isinstance(k,tuple) and len(k)==2 and all(isinstance(x,str) for x in k) for k in list(s._active)+list(s._seen)),'session pending key shape')
    need(all(isinstance(v,dict) for v in s._active.values()),'session pending value shape')
    need(type(s.transitions) is int and s.transitions>=0,'session pending transition count')
    return {'format':'root-bound-pending-state/v1','root':s.root,
            'active':[copy.deepcopy(s._active[k]) for k in sorted(s._active)],
            'seen':[list(k) for k in sorted(s._seen)],'transitions':s.transitions}

def _pending_fingerprint(s):
    state=_pending_state(s);raw=canonical(state)
    # Bind the dictionary keys too; changing a key while retaining its event
    # value must not leave the independent session fingerprint unchanged.
    raw_keys=canonical([list(k) for k in sorted(s._active)])
    bump('session_pending_binding_bytes',len(raw)+len(raw_keys))
    return sha(raw),sha(raw_keys)

def _pending_contract(state,root):
    need(isinstance(state,dict) and set(state)=={'format','root','active','seen','transitions'},'restart pending exact fields')
    need(state['format']=='root-bound-pending-state/v1' and state['root']==root,'restart pending format/root')
    need(type(state['transitions']) is int and state['transitions']>=0,'restart transition count')
    active=state['active'];seen=state['seen']
    need(isinstance(active,list) and isinstance(seen,list),'restart pending collections')
    need(len(active)<=len(seen)<=SCHEMA['restart']['pending_keys_max'],'restart pending/history bound')
    def key_ok(k):
        need(isinstance(k,list) and len(k)==2 and all(isinstance(x,str) for x in k),'restart seen key shape')
        _origin_digest(k[0],'restart event digest');need(locate(k[1])[1]=='target','restart seen target')
        return tuple(k)
    keys=[key_ok(k) for k in seen]
    need(keys==sorted(set(keys)),'restart seen exact sorted unique keys');seen_keys=set(keys)
    events={};active_keys=[]
    for e in active:
        need(isinstance(e,dict) and set(e)=={'event','target','owner','target_version','seed','old_version','new_version','responsibility'},'restart active event shape')
        key=key_ok([e['event'],e['target']]);active_keys.append(key)
        own,kind,_,_=locate(e['target']);seed_owner,seed_kind,_,_=locate(e['seed'])
        need(e['owner']==own==seed_owner and seed_kind in ('source','target'),'restart active owner/seed')
        need(all(type(e[f]) is int and e[f]>=0 for f in ('target_version','old_version','new_version')) and e['new_version']==e['old_version']+1,'restart active versions')
        need(e['responsibility']=={'for_version':e['target_version'],'status':'UNKNOWN','claims':[]} and type(e['responsibility'].get('for_version')) is int,'restart exact UNKNOWN responsibility')
        need(key in seen_keys,'restart active key absent from seen');events[key]=copy.deepcopy(e)
    need(active_keys==sorted(set(active_keys)),'restart active sorted unique keys')
    need(state['transitions']>0 or not (active or seen),'restart baseline pending must be empty')
    bump('restart_pending_active_validated',len(active));bump('restart_pending_seen_validated',len(seen))
    return events,seen_keys

def _repository_identity(r):
    # A local instance identifier, not an adversarial identity credential. The
    # authenticated checkpoint binds it; same-UID inode replacement is outside
    # the cooperative storage model. Relocation/import requires full admission.
    repo_stat=r.path.stat();objects_stat=(r.path/'objects').stat()
    return {'path':str(r.path),'repo_device':repo_stat.st_dev,'repo_inode':repo_stat.st_ino,
            'objects_device':objects_stat.st_dev,'objects_inode':objects_stat.st_ino}

def _bounded_root_binding(r,root,grant):
    raw=r.get(root,'commit','restart_header');tree=r.root(root);tree_raw=r.get(tree,'tree','restart_root')
    OwnerIndex(r,root,grant)
    need(r.read_path(root,'schema.json','restart_header')==canonical(SCHEMA),'restart root schema')
    need(r.read_path(root,'scope.json','restart_header')==canonical(scope_descriptor(grant)),'restart root scope')
    need(r.read_path(root,'grant.json','restart_header')==canonical(grant),'restart root grant')
    bump('restart_root_checks')
    return {'commit':root,'commit_sha256':sha(raw),'tree':tree,'tree_sha256':sha(tree_raw)}

def build_initial_session(r,models,originals,expected_scope,*,origin_map,expected_origin_sha256,archives,expected_grant,owner_grants):
    """Build and admit once, then return (initial_result, authenticated_session).

    Unlike build_initial followed by start_session this does not redo the full
    initial census. Session authority comes only after cold + flush + CAS pass.
    """
    with r.integrity_operation():
        initial=_build_initial(r,models,originals,expected_scope,origin_map,expected_origin_sha256,archives,expected_grant,owner_grants)
        root=initial['commit'];s=LogSession(_SESSION_TOKEN,root,root,code_pin(),SCHEMA_PIN)
        s.repo_path=str(r.path);s.origin_sha256=expected_origin_sha256;s.origin_blob=expected_grant['indexes']['origins']['git_tree'];s.origin_grant=copy.deepcopy(expected_grant)
        _SESSION_BINDINGS[s]=_session_binding(s);_VALIDATION_REUSE.add(s)
        _SESSION_PROVENANCE[s]={'mode':'FULL_INITIAL_ADMISSION','checkpoint_root':None}
        return initial,s

def export_restart_checkpoint(r,session):
    """Serialize a registered admitted/valid-derived session for the trusted host.

    Return canonical bytes, NOT a self-authenticating capability. The host must
    durably retain the bytes and their authenticated SHA256 outside the repository
    and maintain an independent latest root. An adjacent checksum is insufficient.
    """
    _reconstruction_session_check(r,session,session.root,session.code,session.schema)
    need(session in _VALIDATION_REUSE,'restart export requires admitted/derived reuse credential')
    with r.integrity_operation():
        _reconstruction_session_check(r,session,session.root,session.code,session.schema)
        raw=capacity_gate.encode_restart_envelope(_MODULE,r,session,session.root,_pending_state(session))
        r.admit_existing_required();bump('restart_checkpoints_exported');bump('restart_checkpoint_export_bytes',len(raw))
        return raw

def start_lazy_session(r,checkpoint_bytes,requested_root,code,schema,*,authenticated_checkpoint_sha256,expected_latest):
    """Lightweight SAME-REPOSITORY restart, under external host authentication.

    expected_latest must come from external monotonic host state, never r.ref().
    Both authenticated_checkpoint_sha256 and the checkpoint must survive outside
    Git. Restoring both an old checkpoint and old host latest state is undetectable.
    Missing/invalid checkpoint has no permissive empty-pending fallback.
    """
    check_pins(code,schema)
    need(type(checkpoint_bytes) is bytes and 0<len(checkpoint_bytes)<=SCHEMA['restart']['checkpoint_bytes_max'],'external restart checkpoint bytes required/bounded')
    _origin_digest(authenticated_checkpoint_sha256,'external authenticated checkpoint SHA256')
    need(sha(checkpoint_bytes)==authenticated_checkpoint_sha256,'external checkpoint authentication mismatch')
    bump('restart_checkpoint_read_bytes',len(checkpoint_bytes));checkpoint=decode(checkpoint_bytes)
    fields={'format','repository','baseline','root','code','schema','origin_grant','origin_sha256','scope','root_binding','pending','pending_sha256','pending_active_count','pending_seen_count','trust_basis'}
    need(isinstance(checkpoint,dict) and set(checkpoint)==fields and checkpoint['format']==RESTART_FORMAT,'restart checkpoint exact shape/version')
    need(checkpoint['trust_basis']=='PRIOR_FULL_ADMISSION_AND_VALID_DERIVATION_NOT_FRESH_FULL_AUDIT','restart admission basis')
    need(checkpoint['repository']==_repository_identity(r),'restart repository instance mismatch')
    need(checkpoint['code']==code and checkpoint['schema']==schema,'restart checkpoint execution pins')
    need(isinstance(requested_root,str) and OID.fullmatch(requested_root),'restart requested root')
    need(isinstance(expected_latest,str) and OID.fullmatch(expected_latest),'external latest root required')
    need(requested_root==checkpoint['root']==expected_latest,'checkpoint differs from externally expected latest')
    need(isinstance(checkpoint['baseline'],str) and OID.fullmatch(checkpoint['baseline']),'restart baseline root')
    grant=checkpoint['origin_grant'];_grant_contract(grant)
    need(checkpoint['scope']==scope_descriptor(grant) and checkpoint['origin_sha256']==grant['origin_sha256'],'restart compact grant/scope binding')
    pending=checkpoint['pending'];active,seen=_pending_contract(pending,requested_root)
    need(checkpoint['pending_sha256']==sha(canonical(pending)),'restart pending digest')
    need(type(checkpoint['pending_active_count']) is int and checkpoint['pending_active_count']==len(active) and type(checkpoint['pending_seen_count']) is int and checkpoint['pending_seen_count']==len(seen),'restart pending counts')
    with r.integrity_operation():
        need(r.ref()==requested_root,'restart local head differs from externally expected latest')
        need(_bounded_root_binding(r,requested_root,grant)==checkpoint['root_binding'],'restart immutable root/header binding')
        r.admit_existing_required()
        s=LogSession(_SESSION_TOKEN,checkpoint['baseline'],requested_root,code,schema);s.repo_path=str(r.path)
        s.origin_sha256=grant['origin_sha256'];s.origin_blob=grant['indexes']['origins']['git_tree'];s.origin_grant=copy.deepcopy(grant)
        s._active=active;s._seen=seen;s.transitions=pending['transitions']
        _SESSION_BINDINGS[s]=_session_binding(s);_VALIDATION_REUSE.add(s)
        _SESSION_PROVENANCE[s]={'mode':'EXTERNAL_CHECKPOINT_LAZY_RESTART','checkpoint_root':requested_root}
        bump('lazy_restarts_admitted');return s

def session_provenance(session):
    """No O(owner-count) verification claims are inferred from a restart."""
    session_check(session,session.root,session.code,session.schema)
    info=_SESSION_PROVENANCE.get(session,{'mode':'FULL_COLD_AND_REPLAY','checkpoint_root':None})
    return {'admission_mode':info['mode'],'checkpoint_root':info['checkpoint_root'],'current_root':session.root,
            'all_owners_freshly_verified_this_process':info['mode']!='EXTERNAL_CHECKPOINT_LAZY_RESTART',
            'owner_payloads_checked_at_admission':0 if info['mode']=='EXTERNAL_CHECKPOINT_LAZY_RESTART' else session.origin_grant['scope_count'],
            'unscanned_owners_inherit_checkpoint_trust':info['mode']=='EXTERNAL_CHECKPOINT_LAZY_RESTART',
            'latest_root_source':'EXTERNAL_HOST_REQUIRED_NOT_LOCAL_REF',
            'pending_state':'AUTHENTICATED_ACTIVE_PLUS_ALL_SEEN_KEYS','pending_active':len(session._active),'pending_seen':len(session._seen)}

def _validate_lazy_owner(snapshot,su):
    """Recheck loaded owner bytes and semantics, never global scope/chain.

    Current/historical Git paths and bytes authenticate through the exact root
    and declared locators. Prior full admission certifies locator ancestry and
    raw archive census; this function does not replay that historical proof.
    """
    r=snapshot.r;member=snapshot.member_grant(su);origin=snapshot.index.origin(su)
    manifest=snapshot.manifests[su];originals={};archive_anchors=set()
    for kind,ref in manifest['archives'].items():
        descriptor=origin['archives'][kind]
        need({k:ref[k] for k in descriptor}==descriptor and ref['origin_sha256']==member['origin_sha256'],'lazy archive descriptor equals immutable origin')
        need(ref['provenance']==archive_provenance(snapshot.grant['mode']),'lazy archive mode')
        need(r.path_oid(snapshot.commit,ref['storage_path'])==ref['git_blob'] and r.path_oid(ref['commit'],ref['storage_path'])==ref['git_blob'],'lazy archive path/anchor identity')
        archive_anchors.add(ref['commit'])
    need(len(archive_anchors)==1,'lazy shared archive anchor')
    need(set(manifest['originals'])=={'source','target'},'lazy exact projection kinds')
    for kind,ref in manifest['originals'].items():
        need(ref['path']==original_path(su,kind) and ref['commit'] in archive_anchors,'lazy projection route/anchor')
        need(r.path_oid(snapshot.commit,ref['path'])==ref['git_blob'] and r.path_oid(ref['commit'],ref['path'])==ref['git_blob'],'lazy projection retained path')
        raw=r.get(ref['git_blob'],'blob','lazy_projection')
        need(len(raw)==ref['byte_length'] and sha(raw)==ref['sha256'],'lazy projection SHA256/length')
        try:originals[(ref['commit'],ref['path'])]=raw.decode('utf-8')
        except UnicodeError as error:raise Rejected('lazy projection UTF8') from error
        bump('lazy_projection_objects_verified')
    for record in snapshot.sus[su].values():validate_record(snapshot,record);bump('lazy_owner_records_validated')
    _verify_origin_records(snapshot,origin,originals,member['origin_sha256'],False)
    # One bounded record per touched owner per request. No growing session owner
    # cache and no previously touched owner is implicitly counted this request.
    report={'owner':su,'records':len(snapshot.sus[su]),'origin_sha256':member['origin_sha256'],
            'current_records_and_relations':'VERIFIED_THIS_REQUEST','origin_and_projections':'VERIFIED_THIS_REQUEST',
            'byte_source':'VERIFIED_LOAD_OR_APPEND_ONLY_SERVICE_CACHE_NOT_FORCED_DISK_REREAD',
            'raw_archive_payloads':'INHERITED_CHECKPOINT_NOT_READ','locator_ancestry':'INHERITED_CHECKPOINT_NOT_REPLAYED'}
    r._lazy_owner_reports[su]=report;bump('lazy_owners_validated')

def _lazy_operation(fn):
    # Enter the mode before fn starts its integrity operation. fn remains the
    # authority/CAS/persistence implementation. No extra plan fields are inserted
    # because plans and durable recovery intents must be byte-identical.
    import functools
    @functools.wraps(fn)
    def wrapped(r,*args,**kwargs):
        session=kwargs.get('session')
        # Public session arguments may be positional. Bind using the frozen
        # function signature rather than accidentally omitting lazy checks.
        if session is None:
            import inspect
            session=inspect.signature(fn).bind(r,*args,**kwargs).arguments.get('session')
        lazy=_SESSION_PROVENANCE.get(session,{}).get('mode')=='EXTERNAL_CHECKPOINT_LAZY_RESTART' if isinstance(session,LogSession) else False
        read_provenance=None
        if fn.__name__ in ('query','query_note','query_archive','query_origin') and isinstance(session,LogSession):
            # Capture one validated root's metadata before the read. The second
            # check rejects an advance while collecting its root/pending counts;
            # the wrapped read then checks that same root under its own lock.
            # After successful read, use this immutable snapshot, never mutable
            # session fields after the read's integrity lock has been released.
            read_provenance=session_provenance(session)
            session_check(session,read_provenance['current_root'],session.code,session.schema)
        previous=getattr(r,'_lazy_validate',False);old_reports=getattr(r,'_lazy_owner_reports',{})
        r._lazy_validate=lazy;r._lazy_owner_reports={}
        try:
            result=fn(r,*args,**kwargs)
            if isinstance(result,dict) and 'authentication' in result and read_provenance is not None:
                need(result['authentication']['trusted_commit']==read_provenance['current_root'],'query provenance root differs from verified result')
                result['authentication'].update(read_provenance)
                result['authentication']['current_request_owner_validation']=copy.deepcopy(list(r._lazy_owner_reports.values()))
                if lazy:
                    result['authentication']['validation_extent']='ONLY_LISTED_OWNER_RECORDS_PLUS_EXPLICIT_API_PAYLOADS; OTHER_OWNERS_INHERITED'
            return result
        finally:r._lazy_validate=previous;r._lazy_owner_reports=old_reports
    return wrapped

query=_lazy_operation(query)
query_note=_lazy_operation(query_note)
query_archive=_lazy_operation(query_archive)
query_origin=_lazy_operation(query_origin)
apply=_lazy_operation(apply)
recover=_lazy_operation(recover)
receive=_lazy_operation(receive)

def full_audit(r,session):
    """Explicit independent full verification, without republishing or shortcuts.

    Drop repository payload/known/hash caches, then cold baseline + deterministic
    replay + full current-state cold audit. Does NOT upgrade the supplied lazy
    session or certify future uncooperative mutations. A fresh process remains
    the stronger isolated measurement; this API clears all service caches first.
    """
    _reconstruction_session_check(r,session,session.root,session.code,session.schema)
    checkpoint=make_checkpoint(session.origin_grant,session.admission,session.root)
    reset_service_cache(r.path);r.close();previous=getattr(r,'_lazy_validate',False);r._lazy_validate=False
    try:
        audited=start_session(r,checkpoint,session.root,session.code,session.schema,expected_latest=session.root)
        with r.integrity_operation():
            current=cold(r,session.root,scope_descriptor(session.origin_grant),expected_origin_sha256=session.origin_sha256,expected_grant=session.origin_grant)
            r.admit_existing_required()
        need(_pending_state(audited)==_pending_state(session),'independent full audit pending differs from supplied session')
        return {'root':session.root,'baseline':session.admission,'transitions_replayed':audited.transitions,
                'pending_active':len(audited._active),'pending_seen':len(audited._seen),
                'all_history_transitions_audited':True,'all_current_owners_audited':True,
                'audit':'FRESH_SERVICE_CACHE_FULL_BASELINE_REPLAY_AND_CURRENT_COLD','current':current}
    finally:r._lazy_validate=previous
