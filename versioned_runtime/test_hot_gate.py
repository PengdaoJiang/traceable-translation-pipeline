#!/usr/bin/env python3
"""Synthetic bounded-hot acceptance, negative controls and no-enumeration proof."""
import hashlib, importlib.util, json, os, pathlib, shutil, subprocess, sys, tempfile, time, zlib
from unittest.mock import patch
sys.dont_write_bytecode=True
HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('host_checkpoint', HERE/'host_checkpoint.py');h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
rows=[]
def passed(name,**kw):rows.append({'case':name,'pass':True,**kw})
def reject(name,fn):
 try:fn()
 except (h.Rejected,OSError):passed(name);return
 raise AssertionError(name+' accepted')

def run():
 with tempfile.TemporaryDirectory(prefix='v42_2-hot-gate-') as temp:
  root=pathlib.Path(temp);repo=root/'bare.git';subprocess.run(['git','init','--bare','--quiet','--initial-branch=main',str(repo)],check=True,env=h.git_environment())
  p=h.load_core();r=p.Repo(repo);caps=[p.synthetic_fixtures.capture(1,4)];inv={c['owner']:p.k.sha(p.k.canonical(p.native.capture_receipt(c))) for c in caps}
  _,s=p.build_initial_pending_session(r,caps,expected_inventory=inv,mode='synthetic_scale_only');n0,m,grant=s.native_baseline,s.baseline,s.grant;r.close()
  grantfile=root/'grant.json';grantfile.write_bytes(h.canonical(grant));c=h.input_contract(repo,n0,m,m,grantfile,h.sha(grantfile.read_bytes()))
  receipt=h.run_admit(c,root/'host','SU-000001-T0001');identity=h.repository_identity(repo)
  def no_enumeration(*a,**kw):raise AssertionError('hot query attempted full repository traversal')
  with patch.object(h.os,'walk',no_enumeration),patch.object(h,'repository_gate',no_enumeration):
   t=time.monotonic();q=h.run_query(c,root/'host',receipt['host_sha256'],'SU-000001-T0001');seconds=time.monotonic()-t
  assert q['query']==receipt['query'];passed('query_no_os_walk_or_cold_repository_gate',complete_api_wall_seconds=seconds)
  # Add valid unreachable append-only Git objects. Hot validation must not walk
  # these files or depend on their count; touched-object checks remain core-owned.
  for i in range(4096):
   raw=('synthetic unreachable '+str(i)).encode();obj=b'blob '+str(len(raw)).encode()+b'\0'+raw;oid=hashlib.sha1(obj).hexdigest();path=repo/'objects'/oid[:2]/oid[2:];path.parent.mkdir(exist_ok=True);path.write_bytes(zlib.compress(obj))
  with patch.object(h.os,'walk',no_enumeration),patch.object(h,'repository_gate',no_enumeration):
   t=time.monotonic();large=h.run_query(c,root/'host',receipt['host_sha256'],'SU-000001-T0001');seconds=time.monotonic()-t
  assert large['query']==q['query'];passed('4096_extra_valid_objects_not_enumerated',complete_api_wall_seconds=seconds)
  reject('cross_instance_identity',lambda:h.repository_hot_gate(repo,{**identity,'repo_inode':identity['repo_inode']+1}))
  for rel in ('objects/info/alternates','objects/info/http-alternates','shallow','info/grafts','commondir','config.worktree'):
   path=repo/rel;path.parent.mkdir(exist_ok=True);path.write_bytes(b'')
   reject('reject_'+rel,lambda:h.repository_hot_gate(repo,identity));path.unlink()
  old=(repo/'config').read_bytes()
  for block in ('\n[include]\n path = /missing-config\n','\n[remote "origin"]\n promisor = true\n','\n[extensions]\n refStorage = reftable\n', '\n[extensions]\n partialClone = origin\n', '\n[extensions]\n partialclone = origin\n'):
   (repo/'config').write_bytes(old+block.encode());reject('config_indirection_'+str(len(rows)),lambda:h.repository_hot_gate(repo,identity))
  (repo/'config').write_bytes(old)
  (repo/'config').write_bytes(old+b'#'+b'x'*65536);reject('bounded_config_size',lambda:h.repository_hot_gate(repo,identity));(repo/'config').write_bytes(old)
  replace=repo/'refs/replace';replace.mkdir();(replace/('0'*40)).write_text(m+'\n');reject('loose_replacement_ref',lambda:h.repository_hot_gate(repo,identity));(replace/('0'*40)).unlink()
  packed=repo/'packed-refs';packed.write_text('# pack-refs with: peeled fully-peeled sorted\n'+m+' refs/replace/'+('0'*40)+'\n');reject('packed_replacement_ref',lambda:h.repository_hot_gate(repo,identity));packed.unlink()
  packed.write_bytes(b'#'+b'x'*(1024*1024));reject('bounded_packed_refs_size',lambda:h.repository_hot_gate(repo,identity));packed.unlink()
  (repo/'config').unlink();(repo/'config').symlink_to(grantfile);reject('symlink_config',lambda:h.repository_hot_gate(repo,identity));(repo/'config').unlink();(repo/'config').write_bytes(old)
  before=receipt['host_sha256'];bad=root/'badhost';shutil.copytree(root/'host',bad);(bad/'HOST.json').write_bytes(b'{}')
  with patch.object(h,'repository_hot_gate',no_enumeration):reject('authenticate_host_before_repository_hot_access',lambda:h.run_query(c,bad,before,'SU-000001-T0001'))
  passed('full_cold_storage_gate_retained_separate',cold_gate_callable=callable(h.repository_gate))
 return {'status':'PASS','case_count':len(rows),'cases':rows,'synthetic_only':True,'real_corpus_reads':0,'fullbook_cold_calls':0,'runtime_sha256':h.runtime_pin(),'bundle_sha256':h.BUNDLE_SHA256,'scope':'Bounded metadata gate, not hostile same-UID filesystem tamper detection.'}
if __name__=='__main__':
 with h.local_environment():out=run()
 (HERE/'HOT_GATE_TEST_RESULTS.json').write_bytes(h.canonical(out));print(json.dumps({'status':'PASS','cases':len(rows)}))
