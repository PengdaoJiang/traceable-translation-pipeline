#!/usr/bin/env python3
"""Core/host import, capability failure and pipe cleanup boundary checks."""
import builtins,importlib.util,json,os,pathlib,subprocess,sys,tempfile
from unittest.mock import patch
sys.dont_write_bytecode=True
HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('boundary_host',HERE/'host_checkpoint.py');h=importlib.util.module_from_spec(spec);sys.modules[spec.name]=h;spec.loader.exec_module(h)
rows=[]
def passed(name,**more):rows.append({'case':name,'pass':True,**more})
def reject(name,fn,kinds):
 try:fn()
 except kinds:passed(name);return
 raise AssertionError(name+' accepted')
code=r'''
import builtins, importlib, os, pathlib, sys, types
real_import=builtins.__import__;real_dynamic=importlib.import_module
def guarded(name,*args,**kw):
 if name.split('.')[0] in ('fcntl','resource','msvcrt','winreg'):raise ModuleNotFoundError('deliberately unavailable')
 return real_import(name,*args,**kw)
def guarded_dynamic(name,*args,**kw):
 if name.split('.')[0] in ('fcntl','resource','msvcrt','winreg'):raise ModuleNotFoundError('deliberately unavailable')
 return real_dynamic(name,*args,**kw)
builtins.__import__=guarded;importlib.import_module=guarded_dynamic
for name in ('O_DIRECTORY','O_NOFOLLOW','killpg','setsid','getpgid','set_blocking'):
 if hasattr(os,name):delattr(os,name)
root=pathlib.Path(sys.argv[1])
for name,path in [('independent_host',root/'host_checkpoint.py'),('independent_domain',root/'core/native_pending.py')]:
 module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module;exec(compile(path.read_bytes(),str(path),'exec'),module.__dict__)
print('whole-domain-and-host-import-ok')
'''
result=subprocess.run([sys.executable,'-B','-c',code,str(HERE)],capture_output=True,text=True,timeout=30);assert result.returncode==0,result.stderr;passed('whole_host_domain_import_without_optional_platform_modules_or_flags')
with tempfile.TemporaryDirectory(prefix='core-platform-boundary-') as temp:
 root=pathlib.Path(temp);repo=root/'r.git';subprocess.run(['git','init','--bare','--quiet','--initial-branch=main',str(repo)],check=True,env=h.git_environment());p=h.load_core();r=p.Repo(repo)
 real_import=builtins.__import__
 def deny_resource(name,*args,**kw):
  if name.split('.')[0] in ('resource','fcntl'):raise ImportError('not available')
  return real_import(name,*args,**kw)
 with patch.object(builtins,'__import__',deny_resource):
  cap=p.synthetic_fixtures.capture(1,4);inv={cap['owner']:p.k.sha(p.k.canonical(p.native.capture_receipt(cap)))};_,s=p.build_initial_pending_session(r,[cap],expected_inventory=inv,mode='synthetic_scale_only');answer=p.query_native(r,s,{'commit':s.root,'id':'SU-000001-T0001'})
 assert answer['responsibility']['status']=='UNKNOWN';passed('core_build_and_query_do_not_require_resource_or_fcntl')
 baseline=s.root
 request={'op':'revise_text','id':'SU-000001-T0001','expected_version':0,'text':'Synthetic boundary change.','reason':'local_technical_revision'}
 for method in ('sync_file','sync_directory','publish_noreplace','repository_lock'):
  error=p.native.PLATFORM.CapabilityUnavailable(method,'deliberately absent')
  with patch.object(p.native.PLATFORM,method,side_effect=error):reject('missing_'+method+'_no_CAS',lambda:p.apply(r,s,request),(p.native.PLATFORM.CapabilityUnavailable,))
  assert s.root==r.ref()==baseline
 p.apply(r,s,request);passed('retry_after_restored_capability_exact_authorized_transition')
 raw=p.export(r,s);c=json.loads(raw);c['code']='0'*64;modified=h.canonical(c);reject('wrong_execution_pin_even_authenticated_bytes',lambda:p.lazy_restore(r,modified,h.sha(modified),s.root),(p.k.Rejected,))
 data=b'Synthetic missing durable object';oid=p.k.oid('blob',data)
 with patch.object(os,'set_blocking',None,create=True):assert r._persistent_probe({oid:('blob',data)})==[oid]
 passed('persistent_probe_works_without_nonblocking_pipe_primitive')
 original=p.k.subprocess.Popen;spawned=[]
 def recording(*a,**kw):
  child=original(*a,**kw);spawned.append((child,child.stdin,child.stdout,child.stderr));return child
 with patch.object(p.k.subprocess,'Popen',recording),patch.object(p.k.threading.Thread,'start',side_effect=RuntimeError('injected thread start failure')):
  reject('persistent_probe_thread_start_failure',lambda:r._persistent_probe({oid:('blob',data)}),(RuntimeError,))
 assert spawned and all(child.poll() is not None and all(f is None or f.closed for f in handles)for child,*handles in spawned);passed('failed_persistent_probe_reaps_process_and_closes_pipes')
 # Ref durability is explicit even when Git's fsync option is not passed.
 original_git=r.git;after_update=[False];synced=[];original_sync=p.native.PLATFORM.sync_directory
 def git_without_fsync(*args,**kwargs):
  args=list(args)
  if '-c' in args:
   for i in range(len(args)-1):
    if args[i:i+2]==['-c','core.fsync=all']:del args[i:i+2];break
  result=original_git(*args,**kwargs)
  if 'update-ref' in args:after_update[0]=True
  return result
 def observed_sync(path):
  if after_update[0]:synced.append(str(path))
  return original_sync(path)
 req={'op':'revise_text','id':'SU-000001-T0002','expected_version':0,'text':'Explicit ref fence.','reason':'local_technical_revision'}
 with patch.object(r,'git',git_without_fsync),patch.object(p.native.PLATFORM,'sync_directory',observed_sync):p.apply(r,s,req)
 expected_dirs=[str(repo/'refs/heads'),str(repo/'refs'),str(repo)]
 assert synced[-3:]==expected_dirs;passed('CAS_success_requires_explicit_ref_namespace_fence_without_git_fsync_option')
 for mode,target in [('journal','SU-000001-T0003'),('intent','SU-000001-T0004')]:
  req={'op':'revise_text','id':target,'expected_version':0,'text':'Durability recovery '+mode,'reason':'local_technical_revision'};parent=s.root
  parent_raw,journal=p.prepare_journal(r,s,req);ph,jh=h.sha(parent_raw),h.sha(journal)
  fail=p.native.PLATFORM.CapabilityUnavailable('directory_sync','injected post-CAS fence failure')
  with patch.object(p.k,'_durable_ref_fence',side_effect=fail):reject(mode+'_post_CAS_fence_failure_no_success',lambda:p.apply(r,s,req),(p.native.PLATFORM.CapabilityUnavailable,))
  assert r.ref()!=parent and s.root==parent
  def recovery():
   if mode=='journal':return p.recover_journal(r,parent_raw,ph,journal,jh,parent)
   p.recover(r,s,req);return s
  with patch.object(p.k,'_durable_ref_fence',side_effect=fail):reject(mode+'_recovery_still_requires_fence',recovery,(p.native.PLATFORM.CapabilityUnavailable,))
  actual=p.k._durable_ref_fence;fenced=[]
  def fence(repo,root):fenced.append(root);return actual(repo,root)
  with patch.object(p.k,'_durable_ref_fence',side_effect=fence):s=recovery()
  assert fenced==[r.ref()]==[s.root]
  p.export(r,s);passed(mode+'_already_published_recovery_reestablishes_durability')
 r.close()
report={'status':'PASS','case_count':len(rows),'cases':rows,'runtime_sha256':h.runtime_pin(),'platform_sha256':h.PLATFORM_SHA256,'bundle_sha256':h.BUNDLE_SHA256,'real_body_reads':0,'fullbook_builds':0,'scope':'Current environment and injected missing capabilities; not untested-platform certification.'}
(HERE/'CORE_PLATFORM_BOUNDARY_RESULTS.json').write_bytes(h.canonical(report));print(json.dumps({'status':'PASS','cases':len(rows)}))
