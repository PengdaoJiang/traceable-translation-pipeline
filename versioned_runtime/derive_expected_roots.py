#!/usr/bin/env python3
"""Independent byte-format oracle: old accepted clean M -> new code-bound M.

No import of either runtime and no native build/cold. Caller authenticates old
N0/M, old/new manifests and exact source repository. Only small M metadata read.
"""
import argparse,hashlib,json,os,pathlib,re,subprocess
canon=lambda value:json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
sha=lambda raw:hashlib.sha256(raw).hexdigest()
def oid(kind,raw):return hashlib.sha1(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def require(ok,reason):
 if not ok:raise ValueError(reason)
def parse_tree(raw):
 result={};at=0
 while at<len(raw):
  end=raw.index(b'\0',at);mode,name=raw[at:end].decode().split(' ',1);value=raw[end+1:end+21].hex();require(len(value)==40,'truncated tree');require(name not in result,'duplicate tree entry');result[name]=(mode,value);at=end+21
 return result
def tree_bytes(entries):return b''.join(mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(value) for name,(mode,value) in sorted(entries.items(),key=lambda item:item[0]+('/' if item[1][0]=='40000' else '')))
def derive(repository,n0,m,old_manifest,new_manifest):
 require(old_manifest['schema_pin']==new_manifest['schema_pin'] and old_manifest['native_schema_pin']==new_manifest['native_schema_pin'],'schema changed; this oracle is inapplicable')
 environment={k:v for k,v in os.environ.items() if not k.startswith('GIT_')};environment.update(GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL=os.devnull,GIT_NO_REPLACE_OBJECTS='1',GIT_ALLOW_PROTOCOL='')
 reads=[]
 def read(kind,value):
  require(re.fullmatch('[0-9a-f]{40}',value) is not None,'exact oid')
  raw=subprocess.check_output(['git','--git-dir='+str(pathlib.Path(repository).resolve()),'cat-file',kind,value],env=environment,stderr=subprocess.PIPE,timeout=30);require(len(raw)<=65536 and oid(kind,raw)==value,'bounded exact object');reads.append({'kind':kind,'oid':value,'bytes':len(raw),'sha256':sha(raw)});return raw
 old_commit=read('commit',m);header,message=old_commit.split(b'\n\n',1);lines=header.splitlines();require([line for line in lines if line.startswith(b'parent ')]==[b'parent '+n0.encode()],'clean M parent N0');old_top=lines[0][5:].decode();entries=parse_tree(read('tree',old_top));require(set(entries)=={'combined.json','grant.json','native','pending'},'exact M tree')
 descriptor_raw=read('blob',entries['combined.json'][1]);descriptor=json.loads(descriptor_raw);require(canon(descriptor)==descriptor_raw,'canonical descriptor');require(descriptor['code']==old_manifest['compound_pin'] and descriptor['native_baseline']==n0,'old descriptor binding');require(descriptor['schema']['native_schema']==old_manifest['native_schema_pin'],'native schema binding')
 migration=json.loads(message);require(message==canon(migration)+b'\n','canonical migration message');require(migration['code']==old_manifest['compound_pin'] and migration['native_baseline']==n0 and migration['schema']==old_manifest['schema_pin'],'old migration binding')
 descriptor['code']=new_manifest['compound_pin'];migration['code']=new_manifest['compound_pin'];new_descriptor=canon(descriptor);entries['combined.json']=('100644',oid('blob',new_descriptor));new_tree=tree_bytes(entries);lines[0]=b'tree '+oid('tree',new_tree).encode();new_commit=b'\n'.join(lines)+b'\n\n'+canon(migration)+b'\n';new_m=oid('commit',new_commit)
 return {'format':'platform-code-differential-expected-roots/v1','expected_N0':n0,'previous_M':m,'expected_M':new_m,'old_compound_pin':old_manifest['compound_pin'],'new_compound_pin':new_manifest['compound_pin'],'old_native_pin':old_manifest['native_pin'],'new_native_pin':new_manifest['native_pin'],'schema_pin':new_manifest['schema_pin'],'native_schema_pin':new_manifest['native_schema_pin'],'changed_M_fields':['combined.json.code','migration commit message.code','derived tree/commit OIDs'],'native_payload_changes':0,'oracle_imported_runtime':False,'new_build_report_used':False,'source_metadata_reads':reads,'source_bytes_read':sum(row['bytes'] for row in reads),'applicability':'Only unchanged native schema/encoder/genesis semantics with platform-side-effect-only code changes. Confirmed by source diff and synthetic differential regression; fullbook candidate must match these independent expected roots.'}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('repository','native-baseline','baseline','old-manifest','new-manifest','output'):p.add_argument('--'+name,required=True)
 a=p.parse_args();old=json.loads(pathlib.Path(a.old_manifest).read_bytes());new=json.loads(pathlib.Path(a.new_manifest).read_bytes());result=derive(a.repository,a.native_baseline,a.baseline,old,new);pathlib.Path(a.output).write_bytes(canon(result));print(json.dumps(result))
