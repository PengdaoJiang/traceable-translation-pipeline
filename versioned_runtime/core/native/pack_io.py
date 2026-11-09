"""Bounded file-backed Git transport. Storage preparation, never admission.

V22 comparison flags: compression=6, threads=1, window=0, no reuse delta/object.
Subprocess AS cap 512 MiB, CPU ceil(timeout), FSIZE explicit; parent wall stop.
Diagnostic pipes are drained into exclusive private capped files, never PIPE
communicate() accumulation. Incomplete artifacts are retained for diagnosis.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import queue
import threading
import subprocess
import sys
import time
import uuid
import types

_PLATFORM_PATH=Path(__file__).resolve().parent.parent.parent/'platform_api.py'
PLATFORM=types.ModuleType('pack_semantic_platform_api');PLATFORM.__file__=str(_PLATFORM_PATH)
sys.modules[PLATFORM.__name__]=PLATFORM
exec(compile(_PLATFORM_PATH.read_bytes(),str(_PLATFORM_PATH),'exec'),PLATFORM.__dict__)

AS_LIMIT=512*1024*1024
STDERR_LIMIT=65536
STDOUT_LIMIT=4096
FLAGS=['-c','pack.compression=6','pack-objects','--stdout','--revs','--threads=1','--window=0','--no-reuse-delta','--no-reuse-object']
class PackError(RuntimeError): pass

def _fsync_dir(path):
    PLATFORM.sync_directory(path)

def _exclusive(path):
    return PLATFORM.open_exclusive(path,buffering=0)

def _hash(path,cap):
    h=hashlib.sha256();n=0
    with open(path,'rb') as f:
        while True:
            chunk=f.read(65536)
            if not chunk:break
            n+=len(chunk)
            if n>cap:raise PackError('PACK_BYTE_CAP')
            h.update(chunk)
    return n,h.hexdigest()

def _limits(max_bytes,timeout):
    if type(max_bytes) is not int or max_bytes<=0 or not isinstance(timeout,(int,float)) or not math.isfinite(timeout) or timeout<=0:raise PackError('INVALID_LIMIT')

def _run(r,args,stdin,stdout,logbase,file_cap,timeout):
    start=time.monotonic();errpath=Path(str(logbase)+'.stderr.incomplete')
    outpath=Path(str(logbase)+'.stdout.incomplete')
    with _exclusive(errpath) as err:
        out=_exclusive(outpath) if stdout is None else None
        command=[sys.executable,'-B',str(Path(__file__).resolve()),'--child',str(file_cap),str(max(1,math.ceil(timeout))),str(AS_LIMIT),'git','-c','gc.auto=0','-c','pack.threads=1','--git-dir='+str(r.path),*args]
        proc=None;counts={'stderr':0,'stdout':0};readers=[];streams=[]
        chunks=queue.Queue(maxsize=32);stop=threading.Event()
        def read_pipe(name,stream):
            try:
                while not stop.is_set():
                    data=stream.read(8192)
                    while not stop.is_set():
                        try:chunks.put((name,data),timeout=.05);break
                        except queue.Full:pass
                    if not data:break
            except (OSError,ValueError):
                if not stop.is_set():
                    while not stop.is_set():
                        try:chunks.put((name,None),timeout=.05);break
                        except queue.Full:pass
        try:
            proc=PLATFORM.spawn_supervised(command,stdin=stdin,stdout=subprocess.PIPE if out else stdout,stderr=subprocess.PIPE)
            streams=[('stderr',proc.stderr,err,STDERR_LIMIT)]
            if out:streams.append(('stdout',proc.stdout,out,STDOUT_LIMIT))
            sinks={name:(sink,cap) for name,stream,sink,cap in streams};closed=set()
            for name,stream,sink,cap in streams:
                thread=threading.Thread(target=read_pipe,args=(name,stream),daemon=True);thread.start();readers.append(thread)
            while len(closed)<len(streams) or proc.poll() is None:
                if time.monotonic()-start>=timeout:raise PackError('WALL_DEADLINE')
                try:name,data=chunks.get(timeout=.05)
                except queue.Empty:continue
                if data is None:raise PackError('DIAGNOSTIC_READ_FAILED')
                if not data:closed.add(name);continue
                sink,cap=sinks[name];remaining=cap-counts[name]
                sink.write(data[:remaining]);counts[name]+=len(data)
                if counts[name]>cap:raise PackError('DIAGNOSTIC_CAP')
            if proc.wait()!=0:raise PackError('GIT_PROCESS_FAILED')
            PLATFORM.sync_file(err)
            if out:PLATFORM.sync_file(out)
            return {'wall_seconds':time.monotonic()-start,'stderr_bytes':counts['stderr'],'stdout_bytes':counts['stdout'],'address_space_cap':AS_LIMIT,'file_size_cap':file_cap,'cpu_seconds_cap':max(1,math.ceil(timeout)),'stdout_path':str(outpath) if out else None}
        finally:
            stop.set()
            if proc is not None and (proc.poll() is None or any(thread.is_alive() for thread in readers)):
                PLATFORM.terminate_and_reap(proc)
            for name,stream,sink,cap in streams:stream.close()
            for thread in readers:thread.join(timeout=5)
            if any(thread.is_alive() for thread in readers):raise PackError('DIAGNOSTIC_READER_NOT_REAPED')
            if out:out.close()


def pack(r,root,destination,max_bytes,timeout):
    """Export one root; successful descriptor is never an admission proof."""
    _limits(max_bytes,timeout)
    if not re.fullmatch('[0-9a-f]{40}',root):raise PackError('ROOT_SYNTAX')
    dest=Path(destination).resolve();dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    marker=Path(str(dest)+'.completed.json');partial=Path(str(dest)+'.incomplete')
    if dest.exists() or marker.exists():raise PackError('DESTINATION_EXISTS')
    revs=Path(str(dest)+'.revs.incomplete')
    with _exclusive(revs) as f:f.write((root+'\n').encode());PLATFORM.sync_file(f)
    with open(revs,'rb') as inp, _exclusive(partial) as out:
        measured=_run(r,FLAGS,inp,out,partial,max_bytes,timeout)
        PLATFORM.sync_file(out)
    n,digest=_hash(partial,max_bytes)
    if n<12:raise PackError('PACK_HEADER')
    with open(partial,'rb') as f:
        if f.read(4)!=b'PACK':raise PackError('PACK_HEADER')
    PLATFORM.publish_noreplace(partial,dest);_fsync_dir(dest.parent)
    result={'status':'COMPLETE_TRANSPORT_NOT_ADMISSION','path':str(dest),'bytes':n,'sha256':digest,'root':root,'excluded_root':None,'compression':6,'threads':1,'window':0,'reuse_delta':False,'reuse_object':False,**measured}
    marker_partial=Path(str(marker)+'.incomplete')
    with _exclusive(marker_partial) as f:f.write(json.dumps(result,sort_keys=True,separators=(',',':')).encode()+b'\n');PLATFORM.sync_file(f)
    PLATFORM.publish_noreplace(marker_partial,marker)
    _fsync_dir(marker.parent)
    return result

def _invalidate(r):
    if getattr(r,'epoch',None) is not None or getattr(r,'staged',{}):raise PackError('IMPORT_REQUIRES_QUIESCENT_REPO')
    r.close()
    reset=r.git.__func__.__globals__.get('reset_service_cache')
    if reset is not None:reset(r.path)
    for name in ('memo','trees','required','operation_admitted'):
        obj=getattr(r,name,None)
        if obj is not None:obj.clear()

def import_pack(r,pack_path,max_bytes,timeout):
    """Import objects only. Caller must authenticate root and run full admission."""
    _limits(max_bytes,timeout);path=Path(pack_path).resolve()
    size,digest=_hash(path,max_bytes)
    _invalidate(r)
    logdir=Path(r.path)/('pack-io-'+uuid.uuid4().hex);logdir.mkdir(mode=0o700)
    # Pack-index fanout can exceed a heavily compressed pack's length.
    file_cap=max_bytes*4+1048576
    try:
        with open(path,'rb') as inp:
            measured=_run(r,['index-pack','--stdin','--strict','--threads=1'],inp,None,logdir/'index',file_cap,timeout)
        raw=Path(measured['stdout_path']).read_bytes()
        if not re.fullmatch(rb'pack\t[0-9a-f]{40}\n',raw):raise PackError('INDEX_RESULT')
        oid=raw[5:45].decode();packdir=Path(r.path)/'objects/pack'
        synced=[]
        for suffix in ('.pack','.idx'):
            file=packdir/('pack-'+oid+suffix)
            with open(file,'rb') as f:PLATFORM.sync_file(f)
            synced.append(str(file))
        _fsync_dir(packdir);_fsync_dir(packdir.parent)
        # Caller must supply exact artifact identity; detect changed input too.
        if _hash(path,max_bytes)!=(size,digest):raise PackError('INPUT_CHANGED')
        return {'status':'IMPORTED_STORAGE_ONLY_NOT_ADMISSION','sha256':digest,'bytes':size,'pack_oid':oid,'synced':synced,'ref_publication':False,**measured}
    finally:_invalidate(r)

if __name__=='__main__':
    if len(sys.argv)<7 or sys.argv[1]!='--child':raise SystemExit(2)
    PLATFORM.set_worker_limits(memory_bytes=int(sys.argv[4]),cpu_seconds=int(sys.argv[3]),file_bytes=int(sys.argv[2]))
    os.execvp(sys.argv[5],sys.argv[5:])
