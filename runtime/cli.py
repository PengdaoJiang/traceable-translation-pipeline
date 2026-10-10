"""Opt-in finite jobs; dry run is the default. No account or model defaults."""
import argparse,json,uuid
from concurrent.futures import ThreadPoolExecutor,as_completed
from pathlib import Path
from . import finite_worker as worker

def main():
 p=argparse.ArgumentParser();p.add_argument('prompts',nargs='+',type=Path)
 p.add_argument('--scope',required=True,type=Path);p.add_argument('--exe',required=True,type=Path)
 p.add_argument('--model',required=True);p.add_argument('--effort',required=True)
 p.add_argument('--owner',required=True);p.add_argument('--out',required=True,type=Path)
 p.add_argument('--workers',type=int,default=1);p.add_argument('--timeout',type=int,default=1800)
 p.add_argument('--execute',action='store_true')
 p.add_argument('--sandbox',choices=['read-only','workspace-write'],default='read-only')
 a=p.parse_args();a.owner=str(uuid.UUID(a.owner));a.workflow='construction'
 a.exe=a.exe.resolve(strict=True);a.scope=a.scope.resolve(strict=True);a.out=a.out.resolve()
 a.prompts=[x.resolve(strict=True) for x in a.prompts]
 if not 1<=len(a.prompts)<=a.workers<=8:p.error('one to eight jobs, no hidden queue')
 if len(set(a.prompts))!=len(a.prompts):p.error('duplicate prompt paths')
 if not 1<=a.timeout<=7200:p.error('timeout must be bounded')
 if a.out.exists():p.error('output exists; never overwrite or silently resume')
 if not a.execute:
  print(json.dumps({'dry_run':True,'jobs':[worker.command(a,a.out/f'job-{i:02}') for i in range(len(a.prompts))]},indent=2));return
 a.out.mkdir(parents=True,exist_ok=False);worker.STOP.clear();results=[]
 pool=ThreadPoolExecutor(max_workers=a.workers)
 futures=[pool.submit(worker.run_one,a,prompt,a.out/f'job-{i:02}') for i,prompt in enumerate(a.prompts)]
 try:
  for f in as_completed(futures):results.append(f.result())
 except BaseException:
  worker.STOP.set()
  with worker.LOCK:active=list(worker.ACTIVE.values())
  for process in active:worker.stop_process(process)
  raise
 finally:
  pool.shutdown(wait=True,cancel_futures=True)
  worker.save(a.out/'summary.json',{'jobs':results,'stopped':worker.STOP.is_set(),'meaning':'Execution receipts are not content acceptance.'})
 raise SystemExit(0 if len(results)==len(a.prompts) and all(x['status']=='completed' for x in results) else 1)
if __name__=='__main__':main()
