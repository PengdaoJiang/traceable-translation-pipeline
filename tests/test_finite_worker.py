import json,tempfile,unittest,uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from runtime import finite_worker as w

class FakeProcess:
    pid=999999
    returncode=0
    events=[]
    def __init__(self,args,**kwargs):
        self.job=Path(kwargs['cwd']);self.out=kwargs['stdout']
    def communicate(self,prompt,timeout):
        for event in self.events:self.out.write(json.dumps(event)+'\n')
        self.out.flush();(self.job/'result.md').write_text('Synthetic candidate',encoding='utf-8')
    def poll(self):return self.returncode

class WorkerTests(unittest.TestCase):
    def exercise(self,events):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);scope=root/'scope.txt';scope.write_text('Synthetic scope',encoding='utf-8')
            prompt=root/'input.txt';prompt.write_text('Produce a fixture.',encoding='utf-8')
            args=SimpleNamespace(exe=Path('unused-cli'),effort='configured',model='configured',sandbox='read-only',owner=str(uuid.uuid4()),scope=scope,workflow='construction',timeout=5)
            FakeProcess.events=events;w.STOP.clear()
            with patch.object(w.subprocess,'Popen',FakeProcess):result=w.run_one(args,prompt,root/'job')
            self.assertEqual(w.ACTIVE,{})
            self.assertEqual(json.loads((root/'job/request.json').read_text())['status'],result['status'])
            return result
    def test_actual_event_identity_and_receipt(self):
        identity=str(uuid.uuid4());r=self.exercise([{'type':'thread.started','thread_id':identity},{'type':'turn.completed','usage':{}}])
        self.assertEqual(r['status'],'completed');self.assertEqual(r['task_id'],identity)
    def test_zero_exit_without_completion_is_failure(self):
        self.assertEqual(self.exercise([])['status'],'failed')
    def test_failure_event_wins_over_completed(self):
        r=self.exercise([{'type':'thread.started','thread_id':str(uuid.uuid4())},{'type':'error'},{'type':'turn.completed'}])
        self.assertEqual(r['status'],'failed')
    def test_multiple_identities_are_not_one_execution(self):
        r=self.exercise([{'type':'thread.started','thread_id':str(uuid.uuid4())},{'type':'thread.started','thread_id':str(uuid.uuid4())},{'type':'turn.completed'}])
        self.assertEqual(r['status'],'failed')
if __name__=='__main__':unittest.main()
