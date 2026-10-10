"""Finite source-derived worker lifecycle; importing never launches a model."""
from datetime import datetime, timezone
import hashlib,json,os,subprocess,threading,time,uuid
from pathlib import Path
ACTIVE={}
LOCK=threading.Lock()
STOP=threading.Event()

def reasoning_effort(args):
    return args.effort

def command(args,job):
    return [str(args.exe),"--no-daemon","--ask-for-approval","never","exec",
            "--ignore-user-config","--ephemeral","--skip-git-repo-check",
            "--sandbox",args.sandbox,"--model",args.model,
            "-c",f'model_reasoning_effort="{args.effort}"',
            "-c","agents.enabled=false","-c",'web_search="disabled"',
            "--cd",str(job),"--output-last-message",str(job/"result.md"),
            "--json","--color","never","-"]

def job_prompt(args,prompt_path,job):
    return ("Only perform the supplied task. Do not delegate, publish, send messages, "
            "or change input files. Put deliverables in the current job directory. "
            "Host-owned prompt.txt, request.json, stdout.jsonl, stderr.log and result.md "
            "must not be edited. Output is a candidate, not acceptance.\n\n"
            +args.scope.read_text(encoding="utf-8")+"\n\n"
            +prompt_path.read_text(encoding="utf-8"))

def now():
    return datetime.now(timezone.utc).isoformat()

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def save(path, value):
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)

def stop_process(proc):
    if proc.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(["taskkill.exe", "/PID", str(proc.pid), "/T", "/F"],
                       capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    else:
        proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()

def run_one(args, prompt_path, job):
    if STOP.is_set():
        return {"prompt": str(prompt_path), "status": "not_started"}
    job.mkdir()
    prompt = job_prompt(args, prompt_path, job)
    (job / "prompt.txt").write_text(prompt, encoding="utf-8")
    record = {"status": "running", "owner_task_id": args.owner,
              "started_at": now(), "prompt_path": str(prompt_path),
              "prompt_sha256": sha(job / "prompt.txt"), "task_id": None,
              "requested_model": args.model,
              "requested_effort": reasoning_effort(args), "workflow": args.workflow,
              "execution_access": args.sandbox,
              "args": command(args, job), "usage": [],
              "literary_status": ("unaccepted experimental output" if args.workflow == "tp"
                                  else "unaccepted construction output")}
    record["source_scope_sha256"] = sha(args.scope)
    save(job / "request.json", record)
    started = time.monotonic()
    proc = None
    try:
        # Reuse ChatGPT sign-in, never silently fall back to an inherited API key.
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        for name in ("OPENAI_API_KEY", "CODEX_API_KEY"):
            env.pop(name, None)
        with (job / "stdout.jsonl").open("w", encoding="utf-8") as stdout, \
             (job / "stderr.log").open("w", encoding="utf-8") as stderr:
            with LOCK:
                if STOP.is_set():
                    raise RuntimeError("stopped before launch")
                proc = subprocess.Popen(record["args"], stdin=subprocess.PIPE,
                                        stdout=stdout, stderr=stderr, cwd=job, env=env,
                                        text=True, encoding="utf-8",
                                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
                ACTIVE[proc.pid] = proc
            record["pid"] = proc.pid
            save(job / "request.json", record)
            try:
                proc.communicate(prompt, timeout=args.timeout)
            except subprocess.TimeoutExpired:
                stop_process(proc)
                raise RuntimeError(f"timeout after {args.timeout} seconds; no automatic retry")
            record["exit_code"] = proc.returncode
        if STOP.is_set():
            raise RuntimeError("stopped by controller")
        if proc.returncode:
            raise RuntimeError(f"CLI exit {proc.returncode}; inspect stderr.log")
        completed = False
        identities = set()
        failure = False
        for line in (job / "stdout.jsonl").read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if event.get("type") == "thread.started":
                identities.add(str(uuid.UUID(event["thread_id"])))
            if event.get("type") in ("turn.failed", "error"):
                failure = True
            if event.get("type") == "turn.completed":
                completed = True
                record["usage"].append(event.get("usage", {}))
        if len(identities) == 1:
            record["task_id"] = identities.pop()
        if failure or not completed or not record["task_id"] or not (job / "result.md").is_file():
            raise RuntimeError("missing real task identity, completed turn, or final output")
        if not (job / "result.md").read_text(encoding="utf-8").strip():
            raise RuntimeError("empty final output")
        record.update(status="completed", result_sha256=sha(job / "result.md"))
    except Exception as exc:
        record.update(status="failed", error=str(exc))
        if proc is not None:
            stop_process(proc)
    finally:
        if proc is not None:
            with LOCK:
                ACTIVE.pop(proc.pid, None)
        # A failed request can still have a real identity; retain it for diagnosis.
        log = job / "stdout.jsonl"
        if record["task_id"] is None and log.exists():
            identities = set()
            for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    event = json.loads(line)
                    if event.get("type") == "thread.started":
                        identities.add(str(uuid.UUID(event["thread_id"])))
                except (ValueError, KeyError):
                    continue
            if len(identities) == 1:
                record["task_id"] = identities.pop()
        record.update(finished_at=now(), elapsed_seconds=round(time.monotonic() - started, 3))
        save(job / "request.json", record)
    return record
