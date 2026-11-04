"""jobs: a thread per action, an SSE fan-out to every browser watching it."""
import asyncio
import time
import traceback
import uuid

MAX_LINES = 4000


class Job:
    def __init__(self, kind, title, meta=None):
        self.id = uuid.uuid4().hex[:12]
        self.kind, self.title, self.meta = kind, title, meta or {}
        self.status, self.lines, self.steps, self.progress = "queued", [], [], {}
        self.result = self.error = None
        self.created = self.updated = time.time()
        self._subs = []
        self._lock = __import__("threading").Lock()

    def _emit(self, event):
        with self._lock:
            self.updated = time.time()
            for q, loop in list(self._subs):
                try:
                    loop.call_soon_threadsafe(q.put_nowait, event)
                except Exception:
                    self._subs.remove((q, loop))

    def log(self, text):
        for line in (str(text).splitlines() or [""]):
            self.lines.append(line)
        del self.lines[:-MAX_LINES]
        self._emit({"type": "log", "text": str(text)})

    def step(self, name, status="running", detail=""):
        for s in self.steps:
            if s["name"] == name:
                s.update(status=status, detail=detail or s.get("detail", ""), ts=time.time())
                break
        else:
            self.steps.append({"name": name, "status": status, "detail": detail, "ts": time.time()})
        self._emit({"type": "steps", "steps": self.steps})

    def tick(self, **kw):
        self.progress.update(kw)
        self._emit({"type": "progress", "progress": self.progress})

    def finish(self, status, result=None, error=None):
        self.status, self.result, self.error = status, result, error
        self._emit({"type": "status", "status": status, "result": result, "error": error})

    def snapshot(self):
        return {"id": self.id, "kind": self.kind, "title": self.title, "status": self.status,
                "steps": self.steps, "progress": self.progress, "lines": self.lines[-400:],
                "result": self.result, "error": self.error, "meta": self.meta,
                "created": self.created, "updated": self.updated}

    async def subscribe(self):
        q, loop = asyncio.Queue(), asyncio.get_running_loop()
        with self._lock:
            self._subs.append((q, loop))
        await q.put({"type": "snapshot", "job": self.snapshot()})
        try:
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=20)
                except asyncio.TimeoutError:
                    if self.status in ("ok", "failed", "cancelled"):
                        return
                    yield {"type": "ping", "ts": time.time()}
                    continue
                yield event
                if event.get("type") == "status":
                    return
        finally:
            with self._lock:
                if (q, loop) in self._subs:
                    self._subs.remove((q, loop))


class Hub:
    def __init__(self):
        self.jobs = {}

    def get(self, job_id):
        return self.jobs.get(job_id)

    def run(self, kind, title, fn, meta=None):
        job = Job(kind, title, meta)
        self.jobs[job.id] = job
        done = [j for j in self.jobs.values() if j.status in ("ok", "failed", "cancelled")]
        if len(done) > 60:
            for old in sorted(done, key=lambda j: j.created)[:20]:
                self.jobs.pop(old.id, None)

        def wrapper():
            job.status = "running"
            job.log(f"── {title} ──")
            try:
                job.finish("ok", result=fn(job))
            except Exception as exc:
                job.log(f"FAILED: {exc}")
                job.log(traceback.format_exc(limit=4))
                job.finish("failed", error=str(exc)[:1000])

        import threading
        threading.Thread(target=wrapper, daemon=True, name=f"job-{job.id}").start()
        return job

    def list(self, limit=20):
        return [j.snapshot() for j in sorted(self.jobs.values(), key=lambda j: j.created,
                                             reverse=True)[:limit]]


hub = Hub()
