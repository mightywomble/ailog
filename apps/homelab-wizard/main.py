"""homelab-wizard: the homelab pipeline as a flow.

wizard.yaml → stack.yml → commit → build.yml → PR → ship.yml → proxy host →
tests. Long actions are jobs, streamed to the browser over SSE.
"""
import json
import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import assist
import core
import forge
import pipeline
import swarmio
from jobs import hub

HERE = os.path.dirname(os.path.abspath(__file__))  # web/ is served from the image
app = FastAPI(title="homelab-wizard", docs_url="/api/docs")


class SettingsPatch(BaseModel):
    patch: dict


class ServiceBody(BaseModel):
    entry: dict
    commit: bool = False
    message: str | None = None


class ComposeBody(BaseModel):
    compose: str


class ConvertBody(BaseModel):
    compose: str
    name: str
    hint: str = ""


class PullBody(BaseModel):
    image: str
    node: str | None = None


class PipelineBody(BaseModel):
    message: str | None = None
    deploy: bool = True
    expose: dict | None = None
    test: dict | None = None


class ExposeBody(BaseModel):
    domain: str
    forward_host: str = ""
    forward_port: int
    cert_id: int | None = None
    advanced: str = ""
    dry_run: bool = False
    dns: bool = True


class TestBody(BaseModel):
    stack: str
    domain: str | None = None
    port: int | None = None
    creds: dict | None = None


def _commit(message, files):
    try:
        return core.commit_and_push(message, files=files)
    except core.GitError as exc:
        return {"committed": False, "error": str(exc)[:400]}


# ------------------------------------------------------------------ state

@app.get("/api/state")
def state():
    settings = core.load()
    try:
        if settings.get("gitea_token"):
            core.ensure(settings) if not os.path.isdir(
                os.path.join(settings["repo_dir"], ".git")) else core.sync_if_stale(settings)
        repo = {"ok": True, "branch": settings.get("work_branch"), "commit": core.head()}
    except Exception as exc:
        repo = {"ok": False, "error": str(exc)[:200]}
    try:
        services = pipeline.wizard_services()
        wizard = {"ok": True, "count": len(services),
                  "defaults": pipeline.load_wizard().get("defaults") or {}}
    except Exception as exc:
        services, wizard = [], {"ok": False, "error": str(exc)[:200]}
    return {"settings": core.public(settings), "repo": repo, "wizard": wizard,
            "services": [pipeline.summarise(s) for s in services],
            "jobs": hub.list(12), "domain_suffix": settings.get("domain_suffix")}


@app.get("/api/services/{name}")
def service_detail(name: str):
    svc = pipeline.find_service(name)
    if not svc:
        raise HTTPException(404, f"{name} is not in wizard.yaml")
    try:
        stack = open(os.path.join(core.repo_dir(), f"stacks/{name}/stack.yml")).read()
    except Exception:
        stack = ""
    return {"entry": svc, "stack": stack}


@app.put("/api/services/{name}")
def service_save(name: str, body: ServiceBody):
    entry = dict(body.entry)
    entry["name"] = name
    res = pipeline.save_service(entry)
    if not res.get("ok"):
        return JSONResponse(status_code=400, content=res)
    if body.commit:
        res["commit"] = _commit(body.message or f"wizard: {name}", res["files"])
    return res


@app.delete("/api/services/{name}")
def service_delete(name: str):
    res = pipeline.delete_service(name)
    if not res.get("ok"):
        return JSONResponse(status_code=400, content=res)
    res["commit"] = _commit(f"wizard: remove {name}", res["files"])
    return res


# ------------------------------------------------------------------ settings / models

@app.get("/api/settings")
def settings_get():
    return core.public()


@app.put("/api/settings")
def settings_put(body: SettingsPatch):
    core.save({k: v for k, v in body.patch.items() if v != "••••••"})
    return core.public()


@app.get("/api/models")
def models():
    return {"models": assist.models(), "current": core.load().get("openrouter_model")}


# ------------------------------------------------------------------ ports / compose

@app.get("/api/ports")
def ports():
    return swarmio.registry(core.load(), pipeline.load_wizard())


@app.post("/api/compose/audit")
def compose_audit(body: ComposeBody):
    try:
        return assist.audit_compose(body.compose)
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.post("/api/compose/validate")
def compose_validate(body: ComposeBody):
    return assist.validate_stack(body.compose)


@app.post("/api/ai/convert")
def ai_convert(body: ConvertBody):
    settings = core.load()

    def work(job):
        job.step("audit", "ok", f"{len(body.compose)} bytes")
        job.step("openrouter", "running", settings.get("openrouter_model"))
        res = assist.convert(settings, body.compose, body.name, body.hint)
        job.step("openrouter", "ok" if res["ok"] else "failed",
                 f"{len(res['changes'])} changes, {len(res['problems'])} problems")
        for c in res["changes"]:
            job.log(f"· {c.get('what')}: {c.get('why')}")
        for p in res["problems"]:
            job.log("PROBLEM " + p)
        return res

    return {"job": hub.run("convert", f"convert {body.name}", work, meta={"name": body.name}).id}


# ------------------------------------------------------------------ jobs

@app.get("/api/jobs")
def jobs_list():
    return {"jobs": hub.list(30)}


@app.get("/api/jobs/{job_id}")
def job_get(job_id: str):
    job = hub.get(job_id)
    if not job:
        raise HTTPException(404, "no such job")
    return job.snapshot()


@app.get("/api/jobs/{job_id}/events")
async def job_events(job_id: str):
    job = hub.get(job_id)
    if not job:
        raise HTTPException(404, "no such job")

    async def gen():
        async for event in job.subscribe():
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ------------------------------------------------------------------ actions

@app.post("/api/pull")
def pull(body: PullBody):
    return {"job": hub.run("pull", f"pull {body.image}",
                           lambda j: pipeline.pull_image(j, body.image, body.node),
                           meta={"image": body.image}).id}


@app.post("/api/build")
def build(message: str | None = None):
    return {"job": hub.run("build", "build + smoke test", lambda j: pipeline.build(j, message)).id}


@app.post("/api/ship")
def ship(message: str | None = None):
    return {"job": hub.run("ship", "PR → release → deploy", lambda j: pipeline.ship(j, message)).id}


@app.post("/api/pipeline")
def pipeline_run(body: PipelineBody):
    def work(job):
        out = {}
        job.step("sync repo", "running")
        core.ensure(core.load())
        job.step("sync repo", "ok")
        out["build"] = pipeline.build(job, body.message)
        if body.deploy:
            out["ship"] = pipeline.ship(job, body.message)
        if body.expose:
            settings = core.load()
            job.step("proxy host", "running", body.expose["domain"])
            out["expose"] = forge.create_host(
                settings, body.expose["domain"],
                body.expose.get("forward_host") or settings["ingress_ip"],
                body.expose["port"], body.expose.get("cert_id"),
                body.expose.get("advanced", ""))
            job.step("proxy host", "ok", f"id {out['expose']['id']}")
            if body.expose.get("dns", True):
                out["dns"] = forge.add_dns(settings, body.expose["domain"])
                job.log(f"dns: {out['dns']}")
        if body.test:
            out["tests"] = pipeline.test_stack(job, body.test["stack"],
                                               body.test.get("domain"), body.test.get("port"),
                                               body.test.get("creds"))
        return out

    return {"job": hub.run("pipeline", "build → ship → expose → test", work,
                           meta=body.model_dump()).id}


@app.post("/api/tests")
def tests(body: TestBody):
    return {"job": hub.run("test", f"test {body.stack}",
                           lambda j: pipeline.test_stack(j, body.stack, body.domain,
                                                         body.port, body.creds)).id}


@app.get("/api/stack/{name}")
def stack_state(name: str):
    try:
        settings = core.load()
        return {"replicas": swarmio.service_replicas(settings, name),
                "tasks": swarmio.service_ps(settings, name)}
    except Exception as exc:
        raise HTTPException(502, str(exc)[:300])


# ------------------------------------------------------------------ exposure

@app.get("/api/expose/hosts")
def expose_hosts():
    settings = core.load()
    return {"hosts": forge.list_hosts(settings), "certs": forge.certificates(settings)}


@app.post("/api/expose")
def expose_create(body: ExposeBody):
    settings = core.load()
    try:
        res = forge.create_host(settings, body.domain,
                                body.forward_host or settings["ingress_ip"],
                                body.forward_port, body.cert_id, body.advanced, body.dry_run)
    except forge.ForgeError as exc:
        raise HTTPException(400, str(exc))
    if body.dns and not body.dry_run:
        res["dns"] = forge.add_dns(settings, body.domain)
    return res


# ------------------------------------------------------------------ static

@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/")
def index():
    return FileResponse(os.path.join(HERE, "web", "index.html"))


app.mount("/static", StaticFiles(directory=os.path.join(HERE, "web")), name="static")
