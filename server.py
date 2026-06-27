import asyncio
import json
from dataclasses import asdict

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import config

load_dotenv()

app = FastAPI(title="CoSentinel")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)
app.mount("/static", StaticFiles(directory="static"), name="static")


class ScanRequest(BaseModel):
    repo_url: str
    github_token: str = ""
    model: str = ""


class PRRequest(BaseModel):
    repo_url: str
    github_token: str
    finding_ids: list[str]


@app.get("/")
async def root():
    return FileResponse("static/index.html")


@app.get("/api/models")
async def get_models():
    from agent import get_available_models
    return {"models": get_available_models()}


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "model": config.REGOLO_MODEL,
        "scanners": ["deps", "secrets", "code", "config", "git_history"],
    }


@app.post("/api/scan")
async def scan(req: ScanRequest):
    from scan_service import scan_repository

    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(
            None, scan_repository, req.repo_url, req.github_token, req.model or None
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scans")
async def scans(repo_url: str):
    from scan_service import list_scan_history

    return {"scans": list_scan_history(repo_url)}


@app.get("/api/scans/{scan_id}")
async def scan_detail(scan_id: str):
    from scan_service import get_scan_record

    record = get_scan_record(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return record


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str):
    from scan_service import delete_scan_record

    if not delete_scan_record(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"deleted": True, "scan_id": scan_id}


@app.get("/api/scan/stream")
async def scan_stream(repo_url: str, github_token: str = "", model: str = ""):
    """SSE endpoint: streams progress events then the final result."""
    from scan_service import scan_repository

    def emit(data: dict) -> str:
        return f"data: {json.dumps(data)}\n\n"

    async def generate():
        loop = asyncio.get_event_loop()
        queue: asyncio.Queue[dict] = asyncio.Queue()

        def progress_cb(event: dict) -> None:
            loop.call_soon_threadsafe(queue.put_nowait, event)

        future = loop.run_in_executor(
            None, scan_repository, repo_url, github_token, model or None, progress_cb
        )

        def mark_done(_):
            loop.call_soon_threadsafe(queue.put_nowait, {"type": "__done__"})

        future.add_done_callback(mark_done)

        try:
            while True:
                event = await queue.get()
                if event.get("type") == "__done__":
                    break
                yield emit(event)

            result = await future
            yield emit({"type": "result", **result})
        except Exception as e:
            yield emit({"type": "error", "message": str(e)})

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/create-pr")
async def create_pr(req: PRRequest):
    from pr_creator import create_fix_pr
    from scan_service import get_cached_findings

    findings = get_cached_findings(req.repo_url)
    if not findings:
        raise HTTPException(status_code=400, detail="No cached scan findings for this repository. Run a scan first.")
    pr_url = create_fix_pr(req.repo_url, req.github_token, req.finding_ids, findings)
    return {"pr_url": pr_url}


def _serialize(finding) -> dict:
    d = asdict(finding)
    d["severity"] = finding.severity.value
    return d
