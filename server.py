from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import asyncio
import signal
import os
import json
import uuid

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# in-memory scan registry - stores status + pid for abort; cleaned up on completion
scans = {}

def _kill_scan_group(pid: int):
    """Kill the entire process group (Python + wpscan/ffuf/nuclei children)."""
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except OSError:
        pass  # process already exited or no permission

async def run_scanner(target_url: str, mode: str = "stealth", master_list: str = None, wordlist: str = None):
    """
    Runs the MainLogic.py script asynchronously and yields its output line by line.
    """
    scan_id = str(uuid.uuid4())
    scans[scan_id] = {"target": target_url, "status": "running", "pid": None}

    cmd = ["python3", "-u", "MainLogic.py", target_url, "--mode", mode]
    if master_list:
        cmd.extend(["--master-list", master_list])
    if wordlist:
        cmd.extend(["--wordlist", wordlist])

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        preexec_fn=os.setsid
    )

    scans[scan_id]["pid"] = process.pid

    yield f"data: {json.dumps({'type': 'status', 'msg': f'Scan started for {target_url} in {mode} mode', 'id': scan_id})}\n\n"
    yield f"data: {json.dumps({'type': 'log', 'msg': '[i] Connection established with backend. Initializing engines...'})}\n\n"

    try:
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            clean_line = line.decode().strip()
            yield f"data: {json.dumps({'type': 'log', 'msg': clean_line})}\n\n"

    except asyncio.CancelledError:
        # client disconnected - kill the entire process group so wpscan/ffuf/nuclei die too
        if process.returncode is None:
            _kill_scan_group(process.pid)
        raise

    finally:
        if process.returncode is None:
            return_code = await process.wait()
        else:
            return_code = process.returncode

        if return_code == 0:
            status = "completed"
        elif return_code in (-15, -9):  # SIGTERM or SIGKILL
            status = "aborted"
        else:
            status = "failed"

        # update registry - drop pid, keep status for post-scan queries
        scans[scan_id]["status"] = status
        scans[scan_id]["pid"] = None

        yield f"data: {json.dumps({'type': 'status', 'msg': f'Scan {status}', 'id': scan_id, 'code': return_code})}\n\n"

        # clean up old completed entries - keep at most 50 historical records
        if len(scans) > 50:
            completed = [k for k, v in scans.items() if v["pid"] is None and k != scan_id]
            for old_key in completed[:len(scans) - 50]:
                scans.pop(old_key, None)

@app.get("/scan")
async def start_scan(url: str, mode: str = "stealth", master_list: str = None, wordlist: str = None):
    """
    Start a scan and stream logs in real time via Server-Sent Events.
    Usage: GET /scan?url=http://example.com&mode=aggressive
    """
    return StreamingResponse(run_scanner(url, mode, master_list, wordlist), media_type="text/event-stream")

@app.post("/abort/{scan_id}")
async def abort_scan(scan_id: str):
    """Abort a running scan by killing its entire process group."""
    entry = scans.get(scan_id)
    if entry and entry["pid"] is not None:
        _kill_scan_group(entry["pid"])
        scans[scan_id]["status"] = "aborted"
        scans[scan_id]["pid"] = None
        return {"status": "ok", "msg": f"Scan {scan_id} aborted."}
    return {"status": "error", "msg": "Scan not found or already finished."}

@app.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
