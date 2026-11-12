#!/usr/bin/env python3
"""Run a scan against a deployed MIRSAD API and enforce its CI gate.

Environment:
 SECURITY_API_URL  e.g. https://security.example.com
 SECURITY_API_KEY
 SECURITY_TARGET   authorized project/host target
"""
from __future__ import annotations
import json, os, sys, time, urllib.request, urllib.error
from pathlib import Path

base=os.environ.get("SECURITY_API_URL","").rstrip("/")
key=os.environ.get("SECURITY_API_KEY","")
target=os.environ.get("SECURITY_TARGET","").strip()
if not base or not key or not target:
    print("Security gate not configured; set SECURITY_API_URL, SECURITY_API_KEY and SECURITY_TARGET.")
    raise SystemExit(0)

def request(path, method="GET", body=None):
    data=json.dumps(body).encode() if body is not None else None
    req=urllib.request.Request(base+path,data=data,method=method,headers={"Content-Type":"application/json","X-API-Key":key})
    with urllib.request.urlopen(req,timeout=30) as r: return json.load(r)

job=request("/api/v1/platform/scan/async","POST",{"target":target,"network":True,"web":True,"api":True,"run_gemini":False})
job_id=job.get("job_id") or job.get("scan_id")
if not job_id: raise RuntimeError(f"Unexpected scan response: {job}")
for _ in range(180):
    state=request(f"/api/v1/jobs/{job_id}")
    if state.get("status") in {"completed","failed","cancelled"}:
        break
    time.sleep(2)
if state.get("status")!="completed":
    print(json.dumps(state,indent=2)); raise SystemExit(1)
result=state.get("result") or {}
Path("security-results.json").write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding="utf-8")
print(f"Saved {len(result.get('findings',[]))} findings to security-results.json")
