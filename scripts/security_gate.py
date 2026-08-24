#!/usr/bin/env python3
"""Offline CI/CD security gate.

Usage:
  python scripts/security_gate.py scan-result.json --sarif security-results.sarif
  python scripts/security_gate.py scan-result.json --critical-fail 0 --high-fail 0

The input can be a UnifiedScanResult JSON or {"findings":[...]}.
Exit 1 means the configured security gate failed.
"""
from __future__ import annotations
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"backend"))
from app.modules.compliance import ci_gate

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("--sarif",default="security-results.sarif")
    ap.add_argument("--critical-fail",type=int,default=0)
    ap.add_argument("--high-fail",type=int,default=0)
    ap.add_argument("--medium-fail",type=int,default=0)
    ap.add_argument("--json-report",default="")
    a=ap.parse_args()
    data=json.loads(Path(a.input).read_text(encoding="utf-8"))
    result=ci_gate(data,{"critical_fail":a.critical_fail,"high_fail":a.high_fail,"medium_fail":a.medium_fail})
    Path(a.sarif).write_text(json.dumps(result["sarif"],ensure_ascii=False,indent=2),encoding="utf-8")
    report={k:v for k,v in result.items() if k!="sarif"}
    if a.json_report: Path(a.json_report).write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps(report,ensure_ascii=False,indent=2))
    return result["exit_code"]
if __name__=="__main__": raise SystemExit(main())
