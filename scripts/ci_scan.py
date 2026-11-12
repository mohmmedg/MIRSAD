#!/usr/bin/env python3
"""CI gate for an already-running scanner API.
Usage: python scripts/ci_scan.py --url http://localhost:8000 --target https://test.example.com
"""
import argparse, json, sys, urllib.request

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--url',default='http://localhost:8000'); ap.add_argument('--target',required=True); ap.add_argument('--api-key'); ap.add_argument('--critical',type=int,default=0); ap.add_argument('--high',type=int,default=3); ap.add_argument('--medium-warn',type=int,default=0); args=ap.parse_args()
    data=json.dumps({'target':args.target,'network':True,'web':True,'api':True,'web_profile':'balanced'}).encode()
    req=urllib.request.Request(args.url.rstrip('/')+'/api/v1/platform/scan',data=data,headers={'Content-Type':'application/json',**({'X-API-Key':args.api_key} if args.api_key else {})})
    with urllib.request.urlopen(req,timeout=1800) as r: result=json.load(r)
    findings=result.get('findings',[]); counts={s:sum(1 for f in findings if f.get('severity')==s) for s in ('Critical','High','Medium','Low','Info')}
    failures=[]; warnings=[]
    if counts['Critical']>args.critical: failures.append(f"Critical findings: {counts['Critical']} > {args.critical}")
    if counts['High']>args.high: failures.append(f"High findings: {counts['High']} > {args.high}")
    if counts['Medium']>args.medium_warn: warnings.append(f"Medium findings: {counts['Medium']}")
    print(json.dumps({'passed':not failures,'counts':counts,'risk_score':result.get('risk_score'), 'failures':failures,'warnings':warnings},ensure_ascii=False,indent=2)); return 1 if failures else 0
if __name__=='__main__': sys.exit(main())
