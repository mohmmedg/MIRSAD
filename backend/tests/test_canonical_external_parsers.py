import json
from app.modules.external_scanners.engines import parse_sqlmap_output, parse_ffuf_json, _zap_risk

def test_sqlmap_parser_emits_one_finding_per_parameter():
    raw='''\nParameter: id (GET)\n    Type: boolean-based blind\n    Title: AND boolean-based blind\n    Payload: id=1 AND 1=1\nParameter: q (POST)\n    Type: time-based blind\n    Title: MySQL SLEEP\n    Payload: q=1 AND SLEEP(5)\n'''
    findings=parse_sqlmap_output(raw,'http://lab.local/item')
    assert len(findings)==2
    assert {x['parameter'] for x in findings}=={'id','q'}
    assert {x['position'] for x in findings}=={'GET','POST'}

def test_sqlmap_might_be_injectable_is_detected_not_confirmed_high():
    # The fallback-verdict regex (engines.py) requires the quoted parameter name real
    # sqlmap output always includes, e.g. "Parameter 'id' might be injectable" - the
    # previous fixture text omitted it entirely, so the regex never matched anything.
    findings=parse_sqlmap_output("Parameter 'id' might be injectable", 'http://lab.local')
    assert findings and findings[0]['severity']=='Medium'
    assert findings[0]['confidence']==0.55

def test_zap_riskcode_and_riskdesc_mapping():
    assert _zap_risk(3)=='High'
    assert _zap_risk('High (Medium)')=='High'
    assert _zap_risk(0)=='Info'

def test_ffuf_results_are_not_truncated_and_keep_content_discovery():
    data={'results':[{'url':f'http://lab.local/{i}','status':200,'words':1,'length':10} for i in range(1500)]}
    findings=parse_ffuf_json(data)
    assert len(findings)==1500
    assert all(x['severity']=='Info' for x in findings)
    assert findings[-1]['raw_locator']=='results[1499]'
