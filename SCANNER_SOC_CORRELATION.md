# Scanner → SOC Correlation Pipeline

## Data flow

`Network/Web/API scanner -> normalized finding -> deterministic risk -> security_event -> security_alert -> incident -> optional Gemini explanation`

### Authoritative security path

1. Scanner output is normalized by `backend/app/core/finding_pipeline.py`.
2. Severity, confidence and evidence are converted into a deterministic risk score.
3. Findings are persisted as `security_events` with a stable `finding_id`.
4. Scores >= 60 generate alerts; scores >= 70 normally generate incidents.
5. Re-observing the same finding within 24 hours increases risk and appends evidence to an existing open/investigating incident instead of creating duplicates.
6. Gemini runs only after persistence. It explains already-established evidence and can never change severity, create findings, close incidents, or override deterministic results.
7. Gemini failures do not fail the scanner job.

### Coverage

- Network open ports and NSE output
- Web active vulnerability checks
- Web template matches
- Passive web findings and CORS findings
- Missing security headers
- Integrated API template matches
- API authentication findings
- API schema validation failures

### Operational behavior

Both synchronous scan endpoints and background/Redis jobs feed the same pipeline. A completed scan remains successful even if SOC enrichment or Gemini fails.

## Next phase

The same normalized finding contract should be reused by Continuous Attack Surface Monitoring so that asset drift, new exposure, technology changes and certificate events enter the exact same Event → Detection → Risk → Alert → Incident pipeline.
