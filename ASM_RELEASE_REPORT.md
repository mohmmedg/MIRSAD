# ASM Release Report — 2026-08-22

Implemented Continuous Attack Surface Monitoring on top of the Scanner SOC Correlation release.

## Included
- Database-backed, tenant-scoped continuous schedules
- Deterministic asset surface snapshots and deltas
- Detection of added/removed IPs, ports, services, DNS, technologies, APIs, endpoints and TLS metadata
- TLS certificate expiry warning when <= 30 days
- Surface-change Finding Contract
- Risk scoring and SOC event/alert/incident escalation
- 24-hour duplicate-alert suppression for repeated identical surface findings
- Process restart restoration of enabled schedules
- Admin UI tab for creating/stopping monitors and viewing schedule state
- Supabase migration `0004_continuous_attack_surface.sql`

## Validation
- Python compileall: PASS
- Full backend suite: 148/148 PASS
- Frontend build could not be completed in the provided environment because required `vite/client` and `node` type packages were not installed; `npm ci --ignore-scripts` exceeded the execution timeout.
