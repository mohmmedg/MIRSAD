# Continuous Attack Surface Monitoring

## Release scope

Continuous monitoring is now a first-class layer above the existing scanner/SOC Finding Contract.

`Asset snapshot → deterministic diff → Finding → Risk → Security Event → Alert → Incident`

### Deterministic surface tracking

- IP addresses
- DNS records / resolved addresses
- Open ports
- Services
- Technologies
- Web applications
- APIs
- Endpoints
- TLS protocol
- TLS certificate expiration metadata

The first observation establishes a baseline and does not alert. Later deltas become findings. High-risk exposure changes can create SOC incidents.

### Security guarantees

- Continuous schedules are tenant-scoped and persisted in `continuous_schedules`.
- Schedule reads/deletes always include tenant identity.
- Surface state is stored as a deterministic snapshot, allowing removed values to be detected instead of only accumulating historical values.
- Repeated identical surface findings within 24 hours do not create duplicate alerts.
- Gemini is not used to decide whether a surface change occurred or to change severity. It remains explanatory only.
- Existing scanner findings and surface-change findings converge into the same SOC event/alert/incident model.

### Production architecture note

The current compatibility worker uses in-process asyncio tasks and persists the schedule state in the database. For a multi-replica production deployment, run the same schedule records through the existing durable Redis/job infrastructure so a schedule has a single active owner and survives replica churn without duplicate scans.
