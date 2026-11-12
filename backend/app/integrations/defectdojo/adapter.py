from app.integrations.defectdojo.client import DefectDojoClient
from app.integrations.defectdojo.health import health
from app.integrations.defectdojo.sync import enqueue_sync
class DefectDojoAdapter:
    async def status(self): return await health()
    async def sync(self,scan_id,tenant_id): return await enqueue_sync(scan_id,tenant_id)
    async def resync(self,scan_id,tenant_id): return await enqueue_sync(scan_id,tenant_id)
