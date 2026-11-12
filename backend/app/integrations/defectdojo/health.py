from app.integrations.defectdojo.client import DefectDojoClient
async def health(): return await DefectDojoClient().health()
