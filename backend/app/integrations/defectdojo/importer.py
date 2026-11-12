from datetime import date, timedelta
from app.integrations.defectdojo.client import DefectDojoClient
class DefectDojoImporter:
    def __init__(self,client=None): self.client=client or DefectDojoClient()
    async def ensure_product(self,name,description=""):
        data=await self.client.request("GET","/api/v2/products/",params={"name":name}); rows=data.get("results") or []
        if rows:return rows[0]
        # DefectDojo requires `prod_type` when creating a product; without it the API answers 400.
        return await self.client.request("POST","/api/v2/products/",json={"name":name,"description":description,"prod_type":await self.ensure_product_type()})
    async def ensure_product_type(self,name="MIRSAD"):
        data=await self.client.request("GET","/api/v2/product_types/",params={"name":name}); rows=data.get("results") or []
        if rows:return rows[0]["id"]
        created=await self.client.request("POST","/api/v2/product_types/",json={"name":name,"description":"MIRSAD scans"})
        return created["id"]
    async def ensure_engagement(self,product_id,name):
        data=await self.client.request("GET","/api/v2/engagements/",params={"product":product_id,"name":name}); rows=data.get("results") or []
        if rows:return rows[0]
        return await self.client.request("POST","/api/v2/engagements/",json={"product":product_id,"name":name,"status":"In Progress","target_start":date.today().isoformat(),"target_end":(date.today()+timedelta(days=1)).isoformat()})
