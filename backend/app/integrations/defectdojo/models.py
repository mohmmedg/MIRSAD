from pydantic import BaseModel, Field
class Product(BaseModel): name:str; description:str=""
class Engagement(BaseModel): name:str; product_id:int; status:str="In Progress"
class Test(BaseModel): engagement_id:int; test_type:str="MIRSAD"
class ImportResult(BaseModel): test_id:int; finding_ids:list[int]=Field(default_factory=list)
class Finding(BaseModel): title:str; severity:str; description:str=""; unique_id_from_tool:str; references:list[str]=Field(default_factory=list); cwe:int|None=None; cve:str|None=None
