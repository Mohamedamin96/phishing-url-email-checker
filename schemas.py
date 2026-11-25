from pydantic import BaseModel
class URLRequest(BaseModel): url:str
class EmailRequest(BaseModel): headers:str
