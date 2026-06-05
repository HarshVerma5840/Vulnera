from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class NmapScan(BaseModel):
    target: str
    result: str
    status: str

class ZapScan(BaseModel):
    target: str
    result: str
    status: str
