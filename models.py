from pydantic import BaseModel
from typing import List, Dict, Any, Optional

class Scan(BaseModel):
    model_type: str
    model_name: str
    probe_list: List[str] = None
    report_name: Optional[str] = None
    scan_id: Optional[str] = None