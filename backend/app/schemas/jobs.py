from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field

class JobStatus(str, Enum):
    PENDING='pending'; RUNNING='running'; PAUSED='paused'; COMPLETED='completed'; FAILED='failed'; CANCELLED='cancelled'

class JobSnapshot(BaseModel):
    job_id: str
    job_type: str
    target: str
    status: JobStatus
    progress: int = Field(ge=0, le=100)
    current_engine: str | None = None
    logs: list[str] = Field(default_factory=list)
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_seconds: float | None = None
    error_message: str | None = None
    result: dict | None = None
