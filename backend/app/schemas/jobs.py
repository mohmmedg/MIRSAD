from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field

class JobStatus(str, Enum):
    PENDING='pending'; RUNNING='running'; PAUSED='paused'; CANCEL_REQUESTED='cancel_requested'; PARTIAL='partial'; COMPLETED='completed'; FAILED='failed'; CANCELLED='cancelled'

class JobStage(BaseModel):
    id: str
    label: str
    status: str
    progress: int = 0
    started_at: str | None = None
    finished_at: str | None = None
    message: str = ""

class ExecutionEvent(BaseModel):
    event_id: str
    execution_id: str
    scan_id: str
    operation_id: str | None = None
    sequence: int
    event_type: str
    stage: str | None = None
    tool: str | None = None
    message: str = ''
    payload: dict = Field(default_factory=dict)
    created_at: datetime

class ExecutionSummary(BaseModel):
    execution_id: str
    scan_id: str
    job_id: str
    attempt: int
    job_type: str
    target: str
    status: str
    current_engine: str | None = None
    metadata: dict = Field(default_factory=dict)
    started_at: datetime
    finished_at: datetime | None = None
    event_count: int = 0

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
    execution_config: dict = Field(default_factory=dict)
    stages: list[JobStage] = Field(default_factory=list)
    elapsed_seconds: float = 0.0
    eta_seconds: float | None = None
    current_eta_seconds: float | None = None
    eta_finish_at: datetime | None = None
    current_eta_finish_at: datetime | None = None
    completed_tasks: int = 0
    total_tasks: int = 0
    task_breakdown: dict[str, int] = Field(default_factory=dict)
    execution_id: str | None = None
