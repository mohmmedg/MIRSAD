"""Database models, migrations and PostgreSQL RLS session context."""
from __future__ import annotations
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from typing import Any
from sqlalchemy import DateTime,Integer,String,Text,create_engine,inspect,text,PrimaryKeyConstraint,Index
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase,Mapped,mapped_column,sessionmaker
from sqlalchemy.types import JSON, LargeBinary
from sqlalchemy.pool import NullPool
from app.core.config import settings
from app.core.auth_context import tenant_context
class Base(DeclarativeBase): pass
class TenantRow(Base):
    __tablename__='tenants'; tenant_id:Mapped[str]=mapped_column(String(64),primary_key=True); name:Mapped[str]=mapped_column(String(200)); created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True))
class UserRow(Base):
    __tablename__='users'
    __table_args__=(Index('ux_users_single_platform_owner', 'role', unique=True, postgresql_where=text("role = 'owner'"), sqlite_where=text("role = 'owner'")),)
    user_id:Mapped[str]=mapped_column(String(64),primary_key=True); tenant_id:Mapped[str]=mapped_column(String(64),index=True); email:Mapped[str]=mapped_column(String(320),unique=True,index=True); password_hash:Mapped[str]=mapped_column(String(512)); role:Mapped[str]=mapped_column(String(24),default='viewer'); is_active:Mapped[bool]=mapped_column(default=True); created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True))
    security_changed_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
class RefreshTokenRow(Base):
    __tablename__='refresh_tokens'; token_hash:Mapped[str]=mapped_column(String(64),primary_key=True); user_id:Mapped[str]=mapped_column(String(64),index=True); tenant_id:Mapped[str]=mapped_column(String(64),index=True); expires_at:Mapped[datetime]=mapped_column(DateTime(timezone=True)); revoked:Mapped[bool]=mapped_column(default=False); created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True))
class JobRow(Base):
    __tablename__='scan_jobs'; job_id:Mapped[str]=mapped_column(String(64),primary_key=True); tenant_id:Mapped[str]=mapped_column(String(64),index=True); created_by_user_id:Mapped[str|None]=mapped_column(String(64),index=True,nullable=True); job_type:Mapped[str]=mapped_column(String(32),index=True); target:Mapped[str]=mapped_column(String(2048)); status:Mapped[str]=mapped_column(String(24),index=True); progress:Mapped[int]=mapped_column(Integer,default=0); current_engine:Mapped[str|None]=mapped_column(String(64),nullable=True); logs:Mapped[list]=mapped_column(JSON,default=list); payload:Mapped[dict]=mapped_column(JSON,default=dict); result:Mapped[dict|None]=mapped_column(JSON,nullable=True); error_message:Mapped[str|None]=mapped_column(Text,nullable=True); created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True)); started_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True); finished_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True); heartbeat_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True,index=True); lease_owner:Mapped[str|None]=mapped_column(String(128),nullable=True); lease_until:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True,index=True); attempt_count:Mapped[int]=mapped_column(Integer,default=0)
class ScanExecutionRow(Base):
    __tablename__='scan_executions'
    execution_id:Mapped[str]=mapped_column(String(64),primary_key=True)
    tenant_id:Mapped[str]=mapped_column(String(64),index=True)
    scan_id:Mapped[str]=mapped_column(String(64),index=True)
    job_id:Mapped[str]=mapped_column(String(64),index=True)
    attempt:Mapped[int]=mapped_column(Integer,default=1)
    job_type:Mapped[str]=mapped_column(String(32),index=True)
    target:Mapped[str]=mapped_column(String(2048))
    status:Mapped[str]=mapped_column(String(24),index=True)
    current_engine:Mapped[str|None]=mapped_column(String(64),nullable=True)
    meta:Mapped[dict]=mapped_column('metadata', JSON, default=dict)
    started_at:Mapped[datetime]=mapped_column(DateTime(timezone=True))
    finished_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)

class ScanExecutionEventRow(Base):
    __tablename__='scan_execution_events'
    event_id:Mapped[str]=mapped_column(String(64),primary_key=True)
    tenant_id:Mapped[str]=mapped_column(String(64),index=True)
    scan_id:Mapped[str]=mapped_column(String(64),index=True)
    execution_id:Mapped[str]=mapped_column(String(64),index=True)
    operation_id:Mapped[str|None]=mapped_column(String(64),index=True,nullable=True)
    sequence:Mapped[int]=mapped_column(Integer,index=True)
    event_type:Mapped[str]=mapped_column(String(64),index=True)
    stage:Mapped[str|None]=mapped_column(String(128),nullable=True)
    tool:Mapped[str|None]=mapped_column(String(128),nullable=True)
    message:Mapped[str]=mapped_column(Text,default='')
    payload:Mapped[dict]=mapped_column(JSON,default=dict)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),index=True)

class RawArtifactRow(Base):
    __tablename__='raw_artifacts'
    artifact_id:Mapped[str]=mapped_column(String(128),primary_key=True)
    tenant_id:Mapped[str]=mapped_column(String(64),index=True)
    scan_id:Mapped[str]=mapped_column(String(64),index=True)
    execution_id:Mapped[str|None]=mapped_column(String(64),index=True,nullable=True)
    engine_result_id:Mapped[str|None]=mapped_column(String(128),index=True,nullable=True)
    tool:Mapped[str|None]=mapped_column(String(64),nullable=True)
    kind:Mapped[str]=mapped_column(String(32),index=True)
    content:Mapped[bytes|None]=mapped_column(LargeBinary,nullable=True)
    sha256:Mapped[str]=mapped_column(String(64),index=True)
    size_bytes:Mapped[int]=mapped_column(Integer,default=0)
    storage_ref:Mapped[str|None]=mapped_column(Text,nullable=True)
    encoding:Mapped[str|None]=mapped_column(String(64),nullable=True)
    part_index:Mapped[int|None]=mapped_column(Integer,nullable=True)
    parent_artifact_id:Mapped[str|None]=mapped_column(String(128),index=True,nullable=True)
    metadata_json:Mapped[dict]=mapped_column('metadata',JSON,default=dict)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda: datetime.now(timezone.utc),index=True)

class EngineResultRow(Base):
    __tablename__='engine_results'
    engine_result_id:Mapped[str]=mapped_column(String(128),primary_key=True)
    tenant_id:Mapped[str]=mapped_column(String(64),index=True)
    scan_id:Mapped[str]=mapped_column(String(64),index=True)
    execution_id:Mapped[str|None]=mapped_column(String(64),index=True,nullable=True)
    engine:Mapped[str]=mapped_column(String(64),index=True)
    version:Mapped[str|None]=mapped_column(String(1000),nullable=True)
    command:Mapped[list]=mapped_column(JSON,default=list)
    started_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    finished_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    duration_seconds:Mapped[float|None]=mapped_column(nullable=True)
    exit_code:Mapped[int|None]=mapped_column(Integer,nullable=True)
    status:Mapped[str]=mapped_column(String(24),index=True)
    metadata_json:Mapped[dict]=mapped_column('metadata',JSON,default=dict)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda: datetime.now(timezone.utc),index=True)

class FindingSourceRow(Base):
    __tablename__='finding_sources'
    source_id:Mapped[str]=mapped_column(String(128),primary_key=True)
    tenant_id:Mapped[str]=mapped_column(String(64),index=True)
    scan_id:Mapped[str]=mapped_column(String(64),index=True)
    finding_id:Mapped[str]=mapped_column(String(128),index=True)
    engine:Mapped[str]=mapped_column(String(64),index=True)
    engine_result_id:Mapped[str|None]=mapped_column(String(128),index=True,nullable=True)
    execution_id:Mapped[str|None]=mapped_column(String(64),index=True,nullable=True)
    raw_artifact_id:Mapped[str|None]=mapped_column(String(128),index=True,nullable=True)
    raw_locator:Mapped[str|None]=mapped_column(String(256),nullable=True)
    observation:Mapped[dict]=mapped_column(JSON,default=dict)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda: datetime.now(timezone.utc),index=True)

class VerificationEventRow(Base):
    __tablename__='verification_events'
    event_id:Mapped[str]=mapped_column(String(128),primary_key=True)
    tenant_id:Mapped[str]=mapped_column(String(64),index=True)
    scan_id:Mapped[str]=mapped_column(String(64),index=True)
    finding_id:Mapped[str]=mapped_column(String(128),index=True)
    method:Mapped[str]=mapped_column(String(128))
    status_from:Mapped[str|None]=mapped_column(String(32),nullable=True)
    status_to:Mapped[str]=mapped_column(String(32),index=True)
    evidence:Mapped[dict]=mapped_column(JSON,default=dict)
    request_ref:Mapped[str|None]=mapped_column(String(256),nullable=True)
    response_ref:Mapped[str|None]=mapped_column(String(256),nullable=True)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda: datetime.now(timezone.utc),index=True)

class ReparseJobRow(Base):
    __tablename__='reparse_jobs'
    reparse_job_id:Mapped[str]=mapped_column(String(128),primary_key=True)
    tenant_id:Mapped[str]=mapped_column(String(64),index=True)
    scan_id:Mapped[str]=mapped_column(String(64),index=True)
    artifact_id:Mapped[str]=mapped_column(String(128),index=True)
    status:Mapped[str]=mapped_column(String(24),index=True,default='PENDING')
    parser:Mapped[str|None]=mapped_column(String(128),nullable=True)
    result_version:Mapped[int]=mapped_column(Integer,default=1)
    error_message:Mapped[str|None]=mapped_column(Text,nullable=True)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda: datetime.now(timezone.utc))
    finished_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)

class ReparseResultRow(Base):
    __tablename__='reparse_results'
    reparse_result_id:Mapped[str]=mapped_column(String(128),primary_key=True)
    tenant_id:Mapped[str]=mapped_column(String(64),index=True)
    scan_id:Mapped[str]=mapped_column(String(64),index=True)
    artifact_id:Mapped[str]=mapped_column(String(128),index=True)
    reparse_job_id:Mapped[str]=mapped_column(String(128),index=True)
    result_version:Mapped[int]=mapped_column(Integer,index=True)
    finding:Mapped[dict]=mapped_column(JSON,default=dict)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda: datetime.now(timezone.utc),index=True)

class DefectDojoMappingRow(Base):
    __tablename__='defectdojo_mappings'
    mapping_id:Mapped[str]=mapped_column(String(128),primary_key=True)
    tenant_id:Mapped[str]=mapped_column(String(64),index=True)
    scan_id:Mapped[str]=mapped_column(String(64),index=True)
    finding_id:Mapped[str|None]=mapped_column(String(128),nullable=True)
    engine_result_id:Mapped[str|None]=mapped_column(String(128),nullable=True)
    engagement_id:Mapped[int|None]=mapped_column(Integer,nullable=True)
    test_id:Mapped[int|None]=mapped_column(Integer,nullable=True)
    defectdojo_finding_id:Mapped[int|None]=mapped_column(Integer,nullable=True)
    fingerprint:Mapped[str|None]=mapped_column(String(128),index=True,nullable=True)
    idempotency_key:Mapped[str]=mapped_column(String(256),index=True)
    mapping_type:Mapped[str]=mapped_column(String(32),index=True)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda: datetime.now(timezone.utc))
    updated_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda: datetime.now(timezone.utc))

class ExternalSyncJobRow(Base):
    __tablename__='external_sync_jobs'
    job_id:Mapped[str]=mapped_column(String(128),primary_key=True)
    tenant_id:Mapped[str]=mapped_column(String(64),index=True)
    scan_id:Mapped[str]=mapped_column(String(64),index=True)
    provider:Mapped[str]=mapped_column(String(64),index=True)
    status:Mapped[str]=mapped_column(String(24),index=True,default='PENDING')
    attempt_count:Mapped[int]=mapped_column(Integer,default=0)
    next_retry_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),index=True)
    last_error_code:Mapped[str|None]=mapped_column(String(64),nullable=True)
    last_error_message:Mapped[str|None]=mapped_column(Text,nullable=True)
    idempotency_key:Mapped[str]=mapped_column(String(256),index=True)
    payload:Mapped[dict]=mapped_column(JSON,default=dict)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda: datetime.now(timezone.utc))
    updated_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda: datetime.now(timezone.utc))

class ScanRow(Base):
    __tablename__='scans'; scan_id:Mapped[str]=mapped_column(String(64),primary_key=True); tenant_id:Mapped[str]=mapped_column(String(64),index=True); created_by_user_id:Mapped[str|None]=mapped_column(String(64),index=True,nullable=True); job_id:Mapped[str|None]=mapped_column(String(64),index=True,nullable=True); scan_kind:Mapped[str]=mapped_column(String(32),index=True); target:Mapped[str]=mapped_column(String(2048)); status:Mapped[str]=mapped_column(String(24),index=True); result:Mapped[dict|None]=mapped_column(JSON,nullable=True); error_message:Mapped[str|None]=mapped_column(Text,nullable=True); created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True)); finished_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
class ContinuousScheduleRow(Base):
    __tablename__='continuous_schedules'
    schedule_id:Mapped[str]=mapped_column(String(64),primary_key=True)
    tenant_id:Mapped[str]=mapped_column(String(64),index=True)
    target:Mapped[str]=mapped_column(String(2048))
    request:Mapped[dict]=mapped_column(JSON,default=dict)
    interval_seconds:Mapped[int]=mapped_column(Integer,default=3600)
    enabled:Mapped[bool]=mapped_column(default=True,index=True)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda: datetime.now(timezone.utc))
    last_run:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    last_status:Mapped[str|None]=mapped_column(String(24),nullable=True)
    last_error:Mapped[str|None]=mapped_column(Text,nullable=True)
    next_run_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True,index=True)
    lease_owner:Mapped[str|None]=mapped_column(String(128),nullable=True)
    lease_until:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)

class BASReplayRunRow(Base):
    """4.4: one row per BAS replay execution - see
    attack_simulation/simulator.py + continuous.py::_execute_bas_replay.
    Append-only history; ContinuousScheduleRow.request["last_summary"] only
    ever caches the latest run inline (no migration needed for that path),
    this table is the durable, queryable history on top of it."""
    __tablename__='bas_replay_runs'
    id:Mapped[str]=mapped_column(String(64),primary_key=True)
    tenant_id:Mapped[str]=mapped_column(String(64),index=True)
    schedule_id:Mapped[str]=mapped_column(String(64),index=True)
    scan_id:Mapped[str]=mapped_column(String(64),index=True)
    total_targets:Mapped[int]=mapped_column(Integer,default=0)
    still_live_count:Mapped[int]=mapped_column(Integer,default=0)
    resolved_count:Mapped[int]=mapped_column(Integer,default=0)
    unknown_count:Mapped[int]=mapped_column(Integer,default=0)
    outcomes:Mapped[list]=mapped_column(JSON,default=list)
    replayed_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda: datetime.now(timezone.utc))


class FindingLifecycleRow(Base):
    __tablename__='finding_lifecycle'
    lifecycle_id:Mapped[str]=mapped_column(String(64),primary_key=True)
    tenant_id:Mapped[str]=mapped_column(String(64),index=True)
    scan_id:Mapped[str]=mapped_column(String(64),index=True)
    finding_id:Mapped[str]=mapped_column(String(128),index=True)
    status:Mapped[str]=mapped_column(String(32),default='DISCOVERED',index=True)
    note:Mapped[str]=mapped_column(Text,default='')
    actor_user_id:Mapped[str|None]=mapped_column(String(64),nullable=True)
    version:Mapped[int]=mapped_column(Integer,default=1)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),index=True)
    updated_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),index=True)


class FindingLifecycleIdempotencyRow(Base):
    # *** إضافة (دعم Idempotency لطلبات Background Sync القابلة للتكرار) ***
    # مفتاح مركّب (tenant_id, idempotency_key): أول طلب بمفتاح معيّن ينفَّذ
    # ويُخزَّن ناتجه هون؛ أي طلب لاحق بنفس المفتاح (retry بعد timeout مثلاً)
    # يرجّع نفس الناتج المخزَّن بدل إعادة تنفيذ العملية.
    __tablename__='finding_lifecycle_idempotency'
    tenant_id:Mapped[str]=mapped_column(String(64),primary_key=True)
    idempotency_key:Mapped[str]=mapped_column(String(128),primary_key=True)
    result:Mapped[dict]=mapped_column(JSON,default=dict)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True))

class VerificationAttemptRow(Base):
    __tablename__='verification_attempts'
    verification_id:Mapped[str]=mapped_column(String(64),primary_key=True)
    tenant_id:Mapped[str]=mapped_column(String(64),index=True)
    scan_id:Mapped[str|None]=mapped_column(String(64),index=True,nullable=True)
    job_id:Mapped[str|None]=mapped_column(String(64),index=True,nullable=True)
    finding_id:Mapped[str]=mapped_column(String(128),index=True)
    rule_id:Mapped[str]=mapped_column(String(128),index=True)
    method:Mapped[str]=mapped_column(String(128))
    verifier:Mapped[str]=mapped_column(String(128),default='deterministic-engine')
    result:Mapped[str]=mapped_column(String(32),index=True)
    confidence:Mapped[float]=mapped_column(default=0.0)
    evidence:Mapped[list]=mapped_column(JSON,default=list)
    request_id:Mapped[str|None]=mapped_column(String(128),nullable=True)
    response_id:Mapped[str|None]=mapped_column(String(128),nullable=True)
    started_at:Mapped[datetime]=mapped_column(DateTime(timezone=True))
    completed_at:Mapped[datetime]=mapped_column(DateTime(timezone=True))
    reason:Mapped[str|None]=mapped_column(Text,nullable=True)

class ScanSnapshotRow(Base):
    __tablename__='scan_snapshots'
    scan_id:Mapped[str]=mapped_column(String(64),primary_key=True)
    tenant_id:Mapped[str]=mapped_column(String(64),index=True)
    snapshot_version:Mapped[str]=mapped_column(String(32),default='2')
    data:Mapped[dict]=mapped_column(JSON,default=dict)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True))
    finalized_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True,index=True)

class AssetRow(Base):
    __tablename__='assets'; asset_id:Mapped[str]=mapped_column(String(64),primary_key=True); tenant_id:Mapped[str]=mapped_column(String(64),index=True); canonical_identity:Mapped[str]=mapped_column(String(2048),default=''); target:Mapped[str]=mapped_column(String(2048)); data:Mapped[dict]=mapped_column(JSON,default=dict); first_seen:Mapped[datetime]=mapped_column(DateTime(timezone=True)); last_seen:Mapped[datetime]=mapped_column(DateTime(timezone=True),index=True)
class AuditLogRow(Base):
    __tablename__='audit_logs'; id:Mapped[str]=mapped_column(String(64),primary_key=True); tenant_id:Mapped[str]=mapped_column(String(64),index=True); event:Mapped[str]=mapped_column(String(64),index=True); target:Mapped[str|None]=mapped_column(String(2048),nullable=True); data:Mapped[dict]=mapped_column(JSON,default=dict); created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),index=True)
class AdminSettingRow(Base):
    __tablename__='admin_settings'; tenant_id:Mapped[str]=mapped_column(String(64),primary_key=True); security_policy:Mapped[dict]=mapped_column(JSON,default=dict); scan_policy:Mapped[dict]=mapped_column(JSON,default=dict); ai_policy:Mapped[dict]=mapped_column(JSON,default=dict); notification_policy:Mapped[dict]=mapped_column(JSON,default=dict); updated_at:Mapped[datetime]=mapped_column(DateTime(timezone=True))
class FeatureFlagRow(Base):
    __tablename__='feature_flags'; tenant_id:Mapped[str]=mapped_column(String(64),primary_key=True); flags:Mapped[dict]=mapped_column(JSON,default=dict); updated_at:Mapped[datetime]=mapped_column(DateTime(timezone=True))
class SecurityEventRow(Base):
    __tablename__='security_events'
    event_id:Mapped[str]=mapped_column(String(64),primary_key=True)
    tenant_id:Mapped[str]=mapped_column(String(64),index=True)
    event_type:Mapped[str]=mapped_column(String(96),index=True)
    severity:Mapped[str]=mapped_column(String(16),index=True)
    actor_user_id:Mapped[str|None]=mapped_column(String(64),index=True,nullable=True)
    target:Mapped[str|None]=mapped_column(String(2048),nullable=True)
    data:Mapped[dict]=mapped_column(JSON,default=dict)
    risk_score:Mapped[int]=mapped_column(Integer,default=0)
    detected:Mapped[bool]=mapped_column(default=False)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),index=True)

class SecurityAlertRow(Base):
    __tablename__='security_alerts'
    alert_id:Mapped[str]=mapped_column(String(64),primary_key=True)
    tenant_id:Mapped[str]=mapped_column(String(64),index=True)
    event_id:Mapped[str|None]=mapped_column(String(64),index=True,nullable=True)
    title:Mapped[str]=mapped_column(String(240))
    severity:Mapped[str]=mapped_column(String(16),index=True)
    status:Mapped[str]=mapped_column(String(24),index=True,default='open')
    risk_score:Mapped[int]=mapped_column(Integer,default=0)
    data:Mapped[dict]=mapped_column(JSON,default=dict)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),index=True)
    acknowledged_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    incident_id:Mapped[str|None]=mapped_column(String(64),index=True,nullable=True)

class IncidentRow(Base):
    __tablename__='security_incidents'
    incident_id:Mapped[str]=mapped_column(String(64),primary_key=True)
    tenant_id:Mapped[str]=mapped_column(String(64),index=True)
    title:Mapped[str]=mapped_column(String(240))
    description:Mapped[str]=mapped_column(Text,default='')
    severity:Mapped[str]=mapped_column(String(16),index=True)
    status:Mapped[str]=mapped_column(String(24),index=True,default='open')
    assignee_user_id:Mapped[str|None]=mapped_column(String(64),index=True,nullable=True)
    sla_due_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    related_asset_id:Mapped[str|None]=mapped_column(String(64),nullable=True)
    related_scan_id:Mapped[str|None]=mapped_column(String(64),nullable=True)
    related_finding_id:Mapped[str|None]=mapped_column(String(128),nullable=True)
    related_user_id:Mapped[str|None]=mapped_column(String(64),nullable=True)
    evidence:Mapped[list]=mapped_column(JSON,default=list)
    timeline:Mapped[list]=mapped_column(JSON,default=list)
    ai_explanation:Mapped[str|None]=mapped_column(Text,nullable=True)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),index=True)
    updated_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),index=True)

class ApiKeyRow(Base):
    __tablename__='admin_api_keys'; key_id:Mapped[str]=mapped_column(String(64),primary_key=True); tenant_id:Mapped[str]=mapped_column(String(64),index=True); user_id:Mapped[str]=mapped_column(String(64),index=True); name:Mapped[str]=mapped_column(String(120)); key_hash:Mapped[str]=mapped_column(String(64),unique=True,index=True); scopes:Mapped[list]=mapped_column(JSON,default=list); expires_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True); last_used_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True); revoked:Mapped[bool]=mapped_column(default=False); created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True))

class ComplianceControlRow(Base):
    __tablename__='compliance_controls'
    control_id:Mapped[str]=mapped_column(String(128))
    tenant_id:Mapped[str]=mapped_column(String(64),index=True)
    framework:Mapped[str]=mapped_column(String(128))
    title:Mapped[str]=mapped_column(String(240))
    description:Mapped[str]=mapped_column(Text,default='')
    enabled:Mapped[bool]=mapped_column(default=True)
    tags:Mapped[list]=mapped_column(JSON,default=list)
    max_severity:Mapped[str]=mapped_column(String(16),default='Low')
    updated_at:Mapped[datetime]=mapped_column(DateTime(timezone=True))
    __table_args__=(PrimaryKeyConstraint('tenant_id','control_id'),)

class ComplianceAssessmentRow(Base):
    __tablename__='compliance_assessments'
    assessment_id:Mapped[str]=mapped_column(String(64),primary_key=True)
    tenant_id:Mapped[str]=mapped_column(String(64),index=True)
    framework:Mapped[str]=mapped_column(String(128))
    score:Mapped[float]=mapped_column()
    passed:Mapped[int]=mapped_column(Integer,default=0)
    failed:Mapped[int]=mapped_column(Integer,default=0)
    controls:Mapped[list]=mapped_column(JSON,default=list)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),index=True)

class CISecurityPolicyRow(Base):
    __tablename__='ci_security_policies'
    tenant_id:Mapped[str]=mapped_column(String(64),primary_key=True)
    critical_fail:Mapped[int]=mapped_column(Integer,default=0)
    high_fail:Mapped[int]=mapped_column(Integer,default=0)
    medium_fail:Mapped[int]=mapped_column(Integer,default=0)
    enabled:Mapped[bool]=mapped_column(default=True)
    updated_at:Mapped[datetime]=mapped_column(DateTime(timezone=True))
url=settings.DATABASE_URL
if url.startswith('sqlite'):
    connect_args={'check_same_thread':False,'timeout':30}
    engine=create_engine(url,connect_args=connect_args,poolclass=NullPool)
    _async_url=url.replace('sqlite://','sqlite+aiosqlite://',1)
    async_engine=create_async_engine(_async_url,connect_args=connect_args,poolclass=NullPool)
else:
    # Direct connection to Supabase Postgres (db.<project-ref>.supabase.co:5432).
    #
    # 2026-09-16: removed the VPN/WSL2-oriented settings this used to carry.
    # The backend now connects to Supabase directly rather than over a VPN
    # tunnel, so the workarounds that existed specifically for a VPN/NAT path
    # dropping connections mid-query no longer apply; TCP keepalives are kept
    # below because they're good practice for any long-lived pooled
    # connection, not because of VPN flakiness. with_db_retry() (below) is
    # still kept as a safety net for genuinely transient network blips, not
    # as a VPN-specific workaround.
    #
    # Two engines share this URL:
    #  - `engine` (psycopg2, sync): used ONLY by init_db()/init_db_with_retry()
    #    at process startup for one-time DDL (schema bootstrap, RLS policies).
    #    This runs once before the app serves any request, so it staying sync
    #    is not a concurrency concern.
    #  - `async_engine` (asyncpg, async): used by session_scope() below for
    #    every request. This is the one that matters for concurrency - see
    #    with_db_retry()'s docstring for why the old sync-on-event-loop setup
    #    caused "the whole site loads slowly".
    # 2026-09-17 fix: DATABASE_URL can arrive with an explicit driver already
    # in the scheme (postgresql+psycopg2://..., which Supabase's own docs and
    # some .env templates use) rather than a bare postgres://. The previous
    # str.replace('postgresql://', ...) only matched a *bare* scheme, so a
    # URL that already said postgresql+psycopg2:// passed straight through
    # unchanged into create_async_engine() - SQLAlchemy then loaded the sync
    # psycopg2 driver for the "async" engine and raised InvalidRequestError
    # ("The asyncio extension requires an async driver... 'psycopg2' is not
    # async") at import time, crashing the whole backend container on boot.
    # Stripping any existing "+driver" from the scheme first makes this
    # rewrite correct regardless of which explicit driver (or none) the
    # supplied DATABASE_URL already names.
    import re as _re
    _scheme_no_driver = _re.sub(r'^(postgres(?:ql)?)\+[a-zA-Z0-9_]+://', r'\1://', url)
    sync_url=_scheme_no_driver.replace('postgres://','postgresql://',1) if _scheme_no_driver.startswith('postgres://') else _scheme_no_driver
    async_url=sync_url.replace('postgresql://','postgresql+asyncpg://',1)

    connect_args={
        'sslmode':str(getattr(settings,'DB_SSLMODE','require') or 'require'),  # 'disable' only for the local docker Postgres
        'connect_timeout':int(getattr(settings,'DB_CONNECT_TIMEOUT_SECONDS',15)),
        'keepalives':1,
        'keepalives_idle':30,
        'keepalives_interval':10,
        'keepalives_count':3,
        'application_name':'mirsad',
    }
    # 2026-09-22: pool_size/max_overflow آتية من effective_db_pool_size/
    # effective_db_max_overflow (core/config.py) وليس من الحقول الخام —
    # هذي القيم مُقلَّصة تلقائياً لتبقى آمنة على حد اتصالات Supabase مهما
    # كان عدد عمليات backend/worker الشغالة. لو تم التقليص عن القيمة
    # المطلوبة، نسجّل تحذير واضح بدل فشل صامت لاحقاً بأخطاء اتصال.
    _eff_pool = settings.effective_db_pool_size
    _eff_overflow = settings.effective_db_max_overflow
    if (_eff_pool + _eff_overflow) < (int(getattr(settings,'DB_POOL_SIZE',15)) + int(getattr(settings,'DB_MAX_OVERFLOW',10))):
        import logging as _logging
        _logging.getLogger("mirsad.database").warning(
            "DB pool clamped for safety: requested pool_size=%s max_overflow=%s -> "
            "effective pool_size=%s max_overflow=%s (EXPECTED_APP_PROCESSES=%s, "
            "SUPABASE_MAX_CONNECTIONS=%s). Raise SUPABASE_MAX_CONNECTIONS or lower "
            "EXPECTED_APP_PROCESSES if this is unexpected.",
            getattr(settings,'DB_POOL_SIZE',15), getattr(settings,'DB_MAX_OVERFLOW',10),
            _eff_pool, _eff_overflow, getattr(settings,'EXPECTED_APP_PROCESSES',5),
            getattr(settings,'SUPABASE_MAX_CONNECTIONS',60),
        )
    engine=create_engine(
        sync_url,
        pool_pre_ping=True,
        pool_recycle=int(getattr(settings,'DB_POOL_RECYCLE_SECONDS',180)),
        pool_timeout=int(getattr(settings,'DB_POOL_TIMEOUT_SECONDS',90)),
        pool_size=_eff_pool,
        max_overflow=_eff_overflow,
        connect_args=connect_args,
    )

    async_connect_args={
        'ssl':str(getattr(settings,'DB_SSLMODE','require') or 'require'),
        # Fail fast on a dead connect attempt and let with_db_retry_async retry
        # (a healthy connect takes well under a second; waiting 15s per attempt
        # made nested retries exceed the browser's request timeout).
        'timeout':min(int(getattr(settings,'DB_CONNECT_TIMEOUT_SECONDS',15)),8),
        'server_settings':{'application_name':'mirsad'},
        # 2026-10-03: never let a single asyncpg call wait forever on a dead pooler link.
        'command_timeout':int(getattr(settings,'DB_COMMAND_TIMEOUT_SECONDS',60)),
        # 2026-09-17: confirmed in production - DATABASE_URL goes through
        # Supavisor/pgbouncer in transaction-pooling mode, not a direct
        # connection to Postgres. In that mode the TCP connection asyncpg
        # holds can be handed to a *different* Postgres backend session
        # between statements, so a server-side prepared statement created on
        # one "statement" can vanish by the next - every second query failed
        # with asyncpg.exceptions.InvalidSQLStatementNameError: prepared
        # statement "__asyncpg_stmt_N__" does not exist. Disabling asyncpg's
        # client-side statement cache makes every execution PARSE+BIND+EXECUTE
        # fresh instead of trying to reuse a cached server-side prepared
        # statement, which is correct and safe whether or not a pooler is
        # actually in the path - so this stays unconditional rather than
        # branching on the URL.
        #
        # 2026-09-18: `statement_cache_size` alone did NOT fix the crash -
        # that key only disables *asyncpg's own* client-side cache. SQLAlchemy's
        # asyncpg dialect keeps a SEPARATE cache of PreparedStatement objects on
        # the pooled DBAPI connection (AsyncAdapt_asyncpg_connection._prepared_statement_cache,
        # an LRUCache defaulting to 100 entries), controlled by the
        # similarly-named but distinct `prepared_statement_cache_size` DBAPI
        # argument. Without disabling that too, SQLAlchemy kept reusing a
        # PreparedStatement object across pool checkouts even though asyncpg's
        # own cache was off - which is exactly what produced the
        # "prepared statement __asyncpg_stmt_N__ does not exist" crashes on
        # nearly every request. Both must be 0.
        'statement_cache_size':0,
        'prepared_statement_cache_size':0,
    }
    async_engine=create_async_engine(
        async_url,
        pool_pre_ping=True,
        pool_recycle=int(getattr(settings,'DB_POOL_RECYCLE_SECONDS',180)),
        pool_timeout=int(getattr(settings,'DB_POOL_TIMEOUT_SECONDS',90)),
        pool_size=_eff_pool,
        max_overflow=_eff_overflow,
        connect_args=async_connect_args,
    )
SessionLocal=sessionmaker(bind=engine,expire_on_commit=False)
AsyncSessionLocal=async_sessionmaker(bind=async_engine,expire_on_commit=False,class_=AsyncSession)

def init_db_with_retry(retries:int=8,base_delay:float=2.0)->None:
    """Startup DB connectivity is retried with exponential backoff instead of crashing
    the whole process on the first transient failure (e.g. Supabase free-tier project
    waking up from an auto-pause, or a brief network blip to the pooler)."""
    import logging,time
    logger=logging.getLogger("app.core.database")
    last_exc:Exception|None=None
    for attempt in range(1,retries+1):
        try:
            init_db()
            if attempt>1:
                logger.info("Database connected successfully on attempt %d/%d",attempt,retries)
            return
        except Exception as exc:  # noqa: BLE001 - intentionally broad: any DB error should retry
            last_exc=exc
            delay=min(base_delay*(2**(attempt-1)),30)
            logger.warning(
                "DB init attempt %d/%d failed (%s: %s). Retrying in %.1fs. "
                "If this keeps failing, check whether the Supabase project is paused "
                "and that DATABASE_URL is current.",
                attempt,retries,type(exc).__name__,exc,delay,
            )
            if attempt<retries:
                time.sleep(delay)
    raise RuntimeError(
        f"Database unreachable after {retries} attempts. Last error: {last_exc}"
    ) from last_exc

def init_db():
    """Legacy/local schema bootstrap.

    Production Supabase deployments must use the checked-in SQL migrations,
    not CREATE/ALTER/DROP POLICY during API startup. This function remains for
    local SQLite/dev compatibility and is only called when DB_AUTO_CREATE_SCHEMA
    is explicitly enabled.
    """
    Base.metadata.create_all(engine)
    insp=inspect(engine)
    for table in ('scan_jobs','scans','scan_snapshots','finding_lifecycle','assets','audit_logs','admin_settings','feature_flags','admin_api_keys','security_events','security_alerts','security_incidents','continuous_schedules','compliance_controls','compliance_assessments','ci_security_policies'):
        cols={c['name'] for c in insp.get_columns(table)}
        if 'tenant_id' not in cols and table not in ('admin_settings','feature_flags'):
            with engine.begin() as c:
                c.execute(text(f"ALTER TABLE {table} ADD COLUMN tenant_id VARCHAR(64)"))
                c.execute(text(f"UPDATE {table} SET tenant_id='legacy' WHERE tenant_id IS NULL"))
    # *** إضافة ***: عمود version لسجلات finding_lifecycle القديمة (قبل هذا
    # التعديل) على بيئات محلية/dev لسا ما أعادت إنشاء الجدول من الصفر.
    if 'finding_lifecycle' in insp.get_table_names():
        lifecycle_cols={c['name'] for c in inspect(engine).get_columns('finding_lifecycle')}
        if 'version' not in lifecycle_cols:
            with engine.begin() as c:
                c.execute(text("ALTER TABLE finding_lifecycle ADD COLUMN version INTEGER DEFAULT 1"))
                c.execute(text("UPDATE finding_lifecycle SET version=1 WHERE version IS NULL"))
    if 'security_alerts' in insp.get_table_names():
        alert_cols={c['name'] for c in inspect(engine).get_columns('security_alerts')}
        if 'incident_id' not in alert_cols:
            with engine.begin() as c:
                c.execute(text("ALTER TABLE security_alerts ADD COLUMN incident_id VARCHAR(64)"))
    if engine.dialect.name=='postgresql':
        with engine.begin() as c:
            c.execute(text("ALTER TABLE scan_jobs ALTER COLUMN tenant_id SET NOT NULL")); c.execute(text("ALTER TABLE scans ALTER COLUMN tenant_id SET NOT NULL"))
            for table in ('scan_jobs','scans','scan_snapshots','finding_lifecycle','assets','audit_logs','admin_settings','feature_flags','admin_api_keys','security_events','security_alerts','security_incidents','continuous_schedules','compliance_controls','compliance_assessments','ci_security_policies'):
                c.execute(text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
                c.execute(text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
                c.execute(text(f"DROP POLICY IF EXISTS tenant_isolation ON {table}"))
                c.execute(text(f"CREATE POLICY tenant_isolation ON {table} USING (tenant_id = current_setting('app.tenant_id', true)) WITH CHECK (tenant_id = current_setting('app.tenant_id', true))"))

@asynccontextmanager
async def session_scope(tenant_id: str|None=None):
    import asyncio as _aio
    db=AsyncSessionLocal(); tid=tenant_id or tenant_context.get()
    try:
        if async_engine.dialect.name=='postgresql':
            # 2026-10-03: transaction-local server-side guards. Behind Supavisor
            # (transaction pooling) a session whose client vanished mid-request
            # (browser abort at 15s -> BaseHTTPMiddleware cancels the handler)
            # stayed "idle in transaction" for 15+ minutes and pinned a pooled
            # backend, starving later requests (/platform/scan-history hung).
            # These bound both a stuck statement and an abandoned transaction.
            if tid:
                await db.execute(text(
                    "SELECT set_config('app.tenant_id', :tid, true),"
                    " set_config('statement_timeout', '60000', true),"
                    " set_config('idle_in_transaction_session_timeout', '60000', true)"),{'tid':tid})
            else:
                await db.execute(text(
                    "SELECT set_config('statement_timeout', '60000', true),"
                    " set_config('idle_in_transaction_session_timeout', '60000', true)"))
        yield db; await db.commit()
    except BaseException:
        # BaseException (not Exception): asyncio.CancelledError must also roll
        # back, otherwise the connection returns to the pool mid-transaction.
        try: await _aio.shield(db.rollback())
        except (Exception,_aio.CancelledError): pass
        raise
    finally:
        try: await _aio.shield(db.close())
        except (Exception,_aio.CancelledError): pass

@contextmanager
def session_scope_sync(tenant_id: str|None=None):
    """Deliberately-kept-synchronous counterpart to session_scope(), backed
    by the sync `engine`/SessionLocal (psycopg2) rather than async_engine.

    2026-09-16: scope boundary for the full asyncpg migration. Used ONLY by
    app/core/policy_enforcement.py's tiny single-row-by-primary-key policy
    lookups (scan_policy/security_policy/ai_policy/scan_timeout_seconds/
    step_timeout_seconds and friends), which are called from deep inside
    scanner modules (app/modules/web_scan/scanner.py,
    app/modules/ai_analysis/analyzer.py, and others) whose own execution
    model (subprocess calls, their own thread/async usage) was not audited
    as part of this migration - forcing `async def` through them without
    being able to verify each one end-to-end would be a real regression
    risk, not a bounds-checked improvement. These lookups are also a
    fundamentally different risk profile than what motivated the async
    migration in the first place: a single indexed PK SELECT, not the bulk
    snapshot fetches that were freezing the event loop (see with_db_retry_async's
    docstring). If a policy lookup call site is later confirmed safe to
    convert, prefer session_scope() (async) over this one.
    """
    db=SessionLocal(); tid=tenant_id or tenant_context.get()
    try:
        if tid and engine.dialect.name=='postgresql': db.execute(text("SELECT set_config('app.tenant_id', :tid, true)"),{'tid':tid})
        yield db; db.commit()
    except Exception: db.rollback(); raise
    finally: db.close()

def utcnow(): return datetime.now(timezone.utc)
def jsonable(value:Any):
    """Convert model values to JSON-safe data at the DB persistence boundary.

    Scan responses can contain arbitrary target-controlled bytes/strings.
    PostgreSQL JSON/JSONB rejects the NUL code point, so sanitize recursively
    here rather than allowing a persistence error to turn a completed scan into
    a worker retry (which would execute the scan again).
    """
    from app.core.json_sanitizer import sanitize_json
    raw = value.model_dump(mode="json") if hasattr(value, "model_dump") else value
    return sanitize_json(raw)

from sqlalchemy.exc import OperationalError, DBAPIError

# 2026-10-03: asyncpg connect timeouts surface as a bare TimeoutError (not
# wrapped in OperationalError), so they previously bypassed the retry loop and
# became HTTP 500s (/jobs/active, /platform/organization-score).
_TRANSIENT_DB_ERRORS = (OperationalError, DBAPIError, TimeoutError, ConnectionError, OSError)

def with_db_retry(fn, *, retries: int = 3, base_delay: float = 0.3):
    """Deprecated sync retry helper, kept only for any stray caller during the
    2026-09-16 async migration. Prefer with_db_retry_async below - every
    in-repo call site has been converted to it."""
    import logging, time as _time
    logger=logging.getLogger("app.core.database")
    if retries is None:
        retries = int(getattr(settings, "DB_RETRY_ATTEMPTS", 5))
    if base_delay is None:
        base_delay = float(getattr(settings, "DB_RETRY_BASE_DELAY_SECONDS", 0.5))
    last_exc: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            return fn()
        except _TRANSIENT_DB_ERRORS as exc:
            last_exc = exc
            if attempt == retries:
                logger.warning(
                    "DB operation failed after %d attempt(s), giving up (%s: %s)",
                    retries, type(exc).__name__, exc,
                )
                raise
            logger.warning(
                "DB operation attempt %d/%d hit a transient error (%s: %s). Retrying.",
                attempt, retries, type(exc).__name__, exc,
            )
            _time.sleep(base_delay * attempt)
    raise last_exc  # pragma: no cover - unreachable, keeps type-checkers happy

def require_rls_bypass_role() -> None:
    """Exit unless the current DB role can read every tenant's rows.

    The worker looks a job up by id before it knows the tenant and sweeps all
    tenants. Under FORCE ROW LEVEL SECURITY a plain role sees 0 rows, so jobs were
    silently ACKed and never ran. Fail loudly at startup instead.
    See supabase/provisioning/worker_role.sql.
    """
    def _check():
        with session_scope_sync() as db:
            if db.get_bind().dialect.name != "postgresql": return True
            return bool(db.execute(text("select rolsuper or rolbypassrls from pg_roles where rolname = current_user")).scalar())
    if not with_db_retry(_check):
        raise SystemExit(
            "FATAL: the worker's database role cannot bypass row level security, so it cannot see any "
            "tenant's jobs. Create the worker role with supabase/provisioning/worker_role.sql and point "
            "the worker's DATABASE_URL at it (WORKER_PG_PASSWORD_URLENCODED in docker-compose.yml)."
        )

async def with_db_retry_async(fn, *, retries: int | None = None, base_delay: float | None = None):
    """Async counterpart of with_db_retry: retries an async unit of work
    (``await fn()``, typically its own fresh ``async with session_scope()``)
    on a transient DB disconnect, using ``asyncio.sleep`` so the backoff
    delay no longer blocks the event loop the way the old ``time.sleep``
    version did (see run_db's history below - that whole indirection is now
    gone since every caller is natively async).

    2026-09-16: original with_db_retry added after /platform/organization-score
    and /platform/scan-history returned bare 500s on a single transient SSL
    EOF, with no retry anywhere outside the one-time startup path
    (init_db_with_retry). This is the async-native version used by every
    route/module after the full asyncpg migration.
    """
    import logging, asyncio as _asyncio
    logger=logging.getLogger("app.core.database")
    if retries is None:
        retries = int(getattr(settings, "DB_RETRY_ATTEMPTS", 5))
    if base_delay is None:
        base_delay = float(getattr(settings, "DB_RETRY_BASE_DELAY_SECONDS", 0.5))
    last_exc: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            return await fn()
        except _TRANSIENT_DB_ERRORS as exc:
            last_exc = exc
            if attempt == retries:
                logger.warning(
                    "DB operation failed after %d attempt(s), giving up (%s: %s)",
                    retries, type(exc).__name__, exc,
                )
                raise
            logger.warning(
                "DB operation attempt %d/%d hit a transient error (%s: %s). Retrying.",
                attempt, retries, type(exc).__name__, exc,
            )
            await _asyncio.sleep(base_delay * attempt)
    raise last_exc  # pragma: no cover - unreachable, keeps type-checkers happy
