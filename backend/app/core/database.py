"""Database models, migrations and PostgreSQL RLS session context."""
from __future__ import annotations
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any
from sqlalchemy import DateTime,Integer,String,Text,create_engine,inspect,text,PrimaryKeyConstraint
from sqlalchemy.orm import DeclarativeBase,Mapped,mapped_column,sessionmaker
from sqlalchemy.types import JSON
from app.core.config import settings
from app.core.auth_context import tenant_context
class Base(DeclarativeBase): pass
class TenantRow(Base):
    __tablename__='tenants'; tenant_id:Mapped[str]=mapped_column(String(64),primary_key=True); name:Mapped[str]=mapped_column(String(200)); created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True))
class UserRow(Base):
    __tablename__='users'; user_id:Mapped[str]=mapped_column(String(64),primary_key=True); tenant_id:Mapped[str]=mapped_column(String(64),index=True); email:Mapped[str]=mapped_column(String(320),unique=True,index=True); password_hash:Mapped[str]=mapped_column(String(512)); role:Mapped[str]=mapped_column(String(24),default='viewer'); is_active:Mapped[bool]=mapped_column(default=True); created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True))
    security_changed_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
class RefreshTokenRow(Base):
    __tablename__='refresh_tokens'; token_hash:Mapped[str]=mapped_column(String(64),primary_key=True); user_id:Mapped[str]=mapped_column(String(64),index=True); tenant_id:Mapped[str]=mapped_column(String(64),index=True); expires_at:Mapped[datetime]=mapped_column(DateTime(timezone=True)); revoked:Mapped[bool]=mapped_column(default=False); created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True))
class JobRow(Base):
    __tablename__='scan_jobs'; job_id:Mapped[str]=mapped_column(String(64),primary_key=True); tenant_id:Mapped[str]=mapped_column(String(64),index=True); job_type:Mapped[str]=mapped_column(String(32),index=True); target:Mapped[str]=mapped_column(String(2048)); status:Mapped[str]=mapped_column(String(24),index=True); progress:Mapped[int]=mapped_column(Integer,default=0); current_engine:Mapped[str|None]=mapped_column(String(64),nullable=True); logs:Mapped[list]=mapped_column(JSON,default=list); payload:Mapped[dict]=mapped_column(JSON,default=dict); result:Mapped[dict|None]=mapped_column(JSON,nullable=True); error_message:Mapped[str|None]=mapped_column(Text,nullable=True); created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True)); started_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True); finished_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
class ScanRow(Base):
    __tablename__='scans'; scan_id:Mapped[str]=mapped_column(String(64),primary_key=True); tenant_id:Mapped[str]=mapped_column(String(64),index=True); job_id:Mapped[str|None]=mapped_column(String(64),index=True,nullable=True); scan_kind:Mapped[str]=mapped_column(String(32),index=True); target:Mapped[str]=mapped_column(String(2048)); status:Mapped[str]=mapped_column(String(24),index=True); result:Mapped[dict|None]=mapped_column(JSON,nullable=True); error_message:Mapped[str|None]=mapped_column(Text,nullable=True); created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True)); finished_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
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

class AssetRow(Base):
    __tablename__='assets'; asset_id:Mapped[str]=mapped_column(String(64),primary_key=True); tenant_id:Mapped[str]=mapped_column(String(64),index=True); target:Mapped[str]=mapped_column(String(2048)); data:Mapped[dict]=mapped_column(JSON,default=dict); first_seen:Mapped[datetime]=mapped_column(DateTime(timezone=True)); last_seen:Mapped[datetime]=mapped_column(DateTime(timezone=True),index=True)
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
    connect_args={'check_same_thread':False}
    engine=create_engine(url,connect_args=connect_args)
else:
    # VPN/WSL2-friendly PostgreSQL settings. Supabase poolers require TLS;
    # TCP keepalives prevent a long-lived VPN/NAT path from silently dropping
    # an otherwise healthy connection. Pooling is deliberately small because
    # Supavisor already multiplexes connections upstream.
    connect_args={
        'sslmode':'require',
        'connect_timeout':int(getattr(settings,'DB_CONNECT_TIMEOUT_SECONDS',15)),
        'keepalives':1,
        'keepalives_idle':30,
        'keepalives_interval':10,
        'keepalives_count':3,
        'application_name':'mirsad',
    }
    engine=create_engine(
        url,
        pool_pre_ping=True,
        pool_recycle=int(getattr(settings,'DB_POOL_RECYCLE_SECONDS',180)),
        pool_size=int(getattr(settings,'DB_POOL_SIZE',3)),
        max_overflow=int(getattr(settings,'DB_MAX_OVERFLOW',2)),
        connect_args=connect_args,
    )
SessionLocal=sessionmaker(bind=engine,expire_on_commit=False)

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
    for table in ('scan_jobs','scans','assets','audit_logs','admin_settings','feature_flags','admin_api_keys','security_events','security_alerts','security_incidents','continuous_schedules','compliance_controls','compliance_assessments','ci_security_policies'):
        cols={c['name'] for c in insp.get_columns(table)}
        if 'tenant_id' not in cols and table not in ('admin_settings','feature_flags'):
            with engine.begin() as c:
                c.execute(text(f"ALTER TABLE {table} ADD COLUMN tenant_id VARCHAR(64)"))
                c.execute(text(f"UPDATE {table} SET tenant_id='legacy' WHERE tenant_id IS NULL"))
    if 'security_alerts' in insp.get_table_names():
        alert_cols={c['name'] for c in inspect(engine).get_columns('security_alerts')}
        if 'incident_id' not in alert_cols:
            with engine.begin() as c:
                c.execute(text("ALTER TABLE security_alerts ADD COLUMN incident_id VARCHAR(64)"))
    if engine.dialect.name=='postgresql':
        with engine.begin() as c:
            c.execute(text("ALTER TABLE scan_jobs ALTER COLUMN tenant_id SET NOT NULL")); c.execute(text("ALTER TABLE scans ALTER COLUMN tenant_id SET NOT NULL"))
            for table in ('scan_jobs','scans','assets','audit_logs','admin_settings','feature_flags','admin_api_keys','security_events','security_alerts','security_incidents','continuous_schedules','compliance_controls','compliance_assessments','ci_security_policies'):
                c.execute(text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
                c.execute(text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
                c.execute(text(f"DROP POLICY IF EXISTS tenant_isolation ON {table}"))
                c.execute(text(f"CREATE POLICY tenant_isolation ON {table} USING (tenant_id = current_setting('app.tenant_id', true)) WITH CHECK (tenant_id = current_setting('app.tenant_id', true))"))

@contextmanager
def session_scope(tenant_id: str|None=None):
    db=SessionLocal(); tid=tenant_id or tenant_context.get()
    try:
        if tid and engine.dialect.name=='postgresql': db.execute(text("SELECT set_config('app.tenant_id', :tid, true)"),{'tid':tid})
        yield db; db.commit()
    except Exception: db.rollback(); raise
    finally: db.close()
def utcnow(): return datetime.now(timezone.utc)
def jsonable(value:Any): return value.model_dump(mode='json') if hasattr(value,'model_dump') else value
