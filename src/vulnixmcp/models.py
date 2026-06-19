import uuid
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, JSON, ForeignKey
from sqlalchemy.orm import declarative_base
from datetime import datetime, timezone

Base = declarative_base()

def get_utc_now():
    return datetime.now(timezone.utc)

class ScanJob(Base):
    __tablename__ = "scan_jobs"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target = Column(String, nullable=False)
    authorized_by = Column(String, nullable=False)
    status = Column(String, nullable=False, default="pending")
    created_at = Column(DateTime, default=get_utc_now)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

class Asset(Base):
    __tablename__ = "assets"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_job_id = Column(String(36), ForeignKey("scan_jobs.id"), nullable=False)
    name = Column(String, nullable=False)
    version = Column(String, nullable=True)
    port = Column(Integer, nullable=True)
    service_type = Column(String, nullable=False)
    is_public = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=get_utc_now)

class Finding(Base):
    __tablename__ = "findings"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_job_id = Column(String(36), ForeignKey("scan_jobs.id"), nullable=False)
    asset_id = Column(String(36), ForeignKey("assets.id"), nullable=False)
    cve_id = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    cvss_score = Column(Float, nullable=True)
    epss_score = Column(Float, nullable=True)
    epss_percentile = Column(Float, nullable=True)
    is_kev = Column(Boolean, default=False)
    risk_score = Column(Float, nullable=True)
    severity = Column(String, nullable=True)
    verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=get_utc_now)

class AttackPath(Base):
    __tablename__ = "attack_paths"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_job_id = Column(String(36), ForeignKey("scan_jobs.id"), nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    finding_ids = Column(JSON, nullable=False)
    risk_level = Column(String, nullable=False)
    created_at = Column(DateTime, default=get_utc_now)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_job_id = Column(String(36), ForeignKey("scan_jobs.id"), nullable=True)
    event_type = Column(String, nullable=False)
    detail = Column(Text, nullable=False)
    created_at = Column(DateTime, default=get_utc_now)
