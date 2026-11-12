"""
core/scan_store.py

In-memory store for asynchronous network/web scan jobs.
The store is intentionally process-local; scan results themselves are returned
through the API and the existing scanner modules remain responsible for the
durable scan data/audit log.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Any
import uuid

from app.schemas.network import ScanStatus


@dataclass
class ScanRecord:
    scan_id: str
    scan_kind: str
    target: str
    status: ScanStatus = ScanStatus.PENDING
    result: Any | None = None
    error_message: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class InMemoryScanStore:
    def __init__(self) -> None:
        self._records: dict[str, ScanRecord] = {}
        self._lock = Lock()

    def create(self, scan_kind: str, target: str, scan_id: str | None = None) -> ScanRecord:
        record = ScanRecord(
            scan_id=scan_id or str(uuid.uuid4()),
            scan_kind=scan_kind,
            target=target,
            status=ScanStatus.PENDING,
            created_at=datetime.now(timezone.utc),
        )
        with self._lock:
            self._records[record.scan_id] = record
        return record

    def get(self, scan_id: str) -> ScanRecord | None:
        with self._lock:
            return self._records.get(scan_id)

    def mark_running(self, scan_id: str) -> None:
        with self._lock:
            record = self._records.get(scan_id)
            if record is not None:
                record.status = ScanStatus.RUNNING
                record.error_message = None

    def mark_completed(self, scan_id: str, result: Any) -> None:
        with self._lock:
            record = self._records.get(scan_id)
            if record is not None:
                record.status = ScanStatus.COMPLETED
                record.result = result
                record.error_message = None

    def mark_failed(self, scan_id: str, error_message: str) -> None:
        with self._lock:
            record = self._records.get(scan_id)
            if record is not None:
                record.status = ScanStatus.FAILED
                record.error_message = error_message

    def delete(self, scan_id: str) -> None:
        with self._lock:
            self._records.pop(scan_id, None)


scan_store = InMemoryScanStore()
