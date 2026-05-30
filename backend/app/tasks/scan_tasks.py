"""Celery tasks for executing scans."""
import asyncio
import logging
from datetime import datetime, timezone

from celery import shared_task
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.models.scan import Scan, ScanModule, ScanStatus
from app.models.vulnerability import SEVERITY_SCORE, Severity, Vulnerability
from app.scanner.engine import run_modules_sync

logger = logging.getLogger(__name__)

_sync_engine = create_engine(settings.sync_database_url, pool_pre_ping=True, pool_size=5)
SyncSessionLocal = sessionmaker(bind=_sync_engine, expire_on_commit=False)


def _compute_risk_score(findings: list[Vulnerability]) -> float:
    """Aggregate severity-weighted risk score in [0, 10]."""
    if not findings:
        return 0.0
    scores = [SEVERITY_SCORE.get(f.severity, 0.0) for f in findings]
    high_impact = max(scores)
    avg = sum(scores) / len(scores)
    risk = 0.6 * high_impact + 0.4 * avg
    return round(min(risk, 10.0), 2)


@shared_task(name="app.tasks.scan_tasks.run_scan", bind=True, max_retries=0)
def run_scan(self, scan_id: str) -> dict:
    """Top-level Celery task. Loads scan, runs modules, persists findings."""
    logger.info("Scan task started: %s", scan_id)
    db: Session = SyncSessionLocal()
    try:
        scan = db.execute(select(Scan).where(Scan.id == scan_id)).scalar_one_or_none()
        if not scan:
            logger.error("Scan %s not found", scan_id)
            return {"status": "not_found"}

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        scan.progress = 0
        db.commit()

        modules = [ScanModule(m) for m in scan.modules]

        def progress_cb(module_name: str, pct: int) -> None:
            try:
                scan.current_module = module_name
                scan.progress = max(0, min(100, pct))
                db.commit()
            except Exception:
                db.rollback()

        try:
            findings_data = asyncio.run(
                run_modules_sync(
                    target_url=scan.target_url,
                    target_host=scan.target_host,
                    modules=modules,
                    depth=scan.depth,
                    progress_cb=progress_cb,
                )
            )
        except Exception as exc:
            logger.exception("Scan engine failed for %s", scan_id)
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)[:1000]
            scan.finished_at = datetime.now(timezone.utc)
            db.commit()
            return {"status": "failed", "error": str(exc)}

        finding_objs: list[Vulnerability] = []
        for f in findings_data:
            v = Vulnerability(
                scan_id=scan.id,
                module=f["module"],
                title=f["title"],
                description=f["description"],
                severity=Severity(f["severity"]),
                owasp_category=f["owasp_category"],
                cvss_score=f.get("cvss_score"),
                evidence=f.get("evidence"),
                remediation=f.get("remediation"),
                reference_url=f.get("reference_url"),
            )
            db.add(v)
            finding_objs.append(v)

        scan.risk_score = _compute_risk_score(finding_objs)
        scan.status = ScanStatus.COMPLETED
        scan.progress = 100
        scan.current_module = None
        scan.finished_at = datetime.now(timezone.utc)
        db.commit()

        logger.info(
            "Scan %s completed: %d findings, risk=%s", scan_id, len(finding_objs), scan.risk_score
        )
        return {
            "status": "completed",
            "findings": len(finding_objs),
            "risk_score": scan.risk_score,
        }
    finally:
        db.close()
