"""Scan endpoints - dispatch, list, retrieve, cancel."""
import uuid
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.api.deps import CurrentUser, DBSession
from app.core.config import settings
from app.core.rate_limit import limiter
from app.models.scan import Scan, ScanStatus
from app.models.vulnerability import SEVERITY_SCORE, Severity, Vulnerability
from app.schemas.scan import ScanCreate, ScanDetail, ScanList, ScanPublic
from app.scanner.target_validator import validate_target_url

router = APIRouter()


@router.post(
    "",
    response_model=ScanPublic,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit("10/minute")
async def create_scan(
    request: Request,
    payload: ScanCreate,
    current_user: CurrentUser,
    db: DBSession,
) -> Scan:
    target_str = str(payload.target_url)
    try:
        target_host, normalized_url = await validate_target_url(
            target_str, allow_private=settings.SCAN_ALLOW_PRIVATE
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    scan = Scan(
        owner_id=current_user.id,
        target_url=normalized_url,
        target_host=target_host,
        modules=[m.value for m in payload.modules],
        depth=payload.depth,
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    from app.tasks.scan_tasks import run_scan

    task = run_scan.delay(str(scan.id))
    scan.celery_task_id = task.id
    await db.commit()
    await db.refresh(scan)
    return scan


@router.get("", response_model=ScanList)
async def list_scans(
    current_user: CurrentUser,
    db: DBSession,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: Optional[ScanStatus] = Query(None, alias="status"),
) -> ScanList:
    stmt = select(Scan).where(Scan.owner_id == current_user.id)
    count_stmt = select(func.count()).select_from(Scan).where(Scan.owner_id == current_user.id)
    if status_filter:
        stmt = stmt.where(Scan.status == status_filter)
        count_stmt = count_stmt.where(Scan.status == status_filter)

    total = (await db.execute(count_stmt)).scalar_one()
    stmt = stmt.order_by(Scan.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(stmt)
    items = list(result.scalars().all())
    return ScanList(
        items=[ScanPublic.model_validate(i) for i in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(scan_id: uuid.UUID, current_user: CurrentUser, db: DBSession) -> Scan:
    stmt = (
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .where(Scan.id == scan_id, Scan.owner_id == current_user.id)
    )
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(scan_id: uuid.UUID, current_user: CurrentUser, db: DBSession) -> None:
    stmt = select(Scan).where(Scan.id == scan_id, Scan.owner_id == current_user.id)
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    await db.delete(scan)
    await db.commit()


@router.post("/{scan_id}/cancel", response_model=ScanPublic)
async def cancel_scan(scan_id: uuid.UUID, current_user: CurrentUser, db: DBSession) -> Scan:
    stmt = select(Scan).where(Scan.id == scan_id, Scan.owner_id == current_user.id)
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if scan.status not in (ScanStatus.PENDING, ScanStatus.RUNNING):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scan is not cancellable in its current state",
        )

    if scan.celery_task_id:
        from app.tasks.celery_app import celery_app

        celery_app.control.revoke(scan.celery_task_id, terminate=True, signal="SIGTERM")

    scan.status = ScanStatus.CANCELLED
    await db.commit()
    await db.refresh(scan)
    return scan


@router.get("/stats/summary")
async def get_stats(current_user: CurrentUser, db: DBSession) -> dict:
    """Aggregated dashboard stats for the current user."""
    total_scans = (
        await db.execute(
            select(func.count()).select_from(Scan).where(Scan.owner_id == current_user.id)
        )
    ).scalar_one()

    status_counts_stmt = (
        select(Scan.status, func.count())
        .where(Scan.owner_id == current_user.id)
        .group_by(Scan.status)
    )
    status_counts = {s.value: c for s, c in (await db.execute(status_counts_stmt)).all()}

    sev_stmt = (
        select(Vulnerability.severity, func.count())
        .join(Scan, Scan.id == Vulnerability.scan_id)
        .where(Scan.owner_id == current_user.id)
        .group_by(Vulnerability.severity)
    )
    sev_result = await db.execute(sev_stmt)
    severity_counts: dict[str, int] = {s.value: 0 for s in Severity}
    for sev, c in sev_result.all():
        severity_counts[sev.value] = c

    avg_risk = (
        await db.execute(
            select(func.avg(Scan.risk_score)).where(
                Scan.owner_id == current_user.id, Scan.risk_score.is_not(None)
            )
        )
    ).scalar()

    return {
        "total_scans": total_scans,
        "status_counts": status_counts,
        "severity_counts": severity_counts,
        "average_risk_score": float(avg_risk) if avg_risk is not None else None,
        "max_severity_score": max(SEVERITY_SCORE.values()),
    }
