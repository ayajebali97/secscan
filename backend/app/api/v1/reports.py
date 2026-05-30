"""Report generation endpoints (PDF export)."""
import uuid

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.api.deps import CurrentUser, DBSession
from app.models.scan import Scan, ScanStatus
from app.reports.pdf_generator import generate_scan_pdf

router = APIRouter()


@router.get("/scan/{scan_id}/pdf")
async def get_scan_pdf(scan_id: uuid.UUID, current_user: CurrentUser, db: DBSession):
    stmt = (
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .where(Scan.id == scan_id, Scan.owner_id == current_user.id)
    )
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scan not yet completed",
        )

    pdf_buffer = generate_scan_pdf(scan)
    filename = f"secscan-{scan.target_host}-{scan.id.hex[:8]}.pdf"
    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
        },
    )
