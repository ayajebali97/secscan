"""Celery application setup."""
from celery import Celery

from app.core.config import settings

celery_app = Celery(
    "secscan",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.tasks.scan_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=settings.MAX_SCAN_DURATION_SECONDS + 60,
    task_soft_time_limit=settings.MAX_SCAN_DURATION_SECONDS,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=50,
    broker_connection_retry_on_startup=True,
)
