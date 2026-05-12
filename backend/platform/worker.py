"""Celery worker configuration for background tasks."""
import os
from celery import Celery

redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
broker_url = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka://localhost:9092")

# Fall back to Redis as broker if Kafka is not configured
if not broker_url or broker_url.startswith("kafka"):
    broker_url = redis_url

celery_app = Celery(
    "cybersec_platform",
    broker=broker_url,
    backend=redis_url,
    include=["platform.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutes
    task_soft_time_limit=25 * 60,
    worker_max_tasks_per_child=200,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_default_queue="cybersec_default",
    task_queues={
        "cybersec_default": {"exchange": "default", "routing_key": "default"},
        "scans": {"exchange": "scans", "routing_key": "scan.#"},
        "analysis": {"exchange": "analysis", "routing_key": "analysis.#"},
        "intel": {"exchange": "intel", "routing_key": "intel.#"},
    },
)


if __name__ == "__main__":
    celery_app.start()
