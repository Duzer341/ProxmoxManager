"""Background poller: refreshes every enabled host on an interval."""

from __future__ import annotations

import asyncio
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete

from .config import settings
from .database import db_session
from .models import ProxmoxHost, StatSample
from .pve import PveError, collect_summary

log = logging.getLogger(__name__)


def poll_host(host_id: int) -> None:
    """Poll one host and persist the result. Safe to call from any thread."""
    with db_session() as db:
        host = db.get(ProxmoxHost, host_id)
        if host is None or not host.enabled:
            return
        now = datetime.now(timezone.utc)
        host.last_poll_at = now
        try:
            summary = collect_summary(host)
        except PveError as exc:
            host.last_error = str(exc)
            log.warning("Poll failed for %s (%s): %s", host.name, host.host, exc)
            return
        except Exception as exc:  # pragma: no cover - defensive
            host.last_error = f"Unexpected error: {exc.__class__.__name__}: {exc}"
            log.exception("Unexpected error polling %s", host.name)
            return

        host.last_error = ""
        host.last_ok_at = now
        host.last_summary_json = json.dumps(summary)
        db.add(
            StatSample(
                host_id=host.id,
                ts=now,
                cpu_pct=summary["cpu_pct"],
                mem_pct=summary["mem_pct"],
                disk_pct=summary["disk_pct"],
            )
        )
        log.info(
            "Polled %s: PVE %s, %d node(s), cpu %.1f%%, mem %.1f%%, disk %.1f%% (%d ms)",
            host.name,
            summary["version"],
            summary["node_count"],
            summary["cpu_pct"],
            summary["mem_pct"],
            summary["disk_pct"],
            summary["latency_ms"],
        )


def prune_samples() -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=settings.SAMPLE_RETENTION_HOURS)
    with db_session() as db:
        db.execute(delete(StatSample).where(StatSample.ts < cutoff))


class Poller:
    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._executor = ThreadPoolExecutor(max_workers=settings.POLL_WORKERS, thread_name_prefix="pve-poll")
        self._wake = asyncio.Event()
        self._inflight: set[int] = set()

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="pve-poller")

    async def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
        self._executor.shutdown(wait=False, cancel_futures=True)

    def trigger(self) -> None:
        """Ask the loop to poll everything now (e.g. after a host is added)."""
        self._wake.set()

    async def poll_one_now(self, host_id: int) -> None:
        """Poll a single host immediately and wait for it (used by the Refresh button)."""
        if host_id in self._inflight:
            return
        self._inflight.add(host_id)
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(self._executor, poll_host, host_id)
        finally:
            self._inflight.discard(host_id)

    async def _poll_all(self) -> None:
        with db_session() as db:
            ids = [h.id for h in db.query(ProxmoxHost).filter_by(enabled=True).all()]
        if not ids:
            return
        loop = asyncio.get_running_loop()
        await asyncio.gather(*(self.poll_one_now(i) for i in ids), return_exceptions=True)
        await loop.run_in_executor(self._executor, prune_samples)

    async def _run(self) -> None:
        log.info("Poller started (interval %ss)", settings.POLL_INTERVAL)
        while not self._stop.is_set():
            try:
                await self._poll_all()
            except Exception:  # pragma: no cover - keep the loop alive
                log.exception("Poll cycle failed")
            self._wake.clear()
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=settings.POLL_INTERVAL)
            except asyncio.TimeoutError:
                pass
        log.info("Poller stopped")


poller = Poller()
