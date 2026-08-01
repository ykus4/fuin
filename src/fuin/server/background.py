"""Scheduling helper for detached background coroutines.

:func:`asyncio.create_task` only keeps a weak reference to the task it returns,
so a fire-and-forget task that nobody holds on to can be garbage-collected
before it finishes. Every detached task in the server goes through
:func:`spawn`, which keeps a strong reference until the task completes.
"""

import asyncio
import logging
from collections.abc import Coroutine
from typing import Any

log = logging.getLogger(__name__)

_background_tasks: set[asyncio.Task] = set()


def _on_done(task: asyncio.Task) -> None:
    _background_tasks.discard(task)
    if not task.cancelled() and task.exception() is not None:
        log.exception("background task failed", exc_info=task.exception())


def spawn(coro: Coroutine[Any, Any, Any]) -> asyncio.Task:
    """Run ``coro`` detached, keeping it alive until it finishes."""
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_on_done)
    return task
