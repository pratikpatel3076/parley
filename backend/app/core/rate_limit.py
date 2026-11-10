import threading
import time
from collections import deque

from app.core.config import settings


class SlidingWindowRateLimiter:
    """A small in-process limiter.

    This is intentionally local to one worker process. It does not share state
    with other workers or hosts and it resets on restart. A multi-process
    deployment needs a shared store instead.
    """

    def __init__(self, max_events: int, window_seconds: int) -> None:
        self.max_events = max_events
        self.window_seconds = window_seconds
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            bucket = self._events.setdefault(key, deque())
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self.max_events:
                return False
            bucket.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._events.clear()


register_limiter = SlidingWindowRateLimiter(
    settings.AUTH_RATE_LIMIT_ATTEMPTS,
    settings.AUTH_RATE_LIMIT_WINDOW_SECONDS,
)
login_limiter = SlidingWindowRateLimiter(
    settings.AUTH_RATE_LIMIT_ATTEMPTS,
    settings.AUTH_RATE_LIMIT_WINDOW_SECONDS,
)


def reset_auth_rate_limits() -> None:
    register_limiter.reset()
    login_limiter.reset()
