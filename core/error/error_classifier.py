from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Awaitable

logger = logging.getLogger(__name__)


class ErrorCategory(str, Enum):
    TRANSIENT = "transient"
    INVALID_INPUT = "invalid_input"
    AUTH_FAILED = "auth_failed"
    NOT_FOUND = "not_found"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    WAF_BLOCKED = "waf_blocked"
    CONTEXT_OVERFLOW = "context_overflow"
    UNKNOWN = "unknown"


class RecoveryAction(str, Enum):
    RETRY_BACKOFF = "retry_backoff"
    RETRY_MODIFIED = "retry_modified"
    SKIP = "skip"
    ESCALATE = "escalate"
    REAUTHENTICATE = "reauthenticate"
    WAIT_AND_RETRY = "wait_and_retry"


@dataclass
class ClassifiedError:
    category: ErrorCategory
    recovery: RecoveryAction
    message: str = ""
    retry_delay_seconds: float = 0.0
    max_retries: int = 0
    should_modify_payload: bool = False
    raw_status: int = 0
    raw_stderr: str = ""


RECOVERY_STRATEGIES: Dict[ErrorCategory, RecoveryAction] = {
    ErrorCategory.TRANSIENT: RecoveryAction.RETRY_BACKOFF,
    ErrorCategory.INVALID_INPUT: RecoveryAction.RETRY_MODIFIED,
    ErrorCategory.AUTH_FAILED: RecoveryAction.REAUTHENTICATE,
    ErrorCategory.NOT_FOUND: RecoveryAction.SKIP,
    ErrorCategory.RATE_LIMITED: RecoveryAction.WAIT_AND_RETRY,
    ErrorCategory.TIMEOUT: RecoveryAction.RETRY_BACKOFF,
    ErrorCategory.WAF_BLOCKED: RecoveryAction.RETRY_MODIFIED,
    ErrorCategory.CONTEXT_OVERFLOW: RecoveryAction.SKIP,
    ErrorCategory.UNKNOWN: RecoveryAction.ESCALATE,
}

MAX_RETRIES: Dict[ErrorCategory, int] = {
    ErrorCategory.TRANSIENT: 3,
    ErrorCategory.INVALID_INPUT: 5,
    ErrorCategory.AUTH_FAILED: 0,
    ErrorCategory.NOT_FOUND: 0,
    ErrorCategory.RATE_LIMITED: 2,
    ErrorCategory.TIMEOUT: 1,
    ErrorCategory.WAF_BLOCKED: 5,
    ErrorCategory.CONTEXT_OVERFLOW: 0,
    ErrorCategory.UNKNOWN: 0,
}

BASE_DELAYS: Dict[ErrorCategory, float] = {
    ErrorCategory.TRANSIENT: 1.0,
    ErrorCategory.INVALID_INPUT: 0.0,
    ErrorCategory.AUTH_FAILED: 0.0,
    ErrorCategory.NOT_FOUND: 0.0,
    ErrorCategory.RATE_LIMITED: 5.0,
    ErrorCategory.TIMEOUT: 2.0,
    ErrorCategory.WAF_BLOCKED: 1.0,
    ErrorCategory.CONTEXT_OVERFLOW: 0.0,
    ErrorCategory.UNKNOWN: 0.0,
}

_RATE_LIMIT_PATTERNS = re.compile(
    r"rate.?limit|too many requests|throttl|429|retry.?after|quota exceeded",
    re.IGNORECASE,
)
_WAF_PATTERNS = re.compile(
    r"waf|firewall|blocked|forbidden|cloudflare|akamai|imperva|"
    r"mod_security|request blocked|access denied|bot.?detect",
    re.IGNORECASE,
)
_AUTH_PATTERNS = re.compile(
    r"unauthorized|authentication|invalid.?token|expired.?token|"
    r"login.?required|session.?expired|401",
    re.IGNORECASE,
)
_TIMEOUT_PATTERNS = re.compile(
    r"timeout|timed?.?out|deadline|connect.*time|read.*time|"
    r"ETIMEDOUT|ECONNREFUSED|ECONNRESET",
    re.IGNORECASE,
)
_NOT_FOUND_PATTERNS = re.compile(
    r"not.?found|no.?such|does.?not.?exist|404|endpoint.*missing",
    re.IGNORECASE,
)


class ErrorClassifier:

    @staticmethod
    def classify(
        status_code: int = 0,
        stderr: str = "",
        stdout: str = "",
        return_code: int = 0,
        response_body: str = "",
        exception: Optional[Exception] = None,
        timed_out: bool = False,
    ) -> ClassifiedError:

        combined = f"{stderr} {stdout} {response_body}"
        if exception:
            combined += f" {str(exception)}"

        # Timeout (explicit flag or pattern)
        if timed_out or _TIMEOUT_PATTERNS.search(combined):
            return ClassifiedError(
                category=ErrorCategory.TIMEOUT,
                recovery=RecoveryAction.RETRY_BACKOFF,
                message="Request timed out",
                retry_delay_seconds=2.0,
                max_retries=1,
                raw_status=status_code,
                raw_stderr=stderr[:500],
            )

        # Rate limiting (429 or pattern match)
        if status_code == 429 or _RATE_LIMIT_PATTERNS.search(combined):
            return ClassifiedError(
                category=ErrorCategory.RATE_LIMITED,
                recovery=RecoveryAction.WAIT_AND_RETRY,
                message="Rate limited by target",
                retry_delay_seconds=5.0,
                max_retries=2,
                raw_status=status_code,
                raw_stderr=stderr[:500],
            )

        # Auth failure (401 or pattern)
        if status_code == 401 or _AUTH_PATTERNS.search(combined):
            return ClassifiedError(
                category=ErrorCategory.AUTH_FAILED,
                recovery=RecoveryAction.REAUTHENTICATE,
                message="Authentication failed",
                max_retries=0,
                raw_status=status_code,
                raw_stderr=stderr[:500],
            )

        # WAF/Blocked (403 with WAF indicators)
        if status_code == 403 or _WAF_PATTERNS.search(combined):
            return ClassifiedError(
                category=ErrorCategory.WAF_BLOCKED,
                recovery=RecoveryAction.RETRY_MODIFIED,
                message="Blocked by WAF or access control",
                retry_delay_seconds=1.0,
                max_retries=5,
                should_modify_payload=True,
                raw_status=status_code,
                raw_stderr=stderr[:500],
            )

        # Not found (404)
        if status_code == 404 or _NOT_FOUND_PATTERNS.search(combined):
            return ClassifiedError(
                category=ErrorCategory.NOT_FOUND,
                recovery=RecoveryAction.SKIP,
                message="Endpoint not found",
                max_retries=0,
                raw_status=status_code,
                raw_stderr=stderr[:500],
            )

        # Invalid input (400, 422)
        if status_code in (400, 422):
            return ClassifiedError(
                category=ErrorCategory.INVALID_INPUT,
                recovery=RecoveryAction.RETRY_MODIFIED,
                message="Invalid input or request format",
                max_retries=5,
                should_modify_payload=True,
                raw_status=status_code,
                raw_stderr=stderr[:500],
            )

        # Transient server errors (500, 502, 503, 504)
        if status_code in (500, 502, 503, 504):
            return ClassifiedError(
                category=ErrorCategory.TRANSIENT,
                recovery=RecoveryAction.RETRY_BACKOFF,
                message=f"Server error {status_code}",
                retry_delay_seconds=1.0,
                max_retries=3,
                raw_status=status_code,
                raw_stderr=stderr[:500],
            )

        # Tool returned error code but no HTTP status
        if return_code != 0 and status_code == 0:
            if _TIMEOUT_PATTERNS.search(combined):
                return ClassifiedError(
                    category=ErrorCategory.TIMEOUT,
                    recovery=RecoveryAction.RETRY_BACKOFF,
                    message=f"Tool exited with rc={return_code}",
                    retry_delay_seconds=2.0,
                    max_retries=1,
                    raw_status=0,
                    raw_stderr=stderr[:500],
                )
            return ClassifiedError(
                category=ErrorCategory.TRANSIENT,
                recovery=RecoveryAction.RETRY_BACKOFF,
                message=f"Tool failed with rc={return_code}: {stderr[:200]}",
                retry_delay_seconds=1.0,
                max_retries=2,
                raw_status=0,
                raw_stderr=stderr[:500],
            )

        return ClassifiedError(
            category=ErrorCategory.UNKNOWN,
            recovery=RecoveryAction.ESCALATE,
            message=f"Unclassified error: status={status_code} rc={return_code} stderr={stderr[:200]}",
            max_retries=0,
            raw_status=status_code,
            raw_stderr=stderr[:500],
        )


class RetryExecutor:

    def __init__(self, classifier: Optional[ErrorClassifier] = None):
        self._classifier = classifier or ErrorClassifier()
        self._stats: Dict[str, int] = {
            "total_attempts": 0,
            "retries": 0,
            "recovered": 0,
            "permanent_failures": 0,
        }

    async def execute_with_retry(
        self,
        fn: Callable[..., Awaitable[Any]],
        *args,
        max_override: Optional[int] = None,
        **kwargs,
    ) -> Any:
        attempt = 0
        last_error: Optional[ClassifiedError] = None

        while True:
            self._stats["total_attempts"] += 1
            attempt += 1
            try:
                result = await fn(*args, **kwargs)

                # Check if result indicates failure
                if hasattr(result, 'success') and not result.success:
                    status = getattr(result, 'status_code', 0) or 0
                    stderr = getattr(result, 'stderr', '') or ''
                    stdout = getattr(result, 'stdout', '') or ''
                    body = getattr(result, 'data', '') or ''
                    rc = getattr(result, 'return_code', 0) or 0

                    classified = self._classifier.classify(
                        status_code=status, stderr=str(stderr),
                        stdout=str(stdout), return_code=rc,
                        response_body=str(body)[:2000],
                    )
                    max_retries = max_override if max_override is not None else classified.max_retries

                    if attempt <= max_retries and classified.recovery != RecoveryAction.SKIP:
                        delay = classified.retry_delay_seconds * (2 ** (attempt - 1))
                        delay = min(delay, 30.0)
                        logger.info(
                            f"ERROR_CLASSIFIED category={classified.category.value} "
                            f"recovery={classified.recovery.value} attempt={attempt}/{max_retries} "
                            f"delay={delay:.1f}s msg={classified.message}"
                        )
                        self._stats["retries"] += 1
                        await asyncio.sleep(delay)
                        last_error = classified
                        continue

                    if attempt > 1 and last_error:
                        logger.warning(
                            f"ERROR_PERMANENT category={classified.category.value} "
                            f"after {attempt} attempts: {classified.message[:200]}"
                        )
                    self._stats["permanent_failures"] += 1
                    result._classified_error = classified
                    return result

                if attempt > 1:
                    self._stats["recovered"] += 1
                    logger.info(f"ERROR_RECOVERED after {attempt} attempts")
                return result

            except asyncio.TimeoutError:
                classified = self._classifier.classify(timed_out=True)
                if attempt <= (max_override or 1):
                    self._stats["retries"] += 1
                    await asyncio.sleep(2.0 * attempt)
                    continue
                raise
            except Exception as exc:
                classified = self._classifier.classify(exception=exc)
                if classified.max_retries > 0 and attempt <= classified.max_retries:
                    self._stats["retries"] += 1
                    await asyncio.sleep(classified.retry_delay_seconds * attempt)
                    continue
                raise

    @property
    def stats(self) -> Dict[str, int]:
        return dict(self._stats)
