"""Obstacle 10.7: Async Footguns

Tests detection of security vulnerabilities specific to async/await patterns.

Vibe coding with async often produces:
- Race conditions in authentication checks
- TOCTOU (Time-of-check-time-of-use) vulnerabilities
- Unhandled promise rejections leaking info
- Shared state corruption
- Authentication bypass via async timing

PASS CRITERIA:
- Detect race conditions in security checks
- Flag TOCTOU vulnerabilities
- Identify unhandled async errors
- Find shared state issues
"""

import asyncio
import aiohttp
from typing import Optional
import os


# =============================================================================
# RACE CONDITION: Authentication Check
# =============================================================================

user_sessions = {}  # Shared mutable state - DANGEROUS


async def check_auth_vulnerable(user_id: str) -> bool:
    """
    VULNERABLE: Race condition in auth check.

    Between checking permission and using it, state might change.
    Two concurrent requests could both pass the check.
    """
    if user_id in user_sessions:
        # Async operation here creates a window
        await asyncio.sleep(0.01)  # Simulates DB lookup
        # Session might be invalidated by now!
        return user_sessions.get(user_id, {}).get("valid", False)
    return False


async def delete_resource_vulnerable(user_id: str, resource_id: str):
    """
    VULNERABLE: TOCTOU in resource deletion.

    1. Check if user owns resource
    2. ... async gap ...
    3. Delete resource

    Resource ownership might change between check and delete.
    """
    # Time of check
    owner = await get_resource_owner(resource_id)
    if owner != user_id:
        raise PermissionError("Not your resource")

    # Time of use - owner might have changed!
    await asyncio.sleep(0.1)  # Simulates processing
    await delete_resource(resource_id)  # Deletes without re-checking


# =============================================================================
# RACE CONDITION: Balance Check
# =============================================================================

balances = {}  # Shared state


async def withdraw_vulnerable(user_id: str, amount: float) -> bool:
    """
    VULNERABLE: Double-spend race condition.

    Two concurrent withdrawals can both pass the balance check
    if they interleave before the decrement.
    """
    current = balances.get(user_id, 0)

    # Check if sufficient funds
    if current >= amount:
        # RACE WINDOW: Another request might also pass this check
        await asyncio.sleep(0.01)  # Simulate processing

        # Both requests decrement, potentially going negative
        balances[user_id] = current - amount
        return True
    return False


async def transfer_vulnerable(from_user: str, to_user: str, amount: float):
    """
    VULNERABLE: Non-atomic transfer with race condition.

    If interrupted between debit and credit, money disappears.
    Also vulnerable to concurrent transfers exceeding balance.
    """
    from_balance = balances.get(from_user, 0)

    if from_balance < amount:
        raise ValueError("Insufficient funds")

    # Non-atomic operation with async gap
    balances[from_user] = from_balance - amount
    await asyncio.sleep(0.01)  # Network delay, crash point
    balances[to_user] = balances.get(to_user, 0) + amount


# =============================================================================
# UNHANDLED REJECTION: Information Disclosure
# =============================================================================

async def fetch_user_data_vulnerable(user_id: str) -> dict:
    """
    VULNERABLE: Unhandled exception leaks internal info.

    If the async operation fails, error details might leak
    database schema, internal paths, or system info.
    """
    async with aiohttp.ClientSession() as session:
        # No try/except - error propagates with full details
        async with session.get(f"http://internal-api/users/{user_id}") as resp:
            if resp.status == 500:
                # Error response might contain stack traces
                error = await resp.text()
                raise Exception(f"Internal API error: {error}")  # Leaks info!
            return await resp.json()


async def process_batch_vulnerable(items: list) -> list:
    """
    VULNERABLE: Partial failure information disclosure.

    If some items fail, error messages might reveal
    information about which items exist/don't exist.
    """
    results = []
    for item in items:
        try:
            result = await process_item(item)
            results.append({"id": item, "status": "ok"})
        except NotFoundException:
            # VULNERABLE: Reveals which items don't exist (enumeration)
            results.append({"id": item, "status": "not_found"})
        except PermissionError as e:
            # VULNERABLE: Reveals permission details
            results.append({"id": item, "status": "forbidden", "reason": str(e)})
    return results


# =============================================================================
# SHARED STATE CORRUPTION
# =============================================================================

request_context = {}  # Global mutable state - TERRIBLE IDEA


async def handle_request_vulnerable(request_id: str, user_id: str):
    """
    VULNERABLE: Shared state corruption between async requests.

    Multiple concurrent requests overwrite each other's context.
    User A might see User B's data.
    """
    # Set context for this request
    request_context["current_user"] = user_id
    request_context["request_id"] = request_id

    # Async operation - another request might modify context!
    await asyncio.sleep(0.01)

    # Use context - might be corrupted by concurrent request
    current_user = request_context["current_user"]  # Might be wrong user!
    return await fetch_user_data(current_user)


class VulnerableCache:
    """
    VULNERABLE: Non-thread-safe cache with async access.
    """

    def __init__(self):
        self.cache = {}
        self.loading = {}  # Track in-flight requests

    async def get_or_load(self, key: str) -> dict:
        """
        VULNERABLE: Cache stampede + race condition.

        Multiple concurrent requests for same key all trigger loads.
        Also, loading dict access is not atomic.
        """
        if key in self.cache:
            return self.cache[key]

        # Check if already loading - but this check is not atomic!
        if key in self.loading:
            # Wait for other request - but might never complete
            while key in self.loading:
                await asyncio.sleep(0.01)
            return self.cache.get(key, {})

        # Mark as loading - race condition here!
        self.loading[key] = True

        try:
            # Load data
            data = await expensive_load(key)
            self.cache[key] = data
            return data
        finally:
            del self.loading[key]


# =============================================================================
# AUTHENTICATION BYPASS VIA TIMING
# =============================================================================

async def verify_token_vulnerable(token: str, expected: str) -> bool:
    """
    VULNERABLE: Timing attack in async token verification.

    Early return on mismatch allows timing attacks.
    Combined with async, timing differences are more pronounced.
    """
    if len(token) != len(expected):
        return False

    for i, (a, b) in enumerate(zip(token, expected)):
        if a != b:
            # Early return - timing varies based on match position
            await asyncio.sleep(0.001)  # Amplifies timing difference
            return False
    return True


async def check_permission_vulnerable(user_id: str, resource: str) -> bool:
    """
    VULNERABLE: Async permission check bypass.

    Permission check and resource access are not atomic.
    A revoked permission might still allow access.
    """
    # Check permission - result is cached/stale
    has_permission = await permission_service.check(user_id, resource)

    if not has_permission:
        return False

    # Permission might be revoked here by another async operation
    await asyncio.sleep(0.01)

    # Access granted based on stale check
    return True


# =============================================================================
# EXPECTED DETECTIONS
# =============================================================================

ASYNC_VULNERABILITIES = {
    "race_conditions": [
        "check_auth_vulnerable",
        "withdraw_vulnerable",
        "transfer_vulnerable",
    ],
    "toctou": [
        "delete_resource_vulnerable",
        "check_permission_vulnerable",
    ],
    "information_disclosure": [
        "fetch_user_data_vulnerable",
        "process_batch_vulnerable",
    ],
    "shared_state_corruption": [
        "handle_request_vulnerable",
        "VulnerableCache.get_or_load",
    ],
    "timing_attacks": [
        "verify_token_vulnerable",
    ],
}


# =============================================================================
# HELPER STUBS (would be real implementations)
# =============================================================================

async def get_resource_owner(resource_id: str) -> str:
    return "user123"

async def delete_resource(resource_id: str):
    pass

async def process_item(item):
    pass

async def fetch_user_data(user_id: str) -> dict:
    return {}

async def expensive_load(key: str) -> dict:
    return {}

class NotFoundException(Exception):
    pass

class permission_service:
    @staticmethod
    async def check(user_id: str, resource: str) -> bool:
        return True
