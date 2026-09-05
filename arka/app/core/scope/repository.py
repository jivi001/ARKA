"""Authoritative Scope Repository with PostgreSQL persistence and atomic concurrency control.

PostgreSQL 'scopes' table is the persistent system of record.
In-memory cache is kept strictly synchronized.
All updates, version increments, and approval invalidations execute atomically
within a single transaction.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from arka.app.core.state.models import (
    ApprovalStatus,
    ScopeDefinition,
    ScopeTarget,
    new_id,
    utc_now,
)
from arka.app.database.models import ApprovalDB, Engagement, Scope

if TYPE_CHECKING:
    from arka.app.core.approvals.manager import ApprovalManager


class ScopeConflictError(ValueError):
    """Raised when an optimistic lock conflict or state mutation violation occurs."""


class ScopeNotFoundError(ValueError):
    """Raised when a requested scope definition does not exist."""


class ScopeRepository:
    """Authoritative repository for Scope definitions.

    Manages persistence to PostgreSQL with optimistic locking and atomic approval invalidation,
    while maintaining an in-memory cache for ultra-fast local lookups.
    """

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
    ) -> None:
        self._session_factory = session_factory
        # In-memory working cache: engagement_id -> ScopeDefinition
        self._cache: dict[str, ScopeDefinition] = {}

    def _from_db_model(self, db_obj: Scope) -> ScopeDefinition:
        """Convert database Scope to canonical ScopeDefinition."""
        includes_data = db_obj.includes or {}
        excludes_data = db_obj.excludes or {}
        return ScopeDefinition(
            scope_id=str(db_obj.id),
            engagement_id=str(db_obj.engagement_id),
            version=db_obj.version,
            includes=ScopeTarget(**includes_data) if includes_data else ScopeTarget(),
            excludes=ScopeTarget(**excludes_data) if excludes_data else ScopeTarget(),
            notes=db_obj.notes or "",
            created_at=db_obj.created_at,
            updated_at=db_obj.updated_at,
        )

    async def get_scope(self, engagement_id: str) -> ScopeDefinition | None:
        """Retrieve the authoritative scope for an engagement.

        Queries PostgreSQL first if database session factory is configured;
        falls back to in-memory cache.
        """
        if self._session_factory:
            try:
                eng_uuid = uuid.UUID(engagement_id)
                async with self._session_factory() as session:
                    stmt = select(Scope).where(Scope.engagement_id == eng_uuid)
                    result = await session.execute(stmt)
                    row = result.scalar_one_or_none()
                    if row:
                        scope_def = self._from_db_model(row)
                        self._cache[engagement_id] = scope_def
                        return scope_def
            except Exception:
                # Fall back to cache if DB query fails or in offline test mode
                pass

        return self._cache.get(engagement_id)

    async def save_scope(
        self,
        scope: ScopeDefinition,
        expected_version: int | None = None,
        invalidate_approvals: bool = False,
        approval_manager: ApprovalManager | None = None,
    ) -> ScopeDefinition:
        """Atomically persist or replace the scope for an engagement.

        SEMANTICS: create-or-replace (NOT merge).
        If existing scope exists:
          - Validates expected_version if provided (optimistic concurrency).
          - Increments version: new_version = existing.version + 1.
          - Replaces includes, excludes, and notes completely.
          - If invalidate_approvals=True, marks all active approvals for engagement as EXPIRED
            within the same database transaction.
        If no existing scope exists:
          - Sets version = 1.
          - Persists new Scope row.

        Updates in-memory cache and memory approval states upon commit.
        """
        now = utc_now()
        eng_id_str = scope.engagement_id

        if self._session_factory:
            try:
                eng_uuid = uuid.UUID(eng_id_str)
                scope_uuid = uuid.UUID(scope.scope_id) if scope.scope_id else uuid.uuid4()
            except ValueError:
                eng_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, eng_id_str)
                scope_uuid = uuid.uuid4()

            async with self._session_factory() as session:
                async with session.begin():
                    # 1. Ensure Engagement row exists in DB to satisfy foreign key
                    eng_stmt = select(Engagement).where(Engagement.id == eng_uuid)
                    eng_res = await session.execute(eng_stmt)
                    eng_row = eng_res.scalar_one_or_none()
                    if not eng_row:
                        eng_row = Engagement(
                            id=eng_uuid,
                            name=f"Engagement {eng_id_str}",
                            description="Auto-registered engagement container",
                            status="created",
                            created_at=now,
                            updated_at=now,
                        )
                        session.add(eng_row)
                        await session.flush()

                    # 2. Query existing scope row with lock
                    scope_stmt = (
                        select(Scope).where(Scope.engagement_id == eng_uuid).with_for_update()
                    )
                    scope_res = await session.execute(scope_stmt)
                    existing_row = scope_res.scalar_one_or_none()

                    if existing_row:
                        if (
                            expected_version is not None
                            and existing_row.version != expected_version
                        ):
                            raise ScopeConflictError(
                                f"Scope version conflict: expected version {expected_version}, "
                                f"but current scope version is {existing_row.version}."
                            )
                        new_version = existing_row.version + 1
                        existing_row.version = new_version
                        existing_row.includes = scope.includes.model_dump()
                        existing_row.excludes = scope.excludes.model_dump()
                        existing_row.notes = scope.notes
                        existing_row.updated_at = now
                        saved_scope_id = str(existing_row.id)
                        created_at = existing_row.created_at
                    else:
                        new_version = 1
                        new_scope_db = Scope(
                            id=scope_uuid,
                            engagement_id=eng_uuid,
                            version=new_version,
                            includes=scope.includes.model_dump(),
                            excludes=scope.excludes.model_dump(),
                            notes=scope.notes,
                            created_at=now,
                            updated_at=now,
                        )
                        session.add(new_scope_db)
                        saved_scope_id = str(scope_uuid)
                        created_at = now

                    # 3. If requested, atomically invalidate active approvals
                    if invalidate_approvals:
                        inval_stmt = (
                            update(ApprovalDB)
                            .where(
                                ApprovalDB.engagement_id == eng_uuid,
                                ApprovalDB.status.in_(
                                    [
                                        ApprovalStatus.REQUIRED.value,
                                        ApprovalStatus.GRANTED.value,
                                    ]
                                ),
                            )
                            .values(
                                status=ApprovalStatus.EXPIRED.value,
                                rejection_reason=f"Scope mutated to version {new_version}",
                                decided_at=now,
                            )
                        )
                        await session.execute(inval_stmt)

                # Committed successfully
                final_scope = ScopeDefinition(
                    scope_id=saved_scope_id,
                    engagement_id=eng_id_str,
                    version=new_version,
                    includes=scope.includes,
                    excludes=scope.excludes,
                    notes=scope.notes,
                    created_at=created_at,
                    updated_at=now,
                )
                self._cache[eng_id_str] = final_scope
                if invalidate_approvals and approval_manager:
                    approval_manager.invalidate_for_engagement(
                        eng_id_str,
                        reason=f"Scope mutated to version {new_version}",
                    )
                return final_scope

        # In-memory only fallback (e.g. offline testing mode without postgres)
        existing_cached = self._cache.get(eng_id_str)
        if existing_cached:
            if expected_version is not None and existing_cached.version != expected_version:
                raise ScopeConflictError(
                    f"Scope version conflict: expected version {expected_version}, "
                    f"but current scope version is {existing_cached.version}."
                )
            new_version = existing_cached.version + 1
            created_at = existing_cached.created_at
            saved_id = existing_cached.scope_id
        else:
            new_version = 1
            created_at = now
            saved_id = scope.scope_id or new_id()

        final_scope = ScopeDefinition(
            scope_id=saved_id,
            engagement_id=eng_id_str,
            version=new_version,
            includes=scope.includes,
            excludes=scope.excludes,
            notes=scope.notes,
            created_at=created_at,
            updated_at=now,
        )
        self._cache[eng_id_str] = final_scope
        if invalidate_approvals and approval_manager:
            approval_manager.invalidate_for_engagement(
                eng_id_str,
                reason=f"Scope mutated to version {new_version}",
            )
        return final_scope

    def clear_cache(self) -> None:
        """Clear local in-memory cache to force fresh-process database reads."""
        self._cache.clear()
