"""add approval fields

Revision ID: 002_approval_fields
Revises: 001_initial_schema
Create Date: 2026-08-19 16:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "002_approval_fields"
down_revision: str | None = "001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("approvals", sa.Column("details", sa.JSON(), nullable=False, server_default="{}"))
    op.add_column(
        "approvals", sa.Column("rejection_reason", sa.Text(), nullable=True, server_default="")
    )
    op.add_column("approvals", sa.Column("correlation_id", sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column("approvals", "correlation_id")
    op.drop_column("approvals", "rejection_reason")
    op.drop_column("approvals", "details")
