"""add task_type, objective, max_iterations columns to tasks table

Revision ID: 005_task_orchestration
Revises: 004_scope_version
Create Date: 2026-09-05 17:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "005_task_orchestration"
down_revision: str | None = "004_scope_version"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "tasks",
        sa.Column("task_type", sa.String(50), nullable=False, server_default="general", index=True),
    )
    op.add_column(
        "tasks",
        sa.Column("objective", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "tasks",
        sa.Column("max_iterations", sa.Integer(), nullable=False, server_default="10"),
    )


def downgrade() -> None:
    op.drop_column("tasks", "max_iterations")
    op.drop_column("tasks", "objective")
    op.drop_column("tasks", "task_type")
