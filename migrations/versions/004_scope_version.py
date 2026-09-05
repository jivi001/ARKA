"""add version column to scopes table

Revision ID: 004_scope_version
Revises: 003_asset_canonical_models
Create Date: 2026-09-05 16:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "004_scope_version"
down_revision: str | None = "003_asset_canonical_models"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scopes",
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    )


def downgrade() -> None:
    op.drop_column("scopes", "version")
