"""add canonical asset models

Revision ID: 003_asset_canonical_models
Revises: 002_approval_fields
Create Date: 2026-09-01 19:15:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "003_asset_canonical_models"
down_revision: str | None = "002_approval_fields"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Create assets table
    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_type", sa.String(length=50), nullable=False),
        sa.Column("address", sa.String(length=255), nullable=True),
        sa.Column("address_type", sa.String(length=50), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("domain", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("source", sa.String(length=100), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_refs", sa.JSON(), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_assets_address"), "assets", ["address"], unique=False)
    op.create_index(op.f("ix_assets_asset_type"), "assets", ["asset_type"], unique=False)
    op.create_index(op.f("ix_assets_domain"), "assets", ["domain"], unique=False)
    op.create_index(op.f("ix_assets_engagement_id"), "assets", ["engagement_id"], unique=False)
    op.create_index(op.f("ix_assets_first_seen"), "assets", ["first_seen"], unique=False)
    op.create_index(op.f("ix_assets_hostname"), "assets", ["hostname"], unique=False)
    op.create_index(op.f("ix_assets_last_seen"), "assets", ["last_seen"], unique=False)
    op.create_index(op.f("ix_assets_status"), "assets", ["status"], unique=False)

    # 2. Create services table
    op.create_table(
        "services",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=20), nullable=False),
        sa.Column("state", sa.String(length=50), nullable=False),
        sa.Column("service_name", sa.String(length=100), nullable=False),
        sa.Column("product", sa.String(length=255), nullable=True),
        sa.Column("version", sa.String(length=100), nullable=True),
        sa.Column("cpe", sa.JSON(), nullable=False),
        sa.Column("banner", sa.Text(), nullable=True),
        sa.Column("source", sa.String(length=100), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_refs", sa.JSON(), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_services_asset_id"), "services", ["asset_id"], unique=False)
    op.create_index(op.f("ix_services_engagement_id"), "services", ["engagement_id"], unique=False)
    op.create_index(op.f("ix_services_port"), "services", ["port"], unique=False)
    op.create_index(op.f("ix_services_protocol"), "services", ["protocol"], unique=False)
    op.create_index(op.f("ix_services_state"), "services", ["state"], unique=False)

    # 3. Create technologies table
    op.create_table(
        "technologies",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("service_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("version", sa.String(length=100), nullable=True),
        sa.Column("cpe", sa.JSON(), nullable=False),
        sa.Column("source", sa.String(length=100), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_refs", sa.JSON(), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["service_id"], ["services.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_technologies_asset_id"), "technologies", ["asset_id"], unique=False)
    op.create_index(
        op.f("ix_technologies_engagement_id"), "technologies", ["engagement_id"], unique=False
    )
    op.create_index(op.f("ix_technologies_name"), "technologies", ["name"], unique=False)
    op.create_index(
        op.f("ix_technologies_service_id"), "technologies", ["service_id"], unique=False
    )

    # 4. Create endpoints table
    op.create_table(
        "endpoints",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scheme", sa.String(length=20), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("path", sa.String(length=2048), nullable=False),
        sa.Column("query_metadata", sa.JSON(), nullable=False),
        sa.Column("source", sa.String(length=100), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_refs", sa.JSON(), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_endpoints_asset_id"), "endpoints", ["asset_id"], unique=False)
    op.create_index(
        op.f("ix_endpoints_engagement_id"), "endpoints", ["engagement_id"], unique=False
    )
    op.create_index(op.f("ix_endpoints_host"), "endpoints", ["host"], unique=False)


def downgrade() -> None:
    op.drop_table("endpoints")
    op.drop_table("technologies")
    op.drop_table("services")
    op.drop_table("assets")
