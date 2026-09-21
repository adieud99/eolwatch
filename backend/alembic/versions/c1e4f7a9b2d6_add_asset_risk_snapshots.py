"""Persist asset risk calculation history."""
from alembic import op
import sqlalchemy as sa

revision = "c1e4f7a9b2d6"
down_revision = "b7f2a9d1e8c4"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "asset_risk_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("priority_level", sa.String(20), nullable=False),
        sa.Column("factors", sa.JSON(), nullable=False),
        sa.Column("calculated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_asset_risk_snapshots_asset_id", "asset_risk_snapshots", ["asset_id"])
    op.create_index("ix_asset_risk_snapshots_priority_level", "asset_risk_snapshots", ["priority_level"])
    op.create_index("ix_asset_risk_snapshots_calculated_at", "asset_risk_snapshots", ["calculated_at"])


def downgrade():
    op.drop_table("asset_risk_snapshots")