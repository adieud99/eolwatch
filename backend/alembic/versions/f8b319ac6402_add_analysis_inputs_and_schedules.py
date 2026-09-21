"""Persist immutable source upload references and recurring analysis schedules."""
from alembic import op
import sqlalchemy as sa

revision = "f8b319ac6402"
down_revision = "e5a294dc13b7"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("analysis_uploads",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("project_name", sa.String(80), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    for column in ("asset_id", "sha256"):
        op.create_index("ix_analysis_uploads_" + column, "analysis_uploads", [column])
    op.create_table("analysis_schedules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("input_spec", sa.JSON(), nullable=False),
        sa.Column("scan_scope", sa.String(300), nullable=False),
        sa.Column("interval_minutes", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_job_id", sa.Integer(), sa.ForeignKey("analysis_jobs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("asset_id", "scan_scope", name="uq_analysis_schedule_target"),
    )
    for column in ("asset_id", "enabled", "next_run_at"):
        op.create_index("ix_analysis_schedules_" + column, "analysis_schedules", [column])


def downgrade():
    op.drop_table("analysis_schedules")
    op.drop_table("analysis_uploads")
