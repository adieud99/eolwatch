"""Store AI-generated assessments of scan results and SSH checks."""
from alembic import op
import sqlalchemy as sa


revision = "e3a9c1d5b7f2"
down_revision = "d2f8c4a71e9b"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_summaries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("model", sa.String(80), nullable=False),
        sa.Column("prompt_sha256", sa.String(64), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("generated_by", sa.String(80), nullable=True),
    )
    op.create_index("ix_ai_summaries_kind_target", "ai_summaries", ["kind", "target_id"])


def downgrade() -> None:
    op.drop_index("ix_ai_summaries_kind_target", table_name="ai_summaries")
    op.drop_table("ai_summaries")
