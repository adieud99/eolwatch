"""Record which AI provider answered and how many tokens the compacted prompt cost."""
from alembic import op
import sqlalchemy as sa


revision = "f4b2d8e6a1c3"
down_revision = "e3a9c1d5b7f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("ai_summaries") as batch:
        batch.add_column(sa.Column("provider", sa.String(20), nullable=False, server_default="anthropic"))
        batch.add_column(sa.Column("prompt_chars", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("input_tokens", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("output_tokens", sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("ai_summaries") as batch:
        batch.drop_column("output_tokens")
        batch.drop_column("input_tokens")
        batch.drop_column("prompt_chars")
        batch.drop_column("provider")
