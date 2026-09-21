"""Per finding: what the target's package manager said about the expected fix."""
from alembic import op
import sqlalchemy as sa


revision = "c1e7a9b3d5f0"
down_revision = "b9d4f2a6c8e1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("component_vulnerabilities") as batch:
        batch.add_column(sa.Column("fix_check", sa.String(30), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("component_vulnerabilities") as batch:
        batch.drop_column("fix_check")
