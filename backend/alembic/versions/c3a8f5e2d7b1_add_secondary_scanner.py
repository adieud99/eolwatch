"""Second scanner (Trivy) agreement per finding."""
from alembic import op
import sqlalchemy as sa


revision = "c3a8f5e2d7b1"
down_revision = "b7e2d9c4a1f0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("component_vulnerabilities") as batch:
        batch.add_column(sa.Column("secondary_status", sa.String(20), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("component_vulnerabilities") as batch:
        batch.drop_column("secondary_status")
