"""Per-target pasted SSH private key (encrypted)."""
from alembic import op
import sqlalchemy as sa


revision = "b9d4f2a6c8e1"
down_revision = "a7c3e9f1d2b8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("assets") as batch:
        batch.add_column(sa.Column("ssh_private_key_encrypted", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("assets") as batch:
        batch.drop_column("ssh_private_key_encrypted")
