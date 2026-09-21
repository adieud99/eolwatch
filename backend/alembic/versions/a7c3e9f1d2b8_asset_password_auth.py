"""Password-based SSH authentication per target with a pinned host key."""
from alembic import op
import sqlalchemy as sa


revision = "a7c3e9f1d2b8"
down_revision = "f4b2d8e6a1c3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("assets") as batch:
        batch.add_column(sa.Column("ssh_auth", sa.String(16), nullable=False, server_default="key"))
        batch.add_column(sa.Column("ssh_password_encrypted", sa.Text(), nullable=True))
        batch.add_column(sa.Column("ssh_host_key", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("assets") as batch:
        batch.drop_column("ssh_host_key")
        batch.drop_column("ssh_password_encrypted")
        batch.drop_column("ssh_auth")
