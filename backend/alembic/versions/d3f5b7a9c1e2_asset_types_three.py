"""Asset types down to three: server, vm, cloud. Older rows fold into server."""
from alembic import op
import sqlalchemy as sa


revision = "d3f5b7a9c1e2"
down_revision = "c1e7a9b3d5f0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(sa.text("UPDATE assets SET asset_type = 'server' WHERE asset_type NOT IN ('server', 'vm', 'cloud')"))


def downgrade() -> None:
    pass  # the folded values cannot be told apart again
