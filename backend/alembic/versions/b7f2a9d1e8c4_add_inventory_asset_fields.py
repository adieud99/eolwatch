"""Add inventory and operational fields to assets."""
from alembic import op
import sqlalchemy as sa


revision = "b7f2a9d1e8c4"
down_revision = "a16c902bf743"
branch_labels = None
depends_on = None


def upgrade():
    columns = [
        ("building", sa.String(120)),
        ("floor", sa.String(40)),
        ("room", sa.String(120)),
        ("rack", sa.String(80)),
        ("rack_position", sa.String(40)),
        ("purchase_date", sa.Date()),
        ("purchase_price", sa.Numeric(14, 2)),
        ("power_watts", sa.Float()),
        ("power_source", sa.String(40)),
        ("warranty_end_date", sa.Date()),
        ("owner_name", sa.String(120)),
        ("owner_department", sa.String(120)),
    ]
    for name, column_type in columns:
        op.add_column("assets", sa.Column(name, column_type, nullable=True))
    op.add_column("assets", sa.Column("operational_status", sa.String(30), nullable=False, server_default="ACTIVE"))
    op.add_column("assets", sa.Column("service_criticality", sa.String(20), nullable=False, server_default="STANDARD"))
    op.create_index("ix_assets_operational_status", "assets", ["operational_status"])
    op.create_index("ix_assets_service_criticality", "assets", ["service_criticality"])


def downgrade():
    op.drop_index("ix_assets_service_criticality", table_name="assets")
    op.drop_index("ix_assets_operational_status", table_name="assets")
    for name in ("service_criticality", "operational_status", "owner_department", "owner_name", "warranty_end_date", "power_source", "power_watts", "purchase_price", "purchase_date", "rack_position", "rack", "room", "floor", "building"):
        op.drop_column("assets", name)