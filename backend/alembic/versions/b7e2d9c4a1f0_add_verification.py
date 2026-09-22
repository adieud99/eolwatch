"""Second-opinion verification: distribution tracker status and kernel source-file relevance per finding, with caches."""
from alembic import op
import sqlalchemy as sa


revision = "b7e2d9c4a1f0"
down_revision = "a9c4e1f7b3d2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("component_vulnerabilities") as batch:
        batch.add_column(sa.Column("tracker_status", sa.String(24), nullable=True))
        batch.add_column(sa.Column("tracker_fix", sa.String(160), nullable=True))
        batch.add_column(sa.Column("host_relevance", sa.String(24), nullable=True))
        batch.add_column(sa.Column("kernel_files", sa.JSON(), nullable=True))
    op.create_table(
        "tracker_cache",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cve", sa.String(40), nullable=False, index=True),
        sa.Column("distro_id", sa.String(40), nullable=False),
        sa.Column("release", sa.String(40), nullable=False),
        sa.Column("package", sa.String(200), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("fix", sa.String(160), nullable=True),
        sa.Column("priority", sa.String(20), nullable=True),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("cve", "distro_id", "release", "package", name="uq_tracker_cache"),
    )
    op.create_table(
        "kernel_cve_files",
        sa.Column("cve", sa.String(40), primary_key=True),
        sa.Column("files", sa.JSON(), nullable=True),
        sa.Column("fixed_versions", sa.JSON(), nullable=True),
        sa.Column("title", sa.String(160), nullable=True),
        sa.Column("missing", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("kernel_cve_files")
    op.drop_table("tracker_cache")
    with op.batch_alter_table("component_vulnerabilities") as batch:
        batch.drop_column("kernel_files")
        batch.drop_column("host_relevance")
        batch.drop_column("tracker_fix")
        batch.drop_column("tracker_status")
