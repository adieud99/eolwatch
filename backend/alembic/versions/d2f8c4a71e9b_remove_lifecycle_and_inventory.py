"""Remove EOL-lifecycle, asset-inventory, customer/site, contract, deployment and notification storage.

The product is re-scoped to a vulnerability scan solution (ZIP source scan, SSH server scan,
scan history). Assets keep only identity and SSH connection fields; product_releases stays as
the internal component-identity table without lifecycle dates.
"""
from alembic import op
import sqlalchemy as sa


revision = "d2f8c4a71e9b"
down_revision = "c1e4f7a9b2d6"
branch_labels = None
depends_on = None


ASSET_COLUMNS = [
    ("manufacturer", sa.String(120)),
    ("model", sa.String(160)),
    ("serial_number", sa.String(160)),
    ("site", sa.String(160)),
    ("building", sa.String(120)),
    ("floor", sa.String(40)),
    ("room", sa.String(120)),
    ("rack", sa.String(80)),
    ("rack_position", sa.String(40)),
    ("introduced_on", sa.Date()),
    ("purchase_date", sa.Date()),
    ("purchase_price", sa.Numeric(14, 2)),
    ("power_watts", sa.Float()),
    ("power_source", sa.String(40)),
    ("warranty_end_date", sa.Date()),
    ("owner_name", sa.String(120)),
    ("owner_department", sa.String(120)),
    ("operational_status", sa.String(30)),
    ("service_criticality", sa.String(20)),
    ("support_end_date", sa.Date()),
    ("lifecycle_source_url", sa.Text()),
]


def _named_constraints_supported() -> bool:
    # SQLite tables were created with unnamed foreign keys; batch mode recreates the
    # table and drops them implicitly. Other dialects (PostgreSQL) auto-named them.
    return op.get_bind().dialect.name != "sqlite"


def upgrade():
    # Dependent tables first (FK-safe order).
    op.drop_table("lifecycle_catalog_applications")
    op.drop_table("lifecycle_catalog_cache")
    op.drop_table("asset_risk_snapshots")
    op.drop_table("deployments")
    op.drop_table("contract_assets")
    op.drop_table("contracts")
    op.drop_table("notification_deliveries")

    # assets: references sites/product_releases must go before sites is dropped.
    with op.batch_alter_table("assets") as batch:
        if _named_constraints_supported():
            batch.drop_constraint("assets_site_id_fkey", type_="foreignkey")
            batch.drop_constraint("assets_model_release_id_fkey", type_="foreignkey")
        batch.drop_index("ix_assets_site_id")
        batch.drop_index("ix_assets_model_release_id")
        batch.drop_index("ix_assets_support_end_date")
        batch.drop_index("ix_assets_operational_status")
        batch.drop_index("ix_assets_service_criticality")
        batch.drop_column("site_id")
        batch.drop_column("model_release_id")
        for name, _ in ASSET_COLUMNS:
            batch.drop_column(name)

    op.drop_table("sites")
    op.drop_table("customers")

    with op.batch_alter_table("product_releases") as batch:
        batch.drop_index("ix_product_releases_eol_date")
        batch.drop_index("ix_product_releases_support_end_date")
        batch.drop_index("ix_product_releases_security_end_date")
        for name in ("eol_date", "support_end_date", "security_end_date", "lifecycle_source_url", "verified_at"):
            batch.drop_column(name)

    with op.batch_alter_table("components") as batch:
        batch.drop_index("ix_components_support_end_date")
        batch.drop_column("support_end_date")
        batch.drop_column("lifecycle_source_url")

    with op.batch_alter_table("sbom_documents") as batch:
        if _named_constraints_supported():
            batch.drop_constraint("sbom_documents_software_product_id_fkey", type_="foreignkey")
        batch.drop_index("ix_sbom_documents_software_product_id")
        batch.drop_column("software_product_id")


def downgrade():
    with op.batch_alter_table("sbom_documents") as batch:
        batch.add_column(sa.Column("software_product_id", sa.Integer(), nullable=True))
        batch.create_foreign_key("sbom_documents_software_product_id_fkey", "product_releases", ["software_product_id"], ["id"], ondelete="SET NULL")
        batch.create_index("ix_sbom_documents_software_product_id", ["software_product_id"])

    with op.batch_alter_table("components") as batch:
        batch.add_column(sa.Column("support_end_date", sa.Date(), nullable=True))
        batch.add_column(sa.Column("lifecycle_source_url", sa.Text(), nullable=True))
        batch.create_index("ix_components_support_end_date", ["support_end_date"])

    with op.batch_alter_table("product_releases") as batch:
        batch.add_column(sa.Column("eol_date", sa.Date(), nullable=True))
        batch.add_column(sa.Column("support_end_date", sa.Date(), nullable=True))
        batch.add_column(sa.Column("security_end_date", sa.Date(), nullable=True))
        batch.add_column(sa.Column("lifecycle_source_url", sa.Text(), nullable=True))
        batch.add_column(sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True))
        batch.create_index("ix_product_releases_eol_date", ["eol_date"])
        batch.create_index("ix_product_releases_support_end_date", ["support_end_date"])
        batch.create_index("ix_product_releases_security_end_date", ["security_end_date"])

    op.create_table(
        "customers",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("customer_code", sa.String(40), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="ACTIVE"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_customers_customer_code", "customers", ["customer_code"], unique=True)
    op.create_index("ix_customers_name", "customers", ["name"])
    op.create_index("ix_customers_status", "customers", ["status"])
    op.create_table(
        "sites",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("customer_id", sa.Integer(), sa.ForeignKey("customers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("site_code", sa.String(40), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("address", sa.Text()),
        sa.Column("timezone", sa.String(50), nullable=False, server_default="Asia/Seoul"),
        sa.UniqueConstraint("customer_id", "site_code", name="uq_customer_site_code"),
    )
    op.create_index("ix_sites_customer_id", "sites", ["customer_id"])

    with op.batch_alter_table("assets") as batch:
        batch.add_column(sa.Column("site_id", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("model_release_id", sa.Integer(), nullable=True))
        for name, column_type in ASSET_COLUMNS:
            batch.add_column(sa.Column(name, column_type, nullable=True))
        batch.create_foreign_key("assets_site_id_fkey", "sites", ["site_id"], ["id"], ondelete="SET NULL")
        batch.create_foreign_key("assets_model_release_id_fkey", "product_releases", ["model_release_id"], ["id"], ondelete="SET NULL")
        batch.create_index("ix_assets_site_id", ["site_id"])
        batch.create_index("ix_assets_model_release_id", ["model_release_id"])
        batch.create_index("ix_assets_support_end_date", ["support_end_date"])
        batch.create_index("ix_assets_operational_status", ["operational_status"])
        batch.create_index("ix_assets_service_criticality", ["service_criticality"])

    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("channel", sa.String(30), nullable=False),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("response_code", sa.Integer()),
        sa.Column("error_message", sa.Text()),
        sa.Column("recipient_label", sa.String(160)),
        sa.Column("payload_summary", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_notification_deliveries_created_at", "notification_deliveries", ["created_at"])
    op.create_index("ix_notification_deliveries_event_type", "notification_deliveries", ["event_type"])
    op.create_index("ix_notification_deliveries_status", "notification_deliveries", ["status"])
    op.create_table(
        "contracts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("customer_id", sa.Integer(), sa.ForeignKey("customers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("contract_no", sa.String(80), nullable=False),
        sa.Column("provider", sa.String(160), nullable=False),
        sa.Column("start_date", sa.Date(), nullable=False),
        sa.Column("end_date", sa.Date(), nullable=False),
        sa.Column("annual_cost", sa.Numeric(14, 2)),
        sa.Column("service_level", sa.String(100)),
    )
    op.create_index("ix_contracts_contract_no", "contracts", ["contract_no"], unique=True)
    op.create_index("ix_contracts_customer_id", "contracts", ["customer_id"])
    op.create_index("ix_contracts_end_date", "contracts", ["end_date"])
    op.create_table(
        "contract_assets",
        sa.Column("contract_id", sa.Integer(), sa.ForeignKey("contracts.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True),
    )
    op.create_table(
        "deployments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("software_product_id", sa.Integer(), sa.ForeignKey("product_releases.id", ondelete="CASCADE"), nullable=False),
        sa.Column("environment", sa.String(40), nullable=False, server_default="production"),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("asset_id", "software_product_id", name="uq_deployment"),
    )
    op.create_index("ix_deployments_asset_id", "deployments", ["asset_id"])
    op.create_index("ix_deployments_software_product_id", "deployments", ["software_product_id"])
    op.create_table(
        "asset_risk_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("priority_level", sa.String(20), nullable=False),
        sa.Column("factors", sa.JSON(), nullable=False),
        sa.Column("calculated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_asset_risk_snapshots_asset_id", "asset_risk_snapshots", ["asset_id"])
    op.create_index("ix_asset_risk_snapshots_priority_level", "asset_risk_snapshots", ["priority_level"])
    op.create_index("ix_asset_risk_snapshots_calculated_at", "asset_risk_snapshots", ["calculated_at"])
    op.create_table(
        "lifecycle_catalog_cache",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cache_key", sa.String(160), nullable=False, unique=True),
        sa.Column("source_url", sa.Text(), nullable=False),
        sa.Column("raw_document", sa.Text()),
        sa.Column("content_sha256", sa.String(64)),
        *(sa.Column(name, sa.DateTime(timezone=True)) for name in
          ("fetched_at", "provider_generated_at", "provider_last_modified", "last_checked_at", "last_error_at")),
        sa.Column("last_error", sa.String(500)),
        sa.Column("etag", sa.Text()),
    )
    op.create_table(
        "lifecycle_catalog_applications",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("product_release_id", sa.Integer(), sa.ForeignKey("product_releases.id", ondelete="CASCADE"), nullable=False),
        sa.Column("applied_by_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("product_slug", sa.String(120), nullable=False),
        sa.Column("release_cycle", sa.String(100), nullable=False),
        sa.Column("source_url", sa.Text(), nullable=False),
        sa.Column("policy_url", sa.Text()),
        sa.Column("source_sha256", sa.String(64), nullable=False),
        sa.Column("source_document", sa.Text(), nullable=False),
        sa.Column("provider_generated_at", sa.DateTime(timezone=True)),
        sa.Column("provider_last_modified", sa.DateTime(timezone=True)),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("previous_values", sa.JSON(), nullable=False),
        sa.Column("applied_values", sa.JSON(), nullable=False),
    )
    op.create_index("ix_lifecycle_catalog_applications_product_release_id", "lifecycle_catalog_applications", ["product_release_id"])
