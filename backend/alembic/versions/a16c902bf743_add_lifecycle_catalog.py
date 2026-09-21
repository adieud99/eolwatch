"""Keep public lifecycle source snapshots and explicit application history."""
from alembic import op
import sqlalchemy as sa

revision = 'a16c902bf743'
down_revision = 'f8b319ac6402'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('lifecycle_catalog_cache',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('cache_key', sa.String(160), nullable=False, unique=True),
        sa.Column('source_url', sa.Text(), nullable=False),
        sa.Column('raw_document', sa.Text()),
        sa.Column('content_sha256', sa.String(64)),
        *(sa.Column(name, sa.DateTime(timezone=True)) for name in
          ('fetched_at', 'provider_generated_at', 'provider_last_modified', 'last_checked_at', 'last_error_at')),
        sa.Column('last_error', sa.String(500)), sa.Column('etag', sa.Text()))
    op.create_table('lifecycle_catalog_applications',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('product_release_id', sa.Integer(), sa.ForeignKey('product_releases.id', ondelete='CASCADE'), nullable=False),
        sa.Column('applied_by_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL')),
        sa.Column('product_slug', sa.String(120), nullable=False),
        sa.Column('release_cycle', sa.String(100), nullable=False),
        sa.Column('source_url', sa.Text(), nullable=False),
        sa.Column('policy_url', sa.Text()),
        sa.Column('source_sha256', sa.String(64), nullable=False),
        sa.Column('source_document', sa.Text(), nullable=False),
        sa.Column('provider_generated_at', sa.DateTime(timezone=True)),
        sa.Column('provider_last_modified', sa.DateTime(timezone=True)),
        sa.Column('fetched_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('applied_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('previous_values', sa.JSON(), nullable=False),
        sa.Column('applied_values', sa.JSON(), nullable=False))
    op.create_index('ix_lifecycle_catalog_applications_product_release_id', 'lifecycle_catalog_applications', ['product_release_id'])


def downgrade():
    op.drop_table('lifecycle_catalog_applications')
    op.drop_table('lifecycle_catalog_cache')
