"""Persist web-triggered analysis jobs and worker ownership."""
from alembic import op
import sqlalchemy as sa

revision = 'd8a671ec54f2'
down_revision = 'c4d62a8170b3'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('analysis_jobs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('asset_id', sa.Integer(), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('active_asset_id', sa.Integer(), nullable=True, unique=True),
        sa.Column('asset_snapshot', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('worker_token', sa.String(36), nullable=True),
        sa.Column('heartbeat_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('requested_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('error_code', sa.String(80), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('analysis_run_id', sa.Integer(), sa.ForeignKey('analysis_runs.id', ondelete='SET NULL'), nullable=True),
        sa.Column('retry_of_id', sa.Integer(), sa.ForeignKey('analysis_jobs.id', ondelete='SET NULL'), nullable=True),
    )
    for name in ('asset_id', 'status', 'analysis_run_id'):
        op.create_index('ix_analysis_jobs_' + name, 'analysis_jobs', [name])


def downgrade():
    for name in ('analysis_run_id', 'status', 'asset_id'):
        op.drop_index('ix_analysis_jobs_' + name, table_name='analysis_jobs')
    op.drop_table('analysis_jobs')
