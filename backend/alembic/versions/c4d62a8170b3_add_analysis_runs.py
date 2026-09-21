"""Record Grype analysis provenance and component-specific findings."""
from alembic import op
import sqlalchemy as sa

revision = 'c4d62a8170b3'
down_revision = '7c61b9af20d4'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('analysis_runs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('sbom_id', sa.Integer(), sa.ForeignKey('sbom_documents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('report_sha256', sa.String(64), nullable=False, unique=True),
        sa.Column('sbom_sha256', sa.String(64), nullable=False),
        sa.Column('scanner', sa.String(40), nullable=False),
        sa.Column('scanner_version', sa.String(80), nullable=False),
        sa.Column('generator', sa.String(160), nullable=False),
        sa.Column('scan_scope', sa.String(300), nullable=False),
        sa.Column('match_count', sa.Integer(), nullable=False),
        sa.Column('cve_count', sa.Integer(), nullable=False),
        sa.Column('link_count', sa.Integer(), nullable=False),
        sa.Column('ignored_non_cve', sa.Integer(), nullable=False),
        sa.Column('database_info', sa.JSON(), nullable=False),
        sa.Column('raw_report', sa.JSON(), nullable=False),
        sa.Column('imported_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_analysis_runs_sbom_id', 'analysis_runs', ['sbom_id'])
    with op.batch_alter_table('component_vulnerabilities') as batch:
        batch.add_column(sa.Column('analysis_run_id', sa.Integer(), nullable=True))
        batch.add_column(sa.Column('finding_source', sa.String(40), nullable=True))
        batch.add_column(sa.Column('finding_severity', sa.String(20), nullable=True))
        batch.add_column(sa.Column('fixed_versions', sa.JSON(), nullable=False, server_default='[]'))
        batch.create_foreign_key('fk_component_vulnerability_analysis_run', 'analysis_runs', ['analysis_run_id'], ['id'], ondelete='SET NULL')
        batch.create_index('ix_component_vulnerabilities_analysis_run_id', ['analysis_run_id'])


def downgrade():
    with op.batch_alter_table('component_vulnerabilities') as batch:
        batch.drop_index('ix_component_vulnerabilities_analysis_run_id')
        batch.drop_constraint('fk_component_vulnerability_analysis_run', type_='foreignkey')
        for name in ['fixed_versions', 'finding_severity', 'finding_source', 'analysis_run_id']:
            batch.drop_column(name)
    op.drop_index('ix_analysis_runs_sbom_id', table_name='analysis_runs')
    op.drop_table('analysis_runs')
