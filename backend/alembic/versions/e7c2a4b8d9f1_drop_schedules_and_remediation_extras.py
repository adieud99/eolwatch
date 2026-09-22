"""Drop scheduled scans and the remediation extras (assignee, due date, attached evidence)."""
from alembic import op


revision = "e7c2a4b8d9f1"
down_revision = "d3f5b7a9c1e2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_table("analysis_schedules")
    with op.batch_alter_table("component_vulnerabilities") as batch:
        batch.drop_index("ix_component_vulnerabilities_due_date")
        batch.drop_index("ix_component_vulnerabilities_assignee_id")
        batch.drop_constraint("fk_component_vulnerabilities_assignee_id_users", type_="foreignkey")
        batch.drop_column("due_date")
        batch.drop_column("assignee_id")
    with op.batch_alter_table("vulnerability_actions") as batch:
        batch.drop_index("ix_vulnerability_actions_evidence_analysis_run_id")
        batch.drop_column("evidence_snapshot")
        batch.drop_column("evidence_analysis_run_id")


def downgrade() -> None:
    raise NotImplementedError("scheduled scans and remediation extras were removed from the product; restore from a backup")
