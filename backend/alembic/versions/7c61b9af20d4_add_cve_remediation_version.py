"""add CVE remediation version

Revision ID: 7c61b9af20d4
Revises: 91c6d6d4a2f1
Create Date: 2026-09-15
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "7c61b9af20d4"
down_revision: Union[str, Sequence[str], None] = "91c6d6d4a2f1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("component_vulnerabilities", sa.Column("fixed_version", sa.String(length=160), nullable=True))


def downgrade() -> None:
    op.drop_column("component_vulnerabilities", "fixed_version")
