"""Add company field to Report model

Revision ID: a1f3159bb1d3
Revises: 502999de38d7
Create Date: 2024-09-11 09:56:59.482781

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a1f3159bb1d3'
down_revision = '502999de38d7'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('report', schema=None) as batch_op:
        # Adding the company column, setting a server default for existing rows, and ensuring non-null for new ones
        batch_op.add_column(sa.Column('company', sa.String(length=150), nullable=False, server_default='default_company'))

def downgrade():
    with op.batch_alter_table('report', schema=None) as batch_op:
        batch_op.drop_column('company')

