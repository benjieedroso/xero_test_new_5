"""Add transaction_date to Report

Revision ID: 4f09f37ea558
Revises: 
Create Date: 2024-08-22 11:09:42.057851

"""
from alembic import op
import sqlalchemy as sa
from datetime import datetime

# revision identifiers, used by Alembic.
revision = '4f09f37ea558'
down_revision = None  # Set to None if this is the first migration
branch_labels = None
depends_on = None

def upgrade():
    # Add column with a default value of the current date
    op.add_column('report', sa.Column('transaction_date', sa.Date, nullable=False, server_default=str(datetime.utcnow().date())))
    # Remove the server_default after the column has been created
    op.alter_column('report', 'transaction_date', server_default=None)

def downgrade():
    op.drop_column('report', 'transaction_date')