"""empty message

Revision ID: 105ec9a5d42c
Revises: f89d5436be46
Create Date: 2024-10-03 14:49:46.976579

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '105ec9a5d42c'
down_revision = 'f89d5436be46'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('report', schema=None) as batch_op:
        batch_op.alter_column('id',
               existing_type=mysql.VARCHAR(length=36),
               type_=sa.Integer(),
               existing_nullable=False,
               autoincrement=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('report', schema=None) as batch_op:
        batch_op.alter_column('id',
               existing_type=sa.Integer(),
               type_=mysql.VARCHAR(length=36),
               existing_nullable=False,
               autoincrement=True)

    # ### end Alembic commands ###
