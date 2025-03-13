"""Force adding tables

Revision ID: b9c259bca499
Revises: 7fd7f760b263
Create Date: 2025-03-11 16:10:26.236629

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b9c259bca499'
down_revision = '7fd7f760b263'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user',
    sa.Column('first_name', sa.String(length=150), nullable=False),
    sa.Column('last_name', sa.String(length=150), nullable=False),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('username', sa.String(length=150), nullable=False),
    sa.Column('password', sa.String(length=150), nullable=False),
    sa.Column('company', sa.String(length=150), nullable=False),
    sa.Column('role', sa.String(length=150), nullable=False),
    sa.Column('approved', sa.Boolean(), nullable=True),
    sa.Column('reset_token', sa.String(length=100), nullable=True),
    sa.Column('reset_token_expiry', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('username')
    )
    op.create_table('report',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('transaction_date', sa.Date(), nullable=False),
    sa.Column('next_transaction_date', sa.Date(), nullable=True),
    sa.Column('date', sa.DateTime(), nullable=True),
    sa.Column('opening_balance', sa.Float(), nullable=False),
    sa.Column('cash_addition', sa.Float(), nullable=False),
    sa.Column('adjusted_opening_balance', sa.Float(), nullable=True),
    sa.Column('cash_sales', sa.Float(), nullable=False),
    sa.Column('visa_sales', sa.Float(), nullable=False),
    sa.Column('alipay_sales', sa.Float(), nullable=False),
    sa.Column('wechat_sales', sa.Float(), nullable=False),
    sa.Column('master_sales', sa.Float(), nullable=False),
    sa.Column('unionpay_sales', sa.Float(), nullable=False),
    sa.Column('amex_sales', sa.Float(), nullable=False),
    sa.Column('octopus_sales', sa.Float(), nullable=False),
    sa.Column('deliveroo_sales', sa.Float(), nullable=False),
    sa.Column('foodpanda_sales', sa.Float(), nullable=False),
    sa.Column('keeta_sales', sa.Float(), nullable=False),
    sa.Column('openrice_sales', sa.Float(), nullable=False),
    sa.Column('shop_sales', sa.Float(), nullable=False),
    sa.Column('delivery_sales', sa.Float(), nullable=False),
    sa.Column('total_sales', sa.Float(), nullable=False),
    sa.Column('expenses', sa.Float(), nullable=False),
    sa.Column('bank_deposit', sa.Float(), nullable=False),
    sa.Column('closing_balance', sa.Float(), nullable=False),
    sa.Column('receipt_files', sa.Text(), nullable=True),
    sa.Column('uploaded_by', sa.String(length=150), nullable=True),
    sa.Column('company', sa.String(length=150), nullable=False),
    sa.ForeignKeyConstraint(['uploaded_by'], ['user.username'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('report_history',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('report_id', sa.String(length=36), nullable=False),
    sa.Column('company', sa.String(length=150), nullable=False),
    sa.Column('user_id', sa.String(length=36), nullable=True),
    sa.Column('action', sa.String(length=50), nullable=False),
    sa.Column('field_changed', sa.String(length=255), nullable=True),
    sa.Column('old_value', sa.Text(), nullable=True),
    sa.Column('new_value', sa.Text(), nullable=True),
    sa.Column('timestamp', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['report_id'], ['report.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('report_history', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_report_history_company'), ['company'], unique=False)

    op.create_table('shop_expense',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('report_id', sa.String(length=36), nullable=False),
    sa.Column('item', sa.String(length=150), nullable=False),
    sa.Column('amount', sa.Float(), nullable=False),
    sa.Column('remarks', sa.String(length=300), nullable=True),
    sa.Column('files', sa.Text(), nullable=True),
    sa.Column('s3_key', sa.String(length=255), nullable=True),
    sa.ForeignKeyConstraint(['report_id'], ['report.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('shop_expense')
    with op.batch_alter_table('report_history', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_report_history_company'))

    op.drop_table('report_history')
    op.drop_table('report')
    op.drop_table('user')
    # ### end Alembic commands ###
