"""Añadir campo timestamp a Transaction

Revision ID: 42267217ed87
Revises: 
Create Date: 2024-11-16 22:50:32.696336

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '42267217ed87'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('transactions', schema=None) as batch_op:
        batch_op.add_column(sa.Column('timestamp', sa.DateTime(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('transactions', schema=None) as batch_op:
        batch_op.drop_column('timestamp')

    # ### end Alembic commands ###
