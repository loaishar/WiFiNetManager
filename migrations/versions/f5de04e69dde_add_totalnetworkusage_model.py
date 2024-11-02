"""Add TotalNetworkUsage model

Revision ID: f5de04e69dde
Revises: update_users_is_admin
Create Date: 2024-11-01 13:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'f5de04e69dde'
down_revision = 'update_users_is_admin'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('total_network_usage',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.Column('bytes_sent', sa.BigInteger(), nullable=True),
        sa.Column('bytes_recv', sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

def downgrade():
    op.drop_table('total_network_usage')
