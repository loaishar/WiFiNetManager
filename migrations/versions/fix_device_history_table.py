"""Fix device history table

Revision ID: fix_device_history_table
Revises: f5de04e69dde
Create Date: 2024-11-02 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'fix_device_history_table'
down_revision = 'f5de04e69dde'
branch_labels = None
depends_on = None

def upgrade():
    # Drop existing sequence if it exists
    op.execute('DROP SEQUENCE IF EXISTS device_history_id_seq CASCADE')
    
    # Drop existing table if it exists
    op.execute('DROP TABLE IF EXISTS device_history CASCADE')
    
    # Create the table
    op.create_table('device_history',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('device_id', sa.Integer(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.Column('event_type', sa.String(20)),
        sa.Column('connection_speed', sa.Float()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['device_id'], ['devices.id'])
    )

def downgrade():
    op.drop_table('device_history')
