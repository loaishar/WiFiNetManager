"""Update users is_admin field

Revision ID: update_users_is_admin
Revises: af3eca74c50b
Create Date: 2024-11-01 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'update_users_is_admin'
down_revision = 'af3eca74c50b'
branch_labels = None
depends_on = None

def upgrade():
    # Update existing users to set is_admin to False if it's NULL
    op.execute("UPDATE users SET is_admin = FALSE WHERE is_admin IS NULL")
    
    # Now make the column NOT NULL with a default value
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.alter_column('is_admin',
                    existing_type=sa.BOOLEAN(),
                    nullable=False,
                    server_default=sa.text('FALSE'))

def downgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.alter_column('is_admin',
                    existing_type=sa.BOOLEAN(),
                    nullable=True,
                    server_default=None)
