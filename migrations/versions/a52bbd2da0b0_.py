"""empty message

Revision ID: a52bbd2da0b0
Revises: 
Create Date: 2019-04-29 20:09:02.830520

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a52bbd2da0b0'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_name', sa.String(length=80), nullable=True),
    sa.Column('public_id', sa.String(length=50), nullable=True),
    sa.Column('date_created', sa.DateTime(), nullable=True),
    sa.Column('password', sa.String(length=80), nullable=True),
    sa.Column('admin', sa.Boolean(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('public_id')
    )
    op.create_table('plants',
    sa.Column('plant_id', sa.Integer(), nullable=False),
    sa.Column('owner_id', sa.String(length=50), nullable=False),
    sa.Column('plant_name', sa.String(length=255), nullable=True),
    sa.Column('plant_type', sa.String(length=50), nullable=True),
    sa.Column('sensor_id', sa.String(length=12), nullable=True),
    sa.ForeignKeyConstraint(['owner_id'], ['users.public_id'], ),
    sa.PrimaryKeyConstraint('plant_id'),
    sa.UniqueConstraint('sensor_id')
    )
    op.create_table('measurements',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=50), nullable=False),
    sa.Column('sensor_name', sa.String(length=255), nullable=True),
    sa.Column('temp', sa.DECIMAL(), nullable=True),
    sa.Column('soil_m', sa.Integer(), nullable=True),
    sa.Column('humidity', sa.DECIMAL(), nullable=True),
    sa.Column('light', sa.Boolean(), nullable=True),
    sa.Column('date_created', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['username'], ['plants.sensor_id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('models',
    sa.Column('model_id', sa.Integer(), nullable=False),
    sa.Column('xs', sa.String(length=255), nullable=True),
    sa.Column('ys', sa.String(length=255), nullable=True),
    sa.Column('model_name', sa.String(length=80), nullable=False),
    sa.Column('sensor_name', sa.String(length=255), nullable=True),
    sa.ForeignKeyConstraint(['sensor_name'], ['plants.sensor_id'], ),
    sa.PrimaryKeyConstraint('model_id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('models')
    op.drop_table('measurements')
    op.drop_table('plants')
    op.drop_table('users')
    # ### end Alembic commands ###