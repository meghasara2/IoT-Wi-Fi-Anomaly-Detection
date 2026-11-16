from sqlalchemy.dialects import postgresql
import sqlalchemy as sa

print("SQLAlchemy PostgreSQL dialect available:", postgresql.dialect().name)
print("Supported PG types:", [t for t in dir(postgresql) if t.isupper() and not t.startswith('_')])

