from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import Pool

SQLALCHEMY_DATABASE_URL = "sqlite:///./kube_risk.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

@event.listens_for(Pool, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def run_migrations(conn):
    """Add missing columns to existing tables without dropping data."""
    migrations = [
        ("risk_rules", "severity", "VARCHAR DEFAULT 'MEDIUM'"),
        ("findings",   "severity", "VARCHAR DEFAULT 'MEDIUM'"),
    ]
    for table, column, col_def in migrations:
        rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
        existing = {row[1] for row in rows}
        if column not in existing:
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}"))
    conn.commit()


with engine.connect() as _conn:
    run_migrations(_conn)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
