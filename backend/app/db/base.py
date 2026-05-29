from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """
    Shared SQLAlchemy declarative base.

    All ORM models inherit from this. Alembic's env.py imports Base.metadata
    so it can auto-detect models for migration generation.
    """
    pass
