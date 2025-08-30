from datetime import datetime
from typing import Optional
from sqlmodel import SQLModel, Field, Column, Integer


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    auth0_sub: str = Field(index=True, unique=True)
    email: Optional[str] = Field(default=None, index=True)
    first_name: str = Field(default="")
    last_name: str = Field(default="")
    age: Optional[int] = Field(default=None, sa_column=Column(Integer))
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)