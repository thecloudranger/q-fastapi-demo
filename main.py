from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash

app = FastAPI()

engine = create_engine(
    "sqlite:///instance/myflaskdb.db", connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


Base.metadata.create_all(bind=engine)


class UserRegistration(BaseModel):
    username: str
    email: str
    password: str


@app.post("/register")
def register(user: UserRegistration):
    db = SessionLocal()
    existing_user = (
        db.query(User)
        .filter((User.username == user.username) | (User.email == user.email))
        .first()
    )
    if existing_user:
        raise HTTPException(status_code=409, detail="User already exists")
    new_user = User(username=user.username, email=user.email)
    new_user.set_password(user.password)
    db.add(new_user)
    db.commit()
    db.close()
    return {"message": "User registered successfully"}


@app.get("/users/{user_id}")
def get_user(user_id: int):
    db = SessionLocal()
    user = db.query(User).get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.close()
    return {"id": user.id, "username": user.username, "email": user.email}


# Tests


def test_register_user():
    user = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "testpassword",
    }
    response = client.post("/register", json=user)
    assert response.status_code == 200
    assert response.json() == {"message": "User registered successfully"}


def test_get_user():
    db = SessionLocal()
    user = db.query(User).filter(User.username == "testuser").first()
    db.close()
    response = client.get(f"/users/{user.id}")
    assert response.status_code == 200
    assert response.json() == {
        "id": user.id,
        "username": "testuser",
        "email": "test@example.com",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
