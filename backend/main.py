from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import sqlite3

app = FastAPI()

# --- CORS ---
# Allow requests from the Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Config ---
SECRET_KEY = "your-secret-key-change-this"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing context using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme — reads Bearer token from Authorization header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# --- Database ---

def get_db():
    """Open and return a SQLite connection."""
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn


def init_db():
    """Create the users table if it doesn't exist."""
    conn = get_db()
    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        hashed_password TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()




# Run on startup
init_db()


# --- Schemas ---

class RegisterSchema(BaseModel):
    """Fields required to create a new account."""
    username: str
    email: str
    password: str


class LoginSchema(BaseModel):
    """Fields required to log in."""
    email: str
    password: str


class TokenSchema(BaseModel):
    """Shape of the JWT response returned after login."""
    access_token: str
    token_type: str


class UpdateProfileSchema(BaseModel):
    """Fields allowed when updating a user's profile."""
    username: str


class ChangePasswordSchema(BaseModel):
    """Fields required to change a user's password."""
    current_password: str
    new_password: str


    # --- Helpers ---

def hash_password(password: str) -> str:
    """Hash a plain-text password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """Compare a plain-text password against a bcrypt hash."""
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict) -> str:
    """Create a signed JWT with an expiry timestamp."""
    payload = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload.update({"exp": expire})
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """
    Decode the JWT from the Authorization header.
    Returns the user dict if valid, raises 401 otherwise.
    Used as a dependency in protected routes.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE email = ?", (email,)
    ).fetchone()
    conn.close()

    if user is None:
        raise credentials_exception

    return dict(user)


    # --- Auth Routes ---

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(body: RegisterSchema):
    """Register a new user. Rejects duplicate emails."""
    conn = get_db()

    existing = conn.execute(
        "SELECT id FROM users WHERE email = ?", (body.email,)
    ).fetchone()
    if existing:
        conn.close()
        raise HTTPException(status_code=400, detail="Email already registered")

    conn.execute(
        "INSERT INTO users (username, email, hashed_password) VALUES (?, ?, ?)",
        (body.username, body.email, hash_password(body.password)),
    )
    conn.commit()
    conn.close()

    return {"message": "Account created successfully"}


@app.post("/login", response_model=TokenSchema)
def login(body: LoginSchema):
    """Authenticate a user and return a JWT access token."""
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE email = ?", (body.email,)
    ).fetchone()
    conn.close()

    if not user or not verify_password(body.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token({"sub": user["email"]})
    return {"access_token": token, "token_type": "bearer"}


    # --- User Routes ---

@app.get("/me")
def me(current_user: dict = Depends(get_current_user)):
    """Return the currently authenticated user's details."""
    return {
"id": current_user["id"],
"username": current_user["username"],
"email": current_user["email"],
}


@app.put("/me/update")
def update_profile(
    body: UpdateProfileSchema,
    current_user: dict = Depends(get_current_user)
):
    """Update the username of the currently authenticated user."""
    conn = get_db()
    conn.execute(
        "UPDATE users SET username = ? WHERE id = ?",
        (body.username, current_user["id"]),
    )
    conn.commit()
    conn.close()
    return {"message": "Profile updated successfully"}


@app.put("/me/change-password")
def change_password(
    body: ChangePasswordSchema,
    current_user: dict = Depends(get_current_user)
):
    """
    Change the password for the authenticated user.
    Verifies the current password before applying the new one.
    """
    if not verify_password(body.current_password, current_user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    conn = get_db()
    conn.execute(
        "UPDATE users SET hashed_password = ? WHERE id = ?",
        (hash_password(body.new_password), current_user["id"]),
    )
    conn.commit()
    conn.close()
    return {"message": "Password changed successfully"}


    # --- Admin Routes ---

@app.get("/admin/users")
def list_users(current_user: dict = Depends(get_current_user)):
    """Return a list of all registered users. Requires authentication."""
    conn = get_db()
    users = conn.execute(
        "SELECT id, username, email FROM users"
    ).fetchall()
    conn.close()
    return [dict(u) for u in users]


@app.delete("/admin/users/{user_id}")
def delete_user(
    user_id: int,
    current_user: dict = Depends(get_current_user)
):
    """
    Delete a user by ID.
    Prevents a user from deleting their own account.
    """
    if current_user["id"] == user_id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")

    conn = get_db()
    user = conn.execute(
        "SELECT id FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return {"message": "User deleted successfully"}