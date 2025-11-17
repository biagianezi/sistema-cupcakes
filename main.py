import uvicorn
import sqlite3
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
import hashlib
import os
from jose import JWTError, jwt
from datetime import datetime, timedelta

DATABASE_URL = "./cupcakes.db"

SECRET_KEY = "SUA_CHAVE_SECRETA_MUITO_FORTE"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class CupcakeSchema(BaseModel):
    id: int
    name: str
    price: float
    stock: int
    image_url: str

class UserCreate(BaseModel):
    email: str
    password: str
    nome: str
    endereco: str

class UserSchema(BaseModel):
    id: int
    email: str
    nome: str
    endereco: str
    is_admin: bool

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class CartItem(BaseModel):
    cupcake_id: int
    quantity: int

class OrderCreate(BaseModel):
    items: List[CartItem]

class OrderItemSchema(BaseModel):
    cupcake: CupcakeSchema
    quantity: int
    price_at_purchase: float

class OrderSchema(BaseModel):
    id: int
    total: float
    status: str
    created_at: datetime
    items: List[OrderItemSchema]
    owner: UserSchema


def get_db():
    db = sqlite3.connect(DATABASE_URL, check_same_thread=False)
    db.row_factory = sqlite3.Row
    try:
        db.execute("PRAGMA foreign_keys = ON;")
        yield db
    finally:
        db.close()

def init_db(db: sqlite3.Connection):
    cursor = db.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        hashed_password TEXT NOT NULL,
        nome TEXT,
        endereco TEXT,
        is_admin BOOLEAN DEFAULT 0
    );
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cupcakes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        price REAL,
        stock INTEGER,
        image_url TEXT
    );
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER NOT NULL,
        total REAL,
        status TEXT DEFAULT 'Pago',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (owner_id) REFERENCES users (id)
    );
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        cupcake_id INTEGER NOT NULL,
        quantity INTEGER,
        price_at_purchase REAL,
        FOREIGN KEY (order_id) REFERENCES orders (id),
        FOREIGN KEY (cupcake_id) REFERENCES cupcakes (id)
    );
    """)
    db.commit()

def verify_password(plain_password, hashed_password):
    try:
        salt_hex, hash_hex = hashed_password.split(':')
        salt = bytes.fromhex(salt_hex)
        
        new_hash = hashlib.pbkdf2_hmac(
            'sha256',
            plain_password.encode('utf-8'),
            salt,
            100000
        ).hex()
        
        return new_hash == hash_hex
    except (ValueError, TypeError):
        return False

def get_password_hash(password):
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return salt.hex() + ':' + pwd_hash.hex()

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(db: sqlite3.Connection = Depends(get_db), token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não foi possível validar as credenciais",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    
    user = db.execute("SELECT * FROM users WHERE email = ?", (token_data.email,)).fetchone()
    if user is None:
        raise credentials_exception
    return user

async def get_current_admin_user(current_user: sqlite3.Row = Depends(get_current_user)):
    if not current_user['is_admin']:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado: Requer privilégios de administrador",
        )
    return current_user

def _get_order_details(db: sqlite3.Connection, order_id: int) -> OrderSchema:
    order_row = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if not order_row:
        return None

    owner_row = db.execute("SELECT * FROM users WHERE id = ?", (order_row['owner_id'],)).fetchone()
    
    items_rows = db.execute("SELECT * FROM order_items WHERE order_id = ?", (order_id,)).fetchall()
    
    cupcake_ids = [item['cupcake_id'] for item in items_rows]
    if not cupcake_ids:
        cupcakes_map = {}
    else:
        placeholders = ",".join("?" * len(cupcake_ids))
        cupcakes_rows = db.execute(f"SELECT * FROM cupcakes WHERE id IN ({placeholders})", cupcake_ids).fetchall()
        cupcakes_map = {row['id']: CupcakeSchema(**row) for row in cupcakes_rows}

    order_items_schemas = []
    for item in items_rows:
        cupcake_schema = cupcakes_map.get(item['cupcake_id'])
        if cupcake_schema:
            order_items_schemas.append(OrderItemSchema(
                cupcake=cupcake_schema,
                quantity=item['quantity'],
                price_at_purchase=item['price_at_purchase']
            ))

    return OrderSchema(
        id=order_row['id'],
        total=order_row['total'],
        status=order_row['status'],
        created_at=order_row['created_at'],
        items=order_items_schemas,
        owner=UserSchema(**owner_row)
    )

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    db = sqlite3.connect(DATABASE_URL, check_same_thread=False)
    db.row_factory = sqlite3.Row
    try:
        init_db(db)
        
        cursor = db.cursor()
        cursor.execute("SELECT * FROM cupcakes LIMIT 1")
        cupcake = cursor.fetchone()
        if not cupcake:
            cursor.executemany(
                "INSERT INTO cupcakes (name, price, stock, image_url) VALUES (?, ?, ?, ?)",
                [
                    ("Cupcake de Morango", 10.0, 50, "https://placehold.co/400x300/f871b1/ffffff?text=Cupcake"),
                    ("Cupcake de Chocolate", 12.0, 30, "https://placehold.co/400x300/a78bfa/ffffff?text=Cupcake"),
                    ("Cupcake de Baunilha", 9.0, 40, "https://placehold.co/400x300/facc15/ffffff?text=Cupcake")
                ]
            )
        
        cursor.execute("SELECT * FROM users WHERE is_admin = 1 LIMIT 1")
        admin = cursor.fetchone()
        if not admin:
            admin_pass_hashed = get_password_hash("adminpass")
            cursor.execute(
                "INSERT INTO users (email, hashed_password, nome, endereco, is_admin) VALUES (?, ?, ?, ?, ?)",
                ("admin@email.com", admin_pass_hashed, "Admin", "Loja", True)
            )
        
        db.commit()
    finally:
        db.close()

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: sqlite3.Connection = Depends(get_db)):
    email = form_data.username
    password = form_data.password

    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    
    if not user or not verify_password(password, user['hashed_password']):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou senha incorretos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user['email']}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/users/register", response_model=UserSchema)
def create_user(user: UserCreate, db: sqlite3.Connection = Depends(get_db)):
    existing_user = db.execute("SELECT id FROM users WHERE email = ?", (user.email,)).fetchone()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email já registrado")
    
    hashed_password = get_password_hash(user.password)
    
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO users (email, hashed_password, nome, endereco, is_admin) VALUES (?, ?, ?, ?, ?)",
        (user.email, hashed_password, user.nome, user.endereco, False)
    )
    new_user_id = cursor.lastrowid
    db.commit()
    
    new_user_row = db.execute("SELECT * FROM users WHERE id = ?", (new_user_id,)).fetchone()
    return UserSchema(**new_user_row)

@app.get("/cupcakes", response_model=List[CupcakeSchema])
def get_cupcakes(db: sqlite3.Connection = Depends(get_db)):
    rows = db.execute("SELECT * FROM cupcakes WHERE stock > 0").fetchall()
    return [CupcakeSchema(**row) for row in rows]

@app.post("/orders", response_model=OrderSchema)
def create_order(order: OrderCreate, db: sqlite3.Connection = Depends(get_db), current_user: sqlite3.Row = Depends(get_current_user)):
    if current_user['is_admin']:
        raise HTTPException(status_code=403, detail="Administradores não podem criar pedidos")

    cursor = db.cursor()
    total = 0
    items_to_create = []
    
    try:
        for item in order.items:
            cupcake_row = cursor.execute("SELECT * FROM cupcakes WHERE id = ?", (item.cupcake_id,)).fetchone()
            if not cupcake_row:
                raise HTTPException(status_code=404, detail=f"Cupcake com id {item.cupcake_id} não encontrado")
            
            cupcake = CupcakeSchema(**cupcake_row)
            if cupcake.stock < item.quantity:
                raise HTTPException(status_code=400, detail=f"Estoque insuficiente para {cupcake.name}")
            
            total += cupcake.price * item.quantity
            
            cursor.execute("UPDATE cupcakes SET stock = stock - ? WHERE id = ?", (item.quantity, cupcake.id))
            
            items_to_create.append((
                item.cupcake_id,
                item.quantity,
                cupcake.price
            ))

        cursor.execute(
            "INSERT INTO orders (owner_id, total, status) VALUES (?, ?, ?)",
            (current_user['id'], total, "Pago")
        )
        order_id = cursor.lastrowid
        
        items_with_order_id = [(order_id,) + item_data for item_data in items_to_create]
        cursor.executemany(
            "INSERT INTO order_items (order_id, cupcake_id, quantity, price_at_purchase) VALUES (?, ?, ?, ?)",
            items_with_order_id
        )
        
        db.commit()
        
        return _get_order_details(db, order_id)

    except sqlite3.Error as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Erro no banco de dados: {e}")
    except HTTPException as e:
        db.rollback()
        raise e

@app.get("/admin/orders", response_model=List[OrderSchema])
def get_all_orders(db: sqlite3.Connection = Depends(get_db), admin: sqlite3.Row = Depends(get_current_admin_user)):
    order_rows = db.execute("SELECT * FROM orders").fetchall()
    return [_get_order_details(db, row['id']) for row in order_rows]

@app.get("/admin/cupcakes", response_model=List[CupcakeSchema])
def get_all_cupcakes(db: sqlite3.Connection = Depends(get_db), admin: sqlite3.Row = Depends(get_current_admin_user)):
    rows = db.execute("SELECT * FROM cupcakes").fetchall()
    return [CupcakeSchema(**row) for row in rows]

@app.put("/admin/cupcakes/{cupcake_id}/stock", response_model=CupcakeSchema)
def update_stock(cupcake_id: int, new_stock: int, db: sqlite3.Connection = Depends(get_db), admin: sqlite3.Row = Depends(get_current_admin_user)):
    cursor = db.cursor()
    cursor.execute("UPDATE cupcakes SET stock = ? WHERE id = ?", (new_stock, cupcake_id))
    db.commit()
    
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Cupcake não encontrado")
        
    updated_cupcake_row = db.execute("SELECT * FROM cupcakes WHERE id = ?", (cupcake_id,)).fetchone()
    return CupcakeSchema(**updated_cupcake_row)

@app.put("/admin/orders/{order_id}/status", response_model=OrderSchema)
def update_order_status(order_id: int, new_status: str, db: sqlite3.Connection = Depends(get_db), admin: sqlite3.Row = Depends(get_current_admin_user)):
    cursor = db.cursor()
    cursor.execute("UPDATE orders SET status = ? WHERE id = ?", (new_status, order_id))
    db.commit()
    
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Pedido não encontrado")
    
    return _get_order_details(db, order_id)

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
