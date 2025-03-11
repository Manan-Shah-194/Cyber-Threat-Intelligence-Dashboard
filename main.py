from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
import mysql.connector
from fastapi.middleware.cors import CORSMiddleware
import bcrypt

# FastAPI App
app = FastAPI()

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database Connection
def get_db():
    return mysql.connector.connect(
        port=3306,
        user="root",
        password="Mithil29",
        database="cyber_threat_db"
    )

# User Model
class User(BaseModel):
    name: str
    email: str
    password: str
    role: str
    organization: str

# Threat Model
class Threat(BaseModel):
    threat_type: str
    description: str
    severity: str
    source: str
    reported_by: int
#Landing page
@app.get("/")
async def s():
    print("Hello")
# Register User
@app.post("/register")
async def register(user: User):
    db = get_db()
    cursor = db.cursor()
    
    hashed_pw = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    query = "INSERT INTO users (name, email, password, role, organization) VALUES (%s, %s, %s, %s, %s)"
    values = (user.name, user.email, hashed_pw, user.role, user.organization)
    
    cursor.execute(query, values)
    db.commit()
    db.close()
    
    return {"message": "User registered successfully"}

# User Login
@app.post("/login")
async def login(email: str, password: str):
    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    
    db.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), user["password"].encode('utf-8')):
        return {"message": "Login successful", "user": user}
    
    raise HTTPException(status_code=401, detail="Invalid credentials")

# Get All Threats
@app.get("/threats")
async def get_threats():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    cursor.execute("SELECT * FROM threats ORDER BY timestamp DESC")
    threats = cursor.fetchall()
    
    db.close()
    return threats

# Add a New Threat
@app.post("/threats")
async def add_threat(threat: Threat):
    db = get_db()
    cursor = db.cursor()
    
    query = "INSERT INTO threats (threat_type, description, severity, source, reported_by) VALUES (%s, %s, %s, %s, %s)"
    values = (threat.threat_type, threat.description, threat.severity, threat.source, threat.reported_by)
    
    cursor.execute(query, values)
    db.commit()
    db.close()
    
    return {"message": "Threat added successfully"}

# Get Attack Logs
@app.get("/attack_logs")
async def get_attack_logs():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    cursor.execute("SELECT * FROM attack_logs")
    logs = cursor.fetchall()
    
    db.close()
    return logs

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
