from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import mysql.connector
import bcrypt

# FastAPI App
app = FastAPI()

# Database Connection Function
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

class AttackLog(BaseModel):
    threat_id: int
    attacker_ip: str
    target_ip: str
    attack_type: str
  

class Report(BaseModel):
    user_id: int
    summary: str
    threat_count: int
    

class ThreatFeed(BaseModel):
    source_name: str
    source_url: str
    

# Register User
@app.post("/register")
async def register(user: User):
    try:
        db = get_db()
        cursor = db.cursor()

        # Hash Password
        hashed_pw = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt()).decode()

        # Insert User
        query = "INSERT INTO users (name, email, password, role, organization) VALUES (%s, %s, %s, %s, %s)"
        values = (user.name, user.email, hashed_pw, user.role, user.organization)
        cursor.execute(query, values)
        db.commit()

        return {"message": "User registered successfully"}
    
    except mysql.connector.Error as err:
        db.rollback()
        print(f"Database Error: {err}")
        raise HTTPException(status_code=500, detail=f"Database error: {err}")
    
    finally:
        db.close()

# Get All Users
@app.get("/users")
async def get_users():
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT user_id, name, email, role, organization FROM users")  # Exclude password for security
        users = cursor.fetchall()
        return users

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        raise HTTPException(status_code=500, detail=f"Database error: {err}")

    finally:
        db.close()

# User Login
@app.post("/login")
async def login(email: str, password: str):
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)

        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode(), user["password"].encode()):
            return {"message": "Login successful", "user": user}

        raise HTTPException(status_code=401, detail="Invalid credentials")

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        raise HTTPException(status_code=500, detail=f"Database error: {err}")
    
    finally:
        db.close()

# Add a Threat
@app.post("/threats")
async def add_threat(threat: Threat):
    try:
        db = get_db()
        cursor = db.cursor()

        # Check if the reported_by user exists
        cursor.execute("SELECT user_id FROM users WHERE user_id = %s", (threat.reported_by,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=400, detail="Invalid reported_by user ID")

        # Insert Threat
        query = "INSERT INTO threats (threat_type, description, severity, source, reported_by) VALUES (%s, %s, %s, %s, %s)"
        values = (threat.threat_type, threat.description, threat.severity, threat.source, threat.reported_by)
        cursor.execute(query, values)
        db.commit()

        return {"message": "Threat added successfully"}

    except mysql.connector.Error as err:
        db.rollback()
        print(f"Database Error: {err}")
        raise HTTPException(status_code=500, detail=f"Database error: {err}")

    finally:
        db.close()

# Get All Threats
@app.get("/threats")
async def get_threats():
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM threats")
        threats = cursor.fetchall()
        return threats

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        raise HTTPException(status_code=500, detail=f"Database error: {err}")

    finally:
        db.close()

#Get Attack Logs
@app.get("/attack_logs")
async def get_attack_logs():
    try:
        with get_db() as db:
            cursor = db.cursor(dictionary=True)
            
            cursor.execute("SELECT * FROM attack_logs ORDER BY timestamp DESC")
            logs = cursor.fetchall()
            cursor.close()
            
            return logs
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
# Add Attack Logs
@app.post("/attack_logs")
async def add_attack_log(log: AttackLog):
    try:
        with get_db() as db:
            cursor = db.cursor()
            
            query = """INSERT INTO attack_logs 
                       (threat_id, attacker_ip, target_ip, attack_type) 
                       VALUES (%s, %s, %s, %s)"""
            values = (log.threat_id, log.attacker_ip, log.target_ip, log.attack_type)
            
            cursor.execute(query, values)
            db.commit()
            cursor.close()
            
            return {"message": "Attack log added successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

#Get Attack Logs
@app.get("/attack_logs/{log_id}")
async def get_attack_log(log_id: int):
    try:
        with get_db() as db:
            cursor = db.cursor(dictionary=True)
            
            cursor.execute("SELECT * FROM attack_logs WHERE log_id = %s", (log_id,))
            log = cursor.fetchone()
            cursor.close()
            
            if not log:
                raise HTTPException(status_code=404, detail="Attack log not found")
            
            return log
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
