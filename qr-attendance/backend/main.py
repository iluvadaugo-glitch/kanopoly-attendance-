from fastapi.responses import FileResponse
from fastapi import FastAPI, Depends, HTTPException, File, UploadFile
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlalchemy import create_engine, text
from jose import jwt, JWTError
from datetime import datetime, timedelta
import hashlib
import secrets

import os

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg2://postgres:postgress1234@localhost:5432/qr_attendance")

# Fix Railway's postgres:// URL for SQLAlchemy
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
SECRET = "change-this-secret"
engine = create_engine(DATABASE_URL)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app = FastAPI()

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return f"{salt}${digest.hex()}"

def verify_password(password: str, stored: str) -> bool:
    salt, digest = stored.split("$", 1)
    check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return secrets.compare_digest(check.hex(), digest)

def make_token(user_id, role):
    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=12),
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")

def current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        return {"id": int(payload["sub"]), "role": payload["role"]}
    except JWTError:
        raise HTTPException(401, "invalid or expired token")

# -------------------- Pages --------------------
@app.get("/teacher")
def teacher_page():
    return FileResponse("frontend/teacher.html")

@app.get("/student")
def student_page():
    return FileResponse("frontend/student.html")

@app.get("/student-dashboard")
def student_dash_page():
    return FileResponse("frontend/student-dashboard.html")

@app.get("/")
def home_page():
    return FileResponse("frontend/index.html")

@app.get("/register")
def register_page():
    return FileResponse("frontend/register.html")

@app.get("/teacher-dashboard")
def teacher_dash_page():
    return FileResponse("frontend/teacher-dashboard.html")

@app.get("/admin")
def admin_page():
    return FileResponse("frontend/admin.html")


# -------------------- Auth --------------------
@app.post("/register")
def register(name: str, reg_no: str, password: str, role: str = "student"):
    if role not in ("student", "teacher", "admin"):
        raise HTTPException(400, "invalid role")
    password_hash = hash_password(password)
    with engine.begin() as conn:
        # Check if reg_no already exists (for students)
        if role == "student":
            exists = conn.execute(text("SELECT id FROM users WHERE reg_no = :reg"), {"reg": reg_no}).first()
            if exists:
                raise HTTPException(400, "registration number already exists")
            row = conn.execute(
                text("""
                    INSERT INTO users (name, reg_no, password_hash, role)
                    VALUES (:name, :reg_no, :password_hash, 'student')
                    RETURNING id, name, reg_no, role
                """),
                {"name": name, "reg_no": reg_no, "password_hash": password_hash},
            ).mappings().one()
        else:
            # Teachers/Admins still use email
            raise HTTPException(400, "teachers and admins must be created by admin")
    return dict(row)


@app.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends()):
    with engine.begin() as conn:
        # First try registration number (for students)
        row = conn.execute(
            text("SELECT id, password_hash, role FROM users WHERE reg_no = :u"),
            {"u": form.username},
        ).mappings().first()

        # If not found, try email (only for teachers and admins)
        if not row:
            row = conn.execute(
                text("SELECT id, password_hash, role FROM users WHERE email = :u AND role IN ('teacher', 'admin')"),
                {"u": form.username},
            ).mappings().first()

        if not row or not verify_password(form.password, row["password_hash"]):
            raise HTTPException(401, "invalid credentials")

    return {
        "access_token": make_token(row["id"], row["role"]),
        "token_type": "bearer",
        "role": row["role"],
    }
    
# -------------------- Courses --------------------
@app.post("/courses")
def create_course(code: str, title: str, user=Depends(current_user)):
    if user["role"] != "teacher":
        raise HTTPException(403, "only a teacher can create a course")
    with engine.begin() as conn:
        row = conn.execute(
            text("""
                INSERT INTO courses (code, title, teacher_id)
                VALUES (:code, :title, :teacher_id)
                RETURNING id, code, title, teacher_id
            """),
            {"code": code, "title": title, "teacher_id": user["id"]},
        ).mappings().one()
    return dict(row)

@app.get("/courses")
def list_courses():
    with engine.begin() as conn:
        rows = conn.execute(
            text("SELECT id, code, title FROM courses ORDER BY title")
        ).mappings().all()
    return [dict(row) for row in rows]

@app.post("/courses/{course_id}/enroll")
def enroll(course_id: int, student_email: str, user=Depends(current_user)):
    if user["role"] != "teacher":
        raise HTTPException(403, "only a teacher can enroll a student")
    with engine.begin() as conn:
        course = conn.execute(
            text("SELECT id FROM courses WHERE id = :id AND teacher_id = :teacher_id"),
            {"id": course_id, "teacher_id": user["id"]},
        ).first()
        if not course:
            raise HTTPException(404, "course not found")
        student = conn.execute(
            text("SELECT id FROM users WHERE email = :email AND role = 'student'"),
            {"email": student_email},
        ).mappings().first()
        if not student:
            raise HTTPException(404, "student not found")
        conn.execute(
            text("""
                INSERT INTO enrollments (student_id, course_id)
                VALUES (:student_id, :course_id)
                ON CONFLICT DO NOTHING
            """),
            {"student_id": student["id"], "course_id": course_id},
        )
    return {"enrolled": student_email, "course_id": course_id}

@app.post("/courses/{course_id}/enroll-self")
def enroll_self(course_id: int, user=Depends(current_user)):
    if user["role"] != "student":
        raise HTTPException(403, "only students can enroll themselves")
    with engine.begin() as conn:
        course = conn.execute(
            text("SELECT id FROM courses WHERE id = :id"),
            {"id": course_id},
        ).first()
        if not course:
            raise HTTPException(404, "course not found")
        conn.execute(
            text("""
                INSERT INTO enrollments (student_id, course_id)
                VALUES (:student_id, :course_id)
                ON CONFLICT DO NOTHING
            """),
            {"student_id": user["id"], "course_id": course_id},
        )
    return {"enrolled": True, "course_id": course_id}

# -------------------- Sessions & QR --------------------
@app.post("/sessions")
def start_session(course_id: int, user=Depends(current_user)):
    if user["role"] != "teacher":
        raise HTTPException(403, "only a teacher can start a session")
    with engine.begin() as conn:
        course = conn.execute(
            text("SELECT id FROM courses WHERE id = :id AND teacher_id = :teacher_id"),
            {"id": course_id, "teacher_id": user["id"]},
        ).first()
        if not course:
            raise HTTPException(404, "course not found")
        row = conn.execute(
            text("""
                INSERT INTO sessions (course_id, teacher_id, status)
                VALUES (:course_id, :teacher_id, 'open')
                RETURNING id, course_id, status, started_at
            """),
            {"course_id": course_id, "teacher_id": user["id"]},
        ).mappings().one()
    return dict(row)

@app.get("/sessions/{session_id}/qr")
def session_qr(session_id: int, user=Depends(current_user)):
    if user["role"] != "teacher":
        raise HTTPException(403, "only a teacher can display the QR")
    with engine.begin() as conn:
        session = conn.execute(
            text("""
                SELECT id FROM sessions
                WHERE id = :id AND teacher_id = :teacher_id AND status = 'open'
            """),
            {"id": session_id, "teacher_id": user["id"]},
        ).first()
    if not session:
        raise HTTPException(404, "open session not found")
    expires = datetime.utcnow() + timedelta(seconds=600)
    qr_token = jwt.encode(
        {"session_id": session_id, "exp": expires},
        SECRET,
        algorithm="HS256",
    )
    return {"qr_token": qr_token, "expires_in_seconds": 600}

@app.post("/scan")
def scan(qr_token: str, user=Depends(current_user)):
    if user["role"] != "student":
        raise HTTPException(403, "only a student can scan")
    try:
        payload = jwt.decode(qr_token, SECRET, algorithms=["HS256"])
        session_id = int(payload["session_id"])
    except JWTError:
        raise HTTPException(400, "QR expired or invalid")

    with engine.begin() as conn:
        session = conn.execute(
            text("SELECT course_id FROM sessions WHERE id = :id AND status = 'open'"),
            {"id": session_id},
        ).mappings().first()
        if not session:
            raise HTTPException(400, "session is closed")

        # Get the name the teacher uploaded for this student
        teacher_name_row = conn.execute(
            text("""
                SELECT u.name 
                FROM enrollments e
                JOIN users u ON u.id = e.student_id
                WHERE e.student_id = :sid AND e.course_id = :cid
            """),
            {"sid": user["id"], "cid": session["course_id"]}
        ).mappings().first()

        if not teacher_name_row:
            raise HTTPException(403, "You are not on the official list for this course")

        # Flexible name check
        def normalize(name):
            return " ".join(sorted(name.lower().strip().split()))

        student_name = conn.execute(
            text("SELECT name FROM users WHERE id = :id"),
            {"id": user["id"]}
        ).scalar()

        if normalize(student_name) != normalize(teacher_name_row["name"]):
            raise HTTPException(403, "Your name does not match the official list")

        # Check if already marked
        existing = conn.execute(
            text("""
                SELECT id FROM attendance
                WHERE session_id = :session_id AND student_id = :student_id
            """),
            {"session_id": session_id, "student_id": user["id"]},
        ).first()
        if existing:
            raise HTTPException(400, "already marked present")

        # Mark attendance
        conn.execute(
            text("""
                INSERT INTO attendance (session_id, student_id)
                VALUES (:session_id, :student_id)
            """),
            {"session_id": session_id, "student_id": user["id"]},
        )

    return {"present": True, "session_id": session_id}
    
          # -------------------- Student Dashboard --------------------

@app.get("/me/dashboard")
def student_dashboard(user=Depends(current_user)):
    if user["role"] != "student":
        raise HTTPException(403, "only students")
    with engine.begin() as conn:
        courses = conn.execute(
            text("""
                SELECT c.id, c.code, c.title
                FROM enrollments e
                JOIN courses c ON c.id = e.course_id
                WHERE e.student_id = :sid
            """),
            {"sid": user["id"]},
        ).mappings().all()

        result = []
        for c in courses:
            total = conn.execute(
                text("SELECT COUNT(*) FROM sessions WHERE course_id = :cid"),
                {"cid": c["id"]},
            ).scalar() or 0
            attended = conn.execute(
                text("""
                    SELECT COUNT(*) FROM attendance a
                    JOIN sessions s ON s.id = a.session_id
                    WHERE a.student_id = :sid AND s.course_id = :cid
                """),
                {"sid": user["id"], "cid": c["id"]},
            ).scalar() or 0
            percentage = round((attended / total * 100), 1) if total else 0
            result.append({
                "course_id": c["id"],
                "code": c["code"],
                "title": c["title"],
                "attended": attended,
                "total_sessions": total,
                "percentage": percentage
            })
    return {"courses": result}

# -------------------- Teacher Dashboard --------------------
@app.get("/teacher/students")
def teacher_students(user=Depends(current_user)):
    if user["role"] != "teacher":
        raise HTTPException(403, "only teachers")
    with engine.begin() as conn:
        rows = conn.execute(
            text("""
                SELECT u.id, u.name, u.email, c.code as course_code, c.title as course_title
                FROM enrollments e
                JOIN users u ON u.id = e.student_id
                JOIN courses c ON c.id = e.course_id
                WHERE c.teacher_id = :tid
                ORDER BY c.title, u.name
            """),
            {"tid": user["id"]},
        ).mappings().all()
    return [dict(row) for row in rows]

@app.get("/teacher/dashboard")
def teacher_dashboard(user=Depends(current_user)):
    if user["role"] != "teacher":
        raise HTTPException(403, "only teachers")
    with engine.begin() as conn:
        students = conn.execute(
            text("""
                SELECT u.id as student_id, u.name, u.email,
                       c.id as course_id, c.code, c.title
                FROM enrollments e
                JOIN users u ON u.id = e.student_id
                JOIN courses c ON c.id = e.course_id
                WHERE c.teacher_id = :tid
            """),
            {"tid": user["id"]},
        ).mappings().all()

        result = []
        for s in students:
            total = conn.execute(
                text("SELECT COUNT(*) FROM sessions WHERE course_id = :cid"),
                {"cid": s["course_id"]},
            ).scalar() or 0
            attended = conn.execute(
                text("""
                    SELECT COUNT(*) FROM attendance a
                    JOIN sessions se ON se.id = a.session_id
                    WHERE a.student_id = :sid AND se.course_id = :cid
                """),
                {"sid": s["student_id"], "cid": s["course_id"]},
            ).scalar() or 0
            percentage = round((attended / total * 100), 1) if total else 0
            result.append({
                "student_id": s["student_id"],
                "name": s["name"],
                "email": s["email"],
                "course_code": s["code"],
                "course_title": s["title"],
                "attended": attended,
                "total_sessions": total,
                "percentage": percentage
            })
    return {"students": result}

# -------------------- Import Students --------------------
import csv
import io

@app.post("/teacher/import-students")
def import_students(course_id: int, file: UploadFile = File(...), user=Depends(current_user)):
    if user["role"] != "teacher":
        raise HTTPException(403, "only teachers")
    
    content = file.file.read().decode("utf-8")
    lines = content.strip().splitlines()
    if not lines or not lines[0].lower().startswith("name"):
        raise HTTPException(400, "CSV must start with: name,reg_no")
    
    created = 0
    enrolled = 0
    skipped = 0
    
    with engine.begin() as conn:
        for line in lines[1:]:
            if not line.strip():
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 2:
                skipped += 1
                continue
            name, reg_no = parts[0], parts[1]
            
            # Check if student already exists by reg_no
            existing = conn.execute(
                text("SELECT id FROM users WHERE reg_no = :reg"),
                {"reg": reg_no}
            ).mappings().first()
            
            if existing:
                student_id = existing["id"]
            else:
                # Create new student with default password
                password_hash = hash_password("password123")
                new_user = conn.execute(
                    text("""
                        INSERT INTO users (name, reg_no, password_hash, role)
                        VALUES (:name, :reg_no, :password_hash, 'student')
                        RETURNING id
                    """),
                    {"name": name, "reg_no": reg_no, "password_hash": password_hash},
                ).mappings().one()
                student_id = new_user["id"]
                created += 1
            
            # Enroll in course
            conn.execute(
                text("""
                    INSERT INTO enrollments (student_id, course_id)
                    VALUES (:sid, :cid)
                    ON CONFLICT DO NOTHING
                """),
                {"sid": student_id, "cid": course_id},
            )
            enrolled += 1
    
    return {
        "created": created,
        "enrolled": enrolled,
        "skipped": skipped,
        "message": f"Imported {created} new students and enrolled {enrolled}"
    }
# -------------------- Current User Info --------------------
@app.get("/me")
def get_me(user=Depends(current_user)):
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT name, email, role FROM users WHERE id = :id"),
            {"id": user["id"]}
        ).mappings().first()
    return dict(row)

@app.get("/teacher/courses")
def teacher_courses(user=Depends(current_user)):
    if user["role"] != "teacher":
        raise HTTPException(403, "only teachers")
    with engine.begin() as conn:
        rows = conn.execute(
            text("""
                SELECT id, code, title 
                FROM courses 
                WHERE teacher_id = :tid 
                ORDER BY id
            """),
            {"tid": user["id"]},
        ).mappings().all()
    return [dict(row) for row in rows]
@app.get("/admin/users")
def admin_users(user=Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "admin only")
    with engine.begin() as conn:
        rows = conn.execute(
            text("SELECT id, name, email, role FROM users ORDER BY id")
        ).mappings().all()
    return [dict(row) for row in rows]

@app.post("/admin/create-teacher")
def create_teacher(name: str, email: str, password: str, user=Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "admin only")
    password_hash = hash_password(password)
    with engine.begin() as conn:
        exists = conn.execute(text("SELECT id FROM users WHERE email = :email"), {"email": email}).first()
        if exists:
            raise HTTPException(400, "email already exists")
        row = conn.execute(
            text("""
                INSERT INTO users (name, email, password_hash, role)
                VALUES (:name, :email, :password_hash, 'teacher')
                RETURNING id, name, email, role
            """),
            {"name": name, "email": email, "password_hash": password_hash},
        ).mappings().one()
    return dict(row)

@app.get("/admin/courses")
def admin_courses(user=Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "admin only")
    with engine.begin() as conn:
        rows = conn.execute(
            text("""
                SELECT c.id, c.code, c.title, u.name as teacher_name
                FROM courses c
                LEFT JOIN users u ON u.id = c.teacher_id
                ORDER BY c.id
            """)
        ).mappings().all()
    return [dict(row) for row in rows]
import smtplib
from email.mime.text import MIMEText

# Your Gmail details
SMTP_EMAIL = "funds.0002@gmail.com"
SMTP_PASSWORD = "ivvdjrdckdclvsab"   # App Password (spaces removed)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

@app.post("/admin/send-teacher-email")
def send_teacher_email(teacher_email: str, teacher_name: str, password: str, user=Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "admin only")

    subject = "Your Teacher Account - QR Attendance Portal"
    body = f"""
Hello {teacher_name},

Your teacher account has been created.

Login details:
Email: {teacher_email}
Password: {password}

Portal link: https://kanopolyattendance.site/

Please log in and change your password if needed.

Best regards,
School Admin
"""

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_EMAIL
    msg["To"] = teacher_email

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.send_message(msg)
        return {"sent": True, "message": "Email sent successfully"}
    except Exception as e:
        raise HTTPException(500, f"Failed to send email: {str(e)}")

@app.post("/change-password")
def change_password(current_password: str, new_password: str, user=Depends(current_user)):
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT password_hash FROM users WHERE id = :id"),
            {"id": user["id"]}
        ).mappings().first()
        if not row or not verify_password(current_password, row["password_hash"]):
            raise HTTPException(400, "current password is wrong")
        new_hash = hash_password(new_password)
        conn.execute(
            text("UPDATE users SET password_hash = :hash WHERE id = :id"),
            {"hash": new_hash, "id": user["id"]}
        )
    return {"message": "Password changed successfully"}
@app.get("/change-password")
def change_password_page():
    return FileResponse("frontend/change-password.html")
@app.delete("/admin/users/{user_id}")
def delete_user(user_id: int, user=Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "admin only")
    if user["id"] == user_id:
        raise HTTPException(400, "you cannot delete yourself")
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM users WHERE id = :id"), {"id": user_id})
    return {"deleted": True, "user_id": user_id}
