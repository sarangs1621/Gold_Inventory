
# Project Setup & Run Instructions

This project consists of two parts:

- Backend – Python (FastAPI)
- Frontend – React (Node.js)

Follow the steps below to run the project locally.

---

## Prerequisites

Ensure the following are installed on your system:

- Python 3.9+
- Node.js (v16+)
- npm
- Git (optional)

---

## Backend Setup (FastAPI)

### Step 1: Navigate to Backend Directory
```
cd backend
```

### Step 2: Create Virtual Environment
```
python -m venv venv
```

### Step 3: Activate Virtual Environment

**Windows**
```
.\venv\Scripts\activate
```

**Linux / macOS**
```
source venv/bin/activate
```

### Step 4: Install Dependencies
```
pip install -r requirements.txt
```

If any packages are missing, install them manually:
```
pip install motor bleach fastapi slowapi python-dotenv uvicorn passlib httpx
pip install bcrypt==4.2.0
pip install PyJWT==2.10.1
```

### Step 5: Initialize Database
```
python init_db.py
```

### Step 6: Run Backend Server
```
uvicorn server:app --host 0.0.0.0 --port 8001 --reload
```

Backend will run at:
http://localhost:8001

---

## Frontend Setup (React)

### Step 1: Navigate to Frontend Directory
```
cd frontend
```

### Step 2: Install Dependencies
```
npm install
npm install jspdf jspdf-autotable

```

### Step 3: Start Frontend Server
```
npm start
```

Frontend will run at:
http://localhost:3000

---

## Running Summary

| Service   | URL |
|----------|-----|
| Backend  | http://localhost:8001 |
| Frontend | http://localhost:3000 |

---

## Notes

- Start backend before frontend
- Keep virtual environment activated
- Update .env files if required
- Stop servers using Ctrl + C

---

Happy Coding 🚀
