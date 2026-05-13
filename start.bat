@echo off
echo === AWS Security Platform - All 5 Phases ===
start "Backend" cmd /k "cd backend && pip install -r requirements.txt && python app.py"
timeout /t 3 >nul
start "Frontend" cmd /k "cd frontend && npm install && npm start"
echo Open http://localhost:3015 in your browser
