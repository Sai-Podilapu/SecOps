@echo off
echo Starting AWS SecOps Platform...

cd backend
start /B python app.py
echo Backend started on http://localhost:5000

cd ..\frontend
call npm install --legacy-peer-deps
start /B npm start
echo Frontend starting on http://localhost:3000

echo Open http://localhost:3000 in your browser
pause
