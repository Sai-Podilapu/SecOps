#!/bin/bash
echo "=== AWS Security Platform — All 5 Phases ==="
echo ""

# Backend
cd backend
pip install -r requirements.txt -q
python app.py &
BACKEND_PID=$!
echo "✓ Backend started (PID: $BACKEND_PID) on http://localhost:5015"

# Frontend
cd ../frontend
npm install -q
npm start &
FRONTEND_PID=$!
echo "✓ Frontend started (PID: $FRONTEND_PID) on http://localhost:3015"

echo ""
echo "Open http://localhost:3015 in your browser"
echo "Press Ctrl+C to stop both servers"

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" INT TERM
wait
