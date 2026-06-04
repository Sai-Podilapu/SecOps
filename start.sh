#!/bin/bash
echo "Starting AWS SecOps Platform..."
echo ""

# Backend
cd backend
pip install -r requirements.txt --quiet
python app.py &
BACKEND_PID=$!
echo "✓ Backend started on http://localhost:5000 (PID: $BACKEND_PID)"

# Frontend
cd ../frontend
npm install --legacy-peer-deps
npm start &
FRONTEND_PID=$!
echo "✓ Frontend starting on http://localhost:3000 (PID: $FRONTEND_PID)"

echo ""
echo "Open http://localhost:3000 in your browser"
echo "Press Ctrl+C to stop both servers"

trap "kill $BACKEND_PID $FRONTEND_PID" EXIT
wait
