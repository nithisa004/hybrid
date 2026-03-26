@echo off
echo 🚀 Starting Hybrid SIEM Setup...

echo 📦 Installing Python Dependencies...
pip install -r requirements.txt

echo 🎨 Installing Frontend Dependencies...
cd frontend
npm install

echo ✅ Setup Complete! 
echo.
echo Use the following commands to run the project:
echo 1. Backend: cd backend && python manage.py runserver
echo 2. Frontend: cd frontend && ionic serve
echo 3. Sensor: cd detection && python realtime_detection.py (as Admin)
pause
