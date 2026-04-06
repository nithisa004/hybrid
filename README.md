
To run the Hybrid SIEM project correctly, you should open three separate terminal windows and run these commands:

### 🚀 Quick Setup (First Time Only)
Run the automated setup script in your terminal:
```powershell
.\setup_project.bat
```
This will install all backend and frontend dependencies for you.

---

1. Terminal One: Backend (The ML Brain)
This terminal runs your Django API and the Machine Learning models.

powershell
cd d:\hybrid\backend
py manage.py runserver
2. Terminal Two: Frontend (The Dashboard)
This terminal runs the user interface where you see the results.

powershell
cd d:\hybrid\frontend
ionic serve
3. Terminal Three: Security Sensors (Run as Administrator)
You have two options to feed data to your SIEM from the `detection` folder:

*   **Option A: Unified Sensor (NIC + OS Logs)**
    *Best for full-spectrum monitoring.*
    ```powershell
    cd d:\hybrid\detection
    py .\realtime_detection.py
    ```
*  cd d:\hybrid\detection && python realtime_detection.py
    ```


### Bonus: Manual Attack Simulation
If you want to manually test the detection logic without waiting for real events, run this in any terminal:
```powershell
cd d:\hybrid
py simulate_attacks.py
```