# Cloud IDS Monitoring Dashboard

A real-time, zero-dependency Cloud Intrusion Detection System (IDS) monitoring dashboard. Features a glassmorphism UI, live simulated threat data, and an integrated Python Flask backend for advanced deployments.

![Dashboard Screenshot Placeholder](docs/screenshot-placeholder.png)

## 🚀 Live Demo
[View the Live Dashboard here](YOUR_LIVE_URL_HERE)

## ✨ Features
- **Zero Configuration Frontend:** Single HTML file with embedded CSS/JS. No build tools required for the static version.
- **Glassmorphism Design:** Modern dark theme with neon cyan accents, backdrop blurs, and a responsive grid layout.
- **Real-Time Threat Feed:** Animated, auto-updating alerts feed categorized by severity levels (Critical, Warning, Info).
- **Live Analytics:** Dynamic stat counters, geographic threat sources, and attack type distribution charts.
- **Data Export:** One-click JSON report generation.
- **Smart Fallback System:** Fetches from a live Python Flask backend API, but gracefully falls back to local data simulation if the backend is unavailable (perfect for static deployments).

## 🛠️ Local Setup

You can run this project in two modes:

### Mode 1: Frontend Only (Static / Simulation Mode)
Simply open `index.html` in any modern web browser. The app will automatically generate and display simulated threat data entirely on the client side.

### Mode 2: With Python Backend (Live API Mode)
1. Ensure you have Python 3 installed on your machine.
2. Install the required dependencies:
   ```bash
   pip install flask flask-cors
   ```
3. Start the Flask server:
   ```bash
   python backend.py
   ```
4. Open `index.html` in your browser. The dashboard will now automatically fetch real-time simulated data from `http://localhost:5000`.

## 🌐 Deployment Note
When deploying the `index.html` file to static hosting providers (like Netlify, Vercel, or GitHub Pages), the dashboard will automatically run in **Simulation Mode** because the Python backend is not hosted on those platforms. 

If you wish to use the backend in production, you will need to host `backend.py` on a service like Render or Heroku, and update the `fetch()` URLs in `index.html` to point to your new live backend URL.

## 👨‍💻 Author
[Your Name / Handle]
