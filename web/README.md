# SOS Web App

A lightweight web client matching the APK/backend SOS flow.

## Run

1. Start API:
   ```bash
   uvicorn app.main:app --reload
   ```
2. Open:
   - `http://127.0.0.1:8000/web`

## Features

- Register (`/auth/register`)
- Login (`/auth/login`)
- Detect browser location
- Trigger SOS (`/sos/create`)
- View personal alerts (`/sos/my-alerts`)
- View all alerts (`/admin/all-alerts`)
- AI location analysis (`/admin/analyze-location`)

## APK signals used

From `sos_app_1.0.0_APKPure.apk` string analysis:

- App labels/screens: `SOS LOGIN`, `RegisterScreen`, `SOSDashboard`
- API endpoints:
  - `https://sos-backend-q0h6.onrender.com/auth/login`
  - `https://sos-backend-q0h6.onrender.com/sos/my-alerts`
- Emergency message pattern with Google Maps search URL
