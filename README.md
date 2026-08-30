# HCDSF Interface with uvicorn + npm

A working dashboard that uses FastAPI/uvicorn for backend prediction logic and Vite/npm for the frontend.

## What changed
- `backend.py` now serves a REST API for prediction and CSV upload.
- `package.json` and `vite.config.js` support a modern npm/Vite frontend.
- `index.html`, `styles.css`, and `app.js` now present a cleaner, professional dashboard experience.

## Install and run
### Backend
1. Activate your Python environment if needed.
2. Install dependencies:
   ```bash
   py -3 -m pip install -r requirements.txt
   ```
3. Start the backend:
   ```bash
   py -3 -m uvicorn backend:app --reload
   ```

### Frontend
1. Install npm packages:
   ```bash
   npm install
   ```
2. Start Vite dev server:
   ```bash
   npm run dev
   ```
3. Open the URL shown by Vite in your browser.

## Usage
- Click **Load Sample Connection** to load a synthetic IIoT record.
- Upload a CSV file containing a single row of 44 numeric values.
- Click **Run Analysis** to get baseline and refined predictions, feature contributions, shortcut feature warnings, and analyst recommendations.

## Notes
- The frontend calls `http://127.0.0.1:8000/predict` by default.
- FastAPI is configured with CORS so the dashboard can consume the backend from a separate port.
- This still uses the HCDSF paper design: explainability-guided diagnostics, feature refinement, and analyst-centered decision support.
