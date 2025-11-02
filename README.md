# Secure-FinTech - Streamlit App
## Files
- `app.py` - main Streamlit application
- `schema_init.sql` - database schema
- `requirements.txt` - Python dependencies
- `.gitignore` - recommended (ignore data/ and .venv/)

## Quick notes (for Streamlit Cloud deployment)
1. Deploy this repo to Streamlit Cloud (streamlit.io). Streamlit Cloud will install packages from `requirements.txt`.
2. On first run the app needs a DB and a Fernet key. Run the following once locally (or use the Streamlit app page to run it with a small tweak):
