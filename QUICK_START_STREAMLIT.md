# Quick Start: Streamlit App

## Local Testing

1. **Install Streamlit**:
   ```bash
   pip install streamlit
   ```

2. **Set up secrets** (for local testing):
   ```bash
   cp .streamlit/secrets.toml.example .streamlit/secrets.toml
   # Edit .streamlit/secrets.toml and add your API keys
   ```

3. **Run the app**:
   ```bash
   streamlit run streamlit_app.py
   ```

4. **Access the app**: Open http://localhost:8501 in your browser

## Streamlit Cloud Deployment

1. **Push to GitHub**:
   ```bash
   git add .
   git commit -m "Add Streamlit app"
   git push
   ```

2. **Deploy on Streamlit Cloud**:
   - Go to https://share.streamlit.io
   - Click "New app"
   - Connect GitHub repo
   - Set main file: `streamlit_app.py`
   - Set requirements: `streamlit_requirements.txt`
   - Add secrets in dashboard (Settings → Secrets)

3. **Your app will be live!**

## Features

- 📤 **File Upload**: Upload files for security scanning
- 🔍 **Vulnerability Scanner**: View scan results
- 🚨 **Incident Response**: Generate automated remediation plans
- 📊 **Threat Intelligence**: Check IOCs
- 📋 **Dashboard**: View all alerts and incidents

## File Types Supported

- Log files: `.log`, `.txt`
- Code files: `.py`
- Config files: `.json`, `.yaml`, `.yml`, `.xml`, `.html`, `.conf`

## API Keys Required

- **Anthropic API Key**: Required for LLM features (incident response)
- **VirusTotal API Key**: Optional (for threat intelligence)
- **NVD API Key**: Optional (for CVE lookups)

