# Streamlit Cloud Deployment Guide

This guide explains how to deploy the Cyber Security AI Agent System to Streamlit Cloud.

## Prerequisites

1. GitHub account
2. Streamlit Cloud account (free at https://share.streamlit.io)
3. API Keys:
   - Anthropic API key (required for LLM features)
   - VirusTotal API key (optional)
   - NVD API key (optional)

## Deployment Steps

### 1. Push Code to GitHub

```bash
# Initialize git if not already done
git init
git add .
git commit -m "Initial commit with Streamlit app"
git branch -M main
git remote add origin <your-github-repo-url>
git push -u origin main
```

### 2. Deploy to Streamlit Cloud

1. Go to https://share.streamlit.io
2. Click "New app"
3. Connect your GitHub account
4. Select your repository
5. Set the following:
   - **Main file path**: `streamlit_app.py`
   - **Python version**: 3.11
   - **Requirements file**: `streamlit_requirements.txt` (or `requirements-streamlit.txt`)

### 3. Configure Secrets

In Streamlit Cloud dashboard, go to "Settings" → "Secrets" and add:

```toml
ANTHROPIC_API_KEY = "your_anthropic_api_key_here"
VIRUSTOTAL_API_KEY = "your_virustotal_api_key_here"
NVD_API_KEY = "your_nvd_api_key_here"
```

### 4. Deploy

Click "Deploy" and wait for the app to build and launch.

## Features

The Streamlit app provides:

1. **File Upload & Scan**: Upload files for security analysis
   - Log files (.log, .txt)
   - Python code (.py)
   - Configuration files (.json, .yaml, .xml, etc.)
   - Automatic threat detection
   - Auto-incident response generation

2. **Vulnerability Scanner**: View scan results from uploaded files

3. **Incident Response**: 
   - Manual incident creation
   - Automated remediation plan generation
   - Step-by-step action items

4. **Threat Intelligence**: Check IOCs (IPs, URLs, hashes, domains)

5. **Alerts & Incidents Dashboard**: View all security alerts and incidents

## Local Testing

Before deploying, test locally:

```bash
# Install streamlit
pip install streamlit

# Create secrets file (for local testing only)
cp .streamlit/secrets.toml.example .streamlit/secrets.toml
# Edit .streamlit/secrets.toml and add your API keys

# Run locally
streamlit run streamlit_app.py
```

## Limitations

- **Binary Tools**: Trivy and OWASP ZAP won't work on Streamlit Cloud (they require binaries)
- **File Size**: Large files may hit memory limits
- **Processing Time**: Complex scans may timeout (Streamlit Cloud has timeout limits)
- **Storage**: No persistent storage between sessions (use session state)

## Troubleshooting

### App won't start
- Check that `streamlit_app.py` is in the root directory
- Verify `streamlit_requirements.txt` includes all dependencies
- Check build logs in Streamlit Cloud dashboard

### API Key errors
- Ensure secrets are set in Streamlit Cloud dashboard
- Check that secret names match exactly (case-sensitive)

### Import errors
- Verify all Python files are in correct directories
- Check that requirements are properly specified

### Memory errors
- Streamlit Cloud has memory limits
- Consider chunking large file uploads
- Optimize agent initialization

## Updating the App

1. Make changes to your code
2. Commit and push to GitHub
3. Streamlit Cloud will automatically redeploy

## Support

For issues:
- Check Streamlit Cloud logs
- Review GitHub repository
- Check API key configuration

