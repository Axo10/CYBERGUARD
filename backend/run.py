"""
CYBERGUARD Backend Server Runner
"""
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("=" * 65)
    print("  CYBERGUARD: AI-Powered Cyber Threat & Impersonation Defence")
    print(f"  Backend REST API listening on http://127.0.0.1:{port}")
    print("=" * 65)
    app.run(host="127.0.0.1", port=port, debug=False)
