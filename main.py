"""
main.py — Entry Point
======================

Launches the Web UI for the Secure Authentication System.
"""

import sys
import os

# Ensure the project root is on sys.path so relative imports work
# regardless of how the script is invoked.
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from secure_auth_system.web.app import app

def main() -> None:
    """Start the Flask Web Server."""
    print("Starting SecureAuth Web Interface...")
    app.run(host='0.0.0.0', port=5000, debug=True)

if __name__ == "__main__":
    main()

