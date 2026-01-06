#!/usr/bin/env python
"""
BidVerse Application Startup Script
This script helps you start both the backend Django server and serve the frontend.
"""

import os
import sys
import subprocess
import threading
import time
import webbrowser

def start_backend():
    """Start the Django backend server"""
    print("Starting Django backend server...")
    os.chdir('backend')
    try:
        # Start Django server
        process = subprocess.Popen([
            sys.executable, 'manage.py', 'runserver', '127.0.0.1:8000'
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Wait a bit for server to start
        time.sleep(3)

        # Check if server is running
        if process.poll() is None:
            print("✓ Backend server started successfully on http://127.0.0.1:8000")
            return process
        else:
            stdout, stderr = process.communicate()
            print("✗ Failed to start backend server:")
            print("STDOUT:", stdout.decode())
            print("STDERR:", stderr.decode())
            return None

    except Exception as e:
        print(f"✗ Error starting backend: {e}")
        return None

def start_frontend():
    """Start a simple HTTP server for the frontend"""
    print("Starting frontend server...")
    try:
        # Start simple HTTP server
        process = subprocess.Popen([
            sys.executable, '-m', 'http.server', '3000'
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd='.')

        # Wait a bit for server to start
        time.sleep(2)

        if process.poll() is None:
            print("✓ Frontend server started successfully on http://127.0.0.1:3000")
            return process
        else:
            stdout, stderr = process.communicate()
            print("✗ Failed to start frontend server:")
            print("STDOUT:", stdout.decode())
            print("STDERR:", stderr.decode())
            return None

    except Exception as e:
        print(f"✗ Error starting frontend: {e}")
        return None

def main():
    print("🚀 Starting BidVerse Application...")
    print("=" * 50)

    # Ensure we're in the right directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    # Start backend
    backend_process = start_backend()
    if not backend_process:
        print("Cannot continue without backend server.")
        return

    # Start frontend
    frontend_process = start_frontend()

    print("\n" + "=" * 50)
    print("🎉 BidVerse is now running!")
    print("📱 Frontend: http://127.0.0.1:3000")
    print("🔧 Backend API: http://127.0.0.1:8000")
    print("👤 Admin Login: admin@example.com / admin123")
    print("=" * 50)
    print("Press Ctrl+C to stop all servers...")

    try:
        # Open browser
        webbrowser.open('http://127.0.0.1:3000/login.html')

        # Keep running
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n🛑 Shutting down servers...")

        # Terminate processes
        if backend_process:
            backend_process.terminate()
            backend_process.wait()
        if frontend_process:
            frontend_process.terminate()
            frontend_process.wait()

        print("✅ All servers stopped. Goodbye!")

if __name__ == '__main__':
    main()
