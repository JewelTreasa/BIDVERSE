from django.apps import AppConfig
import threading
import time
import os
import sys

class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'accounts'

    def ready(self):
        # Prevent running twice with auto-reloader
        if os.environ.get('RUN_MAIN') != 'true' and 'runserver' in sys.argv:
            return
            
        # Start background thread
        def run_scheduler():
            # Initial delay to let server start
            time.sleep(10)
            from .utils import auto_end_expired_auctions
            
            while True:
                try:
                    # Run auction check logic
                    print("[Background] Checking for expired auctions...")
                    auto_end_expired_auctions()
                except Exception as e:
                    print(f"[Background] Error: {e}")
                
                # Wait for 60 seconds (or 10 mins as requested, but 60s is better for responsiveness)
                # User asked for "within 10 mins", so checking every minute is safe.
                time.sleep(60)

        t = threading.Thread(target=run_scheduler, daemon=True)
        t.start()
        print("[System] Background auction scheduler started.")
