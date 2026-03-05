from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select
import time
import os

def test_add_listing():
    # Initialize the WebDriver
    driver = webdriver.Chrome()
    driver.maximize_window()
    
    try:
        # 1. Login Flow (Necessary setup)
        print("Logging in...")
        driver.get("http://127.0.0.1:8000/login/")
        
        WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.ID, "email")))
        driver.find_element(By.ID, "email").send_keys("alan@gmail.com")
        driver.find_element(By.ID, "password").send_keys("alan@123")
        driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
        
        # 2. Go to Dashboard (redir usually happens automatically, but let's be sure)
        print("Navigating to Dashboard...")
        WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.CLASS_NAME, "profile-icon-btn")))
        driver.get("http://127.0.0.1:8000/dashboard/")
        
        # 3. Go to "Add Listed" section
        print("Clicking on 'Add Listed' section...")
        add_listing_link = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.XPATH, "//a[contains(., 'Add Listed')]"))
        )
        add_listing_link.click()
        
        # Wait for form to load
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.NAME, "commodity")))
        
        # 4. Fill in the auction details
        print("Filling out auction details...")
        driver.find_element(By.NAME, "commodity").send_keys("Organic Wheat")
        driver.find_element(By.NAME, "quantity").send_keys("100")
        
        # Unit selection
        unit_select = Select(driver.find_element(By.NAME, "unit"))
        unit_select.select_by_value("kg")
        
        driver.find_element(By.NAME, "base_price").send_keys("45.50")
        
        # Description
        driver.find_element(By.NAME, "description").send_keys("High quality organic wheat freshly harvested from the farm.")
        
        # Set date to tomorrow to be safe from today's session cutoffs
        print("Setting date to tomorrow...")
        from datetime import datetime, timedelta
        tomorrow = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
        driver.execute_script(f"document.getElementById('listing_date')._flatpickr.setDate('{tomorrow}')")
        time.sleep(1)

        # UNCHECK Morning Session if it's checked by default or mistake
        print("Ensuring Morning Session is unchecked...")
        morning_checkbox = driver.find_element(By.NAME, "morning_session")
        if morning_checkbox.is_selected():
            driver.execute_script("arguments[0].click();", morning_checkbox)

        # CHECK Evening Session
        print("Selecting Evening Session...")
        evening_checkbox = driver.find_element(By.NAME, "evening_session")
        if not evening_checkbox.is_selected():
            driver.execute_script("arguments[0].click();", evening_checkbox)
            
        print("Publishing listing...")
        # Submit the form using Javascript
        submit_btn = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        driver.execute_script("arguments[0].click();", submit_btn)
        
        # 5. Verify listing creation
        # Redirection should go back to My Listings or show a success message
        WebDriverWait(driver, 10).until(EC.url_contains("section=listings"))
        print("Success! Auction listed and redirected to listings page.")
        
        time.sleep(5)
        
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        driver.quit()

if __name__ == "__main__":
    test_add_listing()
