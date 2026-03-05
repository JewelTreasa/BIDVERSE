from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

def test_login():
    # Initialize the WebDriver (assuming Chrome)
    # If the driver is not in your PATH, you might need to specify the path
    # e.g., driver = webdriver.Chrome(executable_path='path/to/chromedriver')
    driver = webdriver.Chrome()
    driver.maximize_window()
    
    try:
        # 1. Go to home page
        print("Navigating to Home Page...")
        driver.get("http://127.0.0.1:8000")
        
        # 2. Go to login page
        print("Clicking on Login button...")
        login_btn = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, ".nav-buttons .btn-outline"))
        )
        login_btn.click()
        
        # 3. Enter credentials
        print("Entering credentials...")
        WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.ID, "email"))
        )
        
        driver.find_element(By.ID, "email").send_keys("alan@gmail.com")
        driver.find_element(By.ID, "password").send_keys("alan@123")
        
        # 4. Click on login button
        print("Submitting login form...")
        driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
        
        # 5. Go to corresponding dashboard
        # Wait for redirection to Home Page after login
        WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.CLASS_NAME, "profile-icon-btn"))
        )
        print("Login successful. Navigating to Dashboard...")
        
        # Click on profile icon to show dropdown
        driver.find_element(By.CLASS_NAME, "profile-icon-btn").click()
        
        # Click on Dashboard link
        dashboard_link = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.XPATH, "//a[contains(., 'Dashboard')]"))
        )
        dashboard_link.click()
        
        # Verify if we are on the dashboard
        WebDriverWait(driver, 10).until(
            EC.url_contains("/dashboard/")
        )
        print("Successfully reached the Dashboard!")
        print("Test passed!")
        
        # Stay on the dashboard for a few seconds to see result
        time.sleep(5)
        
    except Exception as e:
        print(f"An error occurred during the test: {e}")
    finally:
        # Close the driver
        driver.quit()

if __name__ == "__main__":
    test_login()
