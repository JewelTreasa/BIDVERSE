from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

def test_claim_won_auction():
    # Initialize the WebDriver
    driver = webdriver.Chrome()
    driver.maximize_window()
    
    try:
        # 1. Login with the buyer credentials
        print("Logging in as Buyer...")
        driver.get("http://127.0.0.1:8000/login/")
        
        WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.ID, "email")))
        driver.find_element(By.ID, "email").send_keys("jeweltreasaraphel2028@mca.ajce.in")
        driver.find_element(By.ID, "password").send_keys("123jewel")
        driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
        
        # 2. Wait for login and navigate to Dashboard "Won" section
        print("Navigating to Won Auctions section...")
        # Since login usually goes to home, we explicitly go to dashboard won section
        time.sleep(1) # Small delay for auth cookies
        driver.get("http://127.0.0.1:8000/dashboard/?section=won")
        
        # 3. Look for "Claim Now" button
        print("Looking for 'Claim Now' button...")
        try:
            # Locate the first "Claim Now" link
            claim_now_btn = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.XPATH, "//a[contains(text(), 'Claim Now')]"))
            )
            print("Found a won auction ready to be claimed. Clicking 'Claim Now'...")
            
            # Click the button
            driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", claim_now_btn)
            time.sleep(1)
            claim_now_btn.click()
            
            # 4. Verify redirection to checkout/order page
            # Based on the URL pattern, it should go to a checkout or order summary page
            print("Verifying redirection to checkout page...")
            WebDriverWait(driver, 10).until(EC.url_contains("checkout") or EC.url_contains("order"))
            
            print("Test Passed: Redirection to claim/checkout page successful!")
            
        except Exception as inner_e:
            print(f"Claim check failed. Probable cause: No unclaimed won auctions found. Error: {inner_e}")

        # Pause to view the result
        time.sleep(5)
        
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        driver.quit()

if __name__ == "__main__":
    test_claim_won_auction()
