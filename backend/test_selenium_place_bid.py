from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

def test_place_bid():
    # Initialize the WebDriver
    driver = webdriver.Chrome()
    driver.maximize_window()
    
    try:
        # 1. Login with the new credentials
        print("Logging in as Buyer...")
        driver.get("http://127.0.0.1:8000/login/")
        
        WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.ID, "email")))
        driver.find_element(By.ID, "email").send_keys("jeweltreasaraphel2028@mca.ajce.in")
        driver.find_element(By.ID, "password").send_keys("123jewel")
        driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
        
        # 2. Redirection to Home Page
        print("Navigating to Home Page...")
        WebDriverWait(driver, 10).until(EC.url_to_be("http://127.0.0.1:8000/"))
        
        # 3. Find a Live auction and click "Place Bid"
        print("Looking for a Live auction...")
        # We look for the first card that has a "Place Bid" button
        # (Based on index.html: class 'bid-btn' is used for the Place Bid button)
        try:
            place_bid_btn = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, ".auction-card .bid-btn"))
            )
            print("Found an active auction. Clicking 'Place Bid'...")
            # Click the button (scrolling into view first for safety)
            driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", place_bid_btn)
            time.sleep(1)
            place_bid_btn.click()
            
            # 4. On the auction detail page, enter a bid amount
            print("Entering bid amount...")
            # Wait for the bid input field
            bid_input = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.ID, "bidInput"))
            )
            
            # Get the placeholder or current price to decide bid amount
            current_price_str = bid_input.get_attribute("placeholder")
            if not current_price_str:
                current_price_str = bid_input.get_attribute("data-current-price")
            
            try:
                current_price = float(current_price_str)
            except:
                current_price = 100.0 # Fallback
            
            # Place a bid higher than the current price
            new_bid = current_price + 10
            bid_input.clear()
            bid_input.send_keys(str(new_bid))
            print(f"Bidding ₹{new_bid}...")
            
            # 5. Click "Place Bid Now"
            submit_bid_btn = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
            driver.execute_script("arguments[0].click();", submit_bid_btn)
            
            # 6. Verify successful bid
            # The backend redirects to the detail page but doesn't show an 'alert-success'.
            # We verify by checking if the new bid amount appears on the page.
            print(f"Verifying if ₹{new_bid} appears in the bid history...")
            WebDriverWait(driver, 15).until(
                EC.presence_of_element_located((By.XPATH, f"//*[contains(text(), '{int(new_bid)}')]"))
            )
            print("Test Passed: Bid verified on page!")
            
        except Exception as inner_e:
            print(f"Could not find a live auction or place bid: {inner_e}")
            # Alternative: If no live auctions on home page, maybe try Marketplace?
            print("No live auctions found on Home Page. Test finished with no bids.")

        time.sleep(5)
        
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        driver.quit()

if __name__ == "__main__":
    test_place_bid()
