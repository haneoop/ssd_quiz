import pytest
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options

class TestWebApplicationUI:
    
    @pytest.fixture(scope="class")
    def driver(self):
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        
        driver = webdriver.Chrome(options=chrome_options)
        driver.implicitly_wait(10)
        yield driver
        driver.quit()
    
    def test_homepage_loads(self, driver):
        """Test that the homepage loads correctly"""
        driver.get("http://localhost")
        assert "Secure Search Application" in driver.page_source
        assert driver.find_element(By.ID, "search_term")
        assert driver.find_element(By.CSS_SELECTOR, "input[type='submit']")
    
    def test_xss_protection(self, driver):
        """Test XSS attack is blocked"""
        driver.get("http://localhost")
        
        search_input = driver.find_element(By.ID, "search_term")
        search_input.send_keys("<script>alert('xss')</script>")
        
        submit_button = driver.find_element(By.CSS_SELECTOR, "input[type='submit']")
        submit_button.click()
        
        # Should stay on homepage with error message
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CLASS_NAME, "alert-error"))
        )
        assert "XSS attack detected" in driver.page_source
        assert driver.current_url.endswith("/")
    
    def test_sql_injection_protection(self, driver):
        """Test SQL injection attack is blocked"""
        driver.get("http://localhost")
        
        search_input = driver.find_element(By.ID, "search_term")
        search_input.send_keys("' OR 1=1 --")
        
        submit_button = driver.find_element(By.CSS_SELECTOR, "input[type='submit']")
        submit_button.click()
        
        # Should stay on homepage with error message
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CLASS_NAME, "alert-error"))
        )
        assert "SQL injection attack detected" in driver.page_source
        assert driver.current_url.endswith("/")
    
    def test_valid_input_success(self, driver):
        """Test valid input goes to results page"""
        driver.get("http://localhost")
        
        # Wait for page to fully load
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.ID, "search_term"))
        )
        
        search_input = driver.find_element(By.ID, "search_term")
        search_input.clear()  # Clear any existing text
        search_input.send_keys("hello world")
        
        # Wait a moment for the input to be processed
        time.sleep(0.5)
        
        # Find and click the submit button
        submit_button = driver.find_element(By.CSS_SELECTOR, "input[type='submit']")
        
        # Use JavaScript click as alternative (sometimes more reliable)
        driver.execute_script("arguments[0].click();", submit_button)
        
        # Wait for URL change or navigation
        WebDriverWait(driver, 10).until(
            lambda d: d.current_url != "http://localhost/" and d.current_url != "http://localhost"
        )
        
        # Now check for results page content
        assert "Search Results" in driver.page_source
        assert "hello world" in driver.page_source
        assert "Return to Home Page" in driver.page_source
    
    def test_return_to_home_button(self, driver):
        """Test return to home button works"""
        driver.get("http://localhost")
        
        # Submit valid search
        search_input = driver.find_element(By.ID, "search_term")
        search_input.send_keys("test search")
        
        submit_button = driver.find_element(By.CSS_SELECTOR, "input[type='submit']")
        submit_button.click()
        
        # Click return button
        return_button = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.LINK_TEXT, "← Return to Home Page"))
        )
        return_button.click()
        
        # Should be back on homepage
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.ID, "search_term"))
        )
        assert "Secure Search Application" in driver.page_source