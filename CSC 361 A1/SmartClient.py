import ssl
import socket
import re
import sys
import urllib.parse  

def process_uri(url): #Get hostname, resource path, and port from url

    if not url.startswith(("http://", "https://")):
        url = "https://" + url  # Assume HTTPS if not specified

    is_https = url.startswith("https://")
    url = url[8:] if is_https else url[7:]  # Strip protocol only
    default_port = 443 if is_https else 80  # Set port accordingly

    if "/" in url:
        host_and_port, path = url.split("/", 1)
        path = "/" + path
    else:
        host_and_port, path = url, "/"

    if ":" in host_and_port:  # Check if a port is explicitly given
        host, port = host_and_port.split(":")
        port = int(port)
    else:
        host, port = host_and_port, default_port

    return host, port, path, is_https  #  Return HTTPS info

def check_http2_support(host, port): #Checks if the server supports HTTP/2 using ALPN negotiation.

    context = ssl.create_default_context()
    context.set_alpn_protocols(["http/1.1", "h2"])

    try:
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                return secure_sock.selected_alpn_protocol() == "h2"
    except Exception:
        return False  # If error, assume HTTP/2 is not supported

def fetch_http_response(host, port, path, use_https=True): #Sends a http get request and returns raw response

    request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    try:
        if use_https:
            context = ssl.create_default_context()
            with socket.create_connection((host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                    secure_sock.sendall(request.encode())
                    response = b""
                    while chunk := secure_sock.recv(4096):  # Read in chunks
                        response += chunk
        else:
            with socket.create_connection((host, port)) as sock:
                sock.sendall(request.encode())
                response = b""
                while chunk := sock.recv(4096):
                    response += chunk

        return response.decode("utf-8", errors="replace")  # Handle encoding errors
    except Exception as e:
        print(f" Error fetching response: {e}")
        return None

def extract_cookies(headers): #Extract cookies from response header

    cookies = []
    for line in headers.split("\r\n"):
        if line.lower().startswith("set-cookie:"):
            parts = line.split(":", 1)[1].strip().split(";")
            cookie_info = {"name": None, "domain": None, "expires": None}

            key_value = parts[0].split("=")
            cookie_info["name"] = key_value[0].strip()
            if len(key_value) > 1:
                cookie_info["value"] = key_value[1].strip()

            for part in parts[1:]:
                if "domain=" in part.lower():
                    cookie_info["domain"] = part.split("=", 1)[1].strip()
                elif "expires=" in part.lower():
                    cookie_info["expires"] = part.split("=", 1)[1].strip()
            
            cookies.append(cookie_info)
    
    return cookies

def detect_password_protection(headers, body): #Detect password protection based on 401 Unauthorized response, WWW-Authenticate header, or login form.
    
    # Check for 401 Unauthorized Status
    if "HTTP/1.1 401" in headers or "HTTP/2 401" in headers:
        return True  # Server requires authentication

    # Check for 'WWW-Authenticate' header PERHAPS ONLY NECESSARY FOR docs.engr.uvic.ca/docs, where just checking 401 seems to fail. no idea why
    if any("www-authenticate:" in line.lower() for line in headers.split("\r\n")): 
        return True

    # Check for password input fields in HTML
    if re.search(r'<form[^>]*>.*?password.*?</form>', body, re.IGNORECASE | re.DOTALL):
        return True  # Password field found

    return False  # No password protection detected

def get_redirect_location(headers):
    """Extract redirect location from response headers."""
    for line in headers.split("\r\n"):
        if line.lower().startswith("location:"):
            return line.split(":", 1)[1].strip()
    return None

def main():
    if len(sys.argv) < 2:
        print("Error: No URL specified")
        return

    url = sys.argv[1].strip()
    print(f"\n Checking URL: {url}")

    host, port, path, use_https = process_uri(url)

    # Check HTTP version support
    print("\n Checking HTTP version...")
    if check_http2_support(host, port):
        print("\n HTTP/2 is supported.")
    else:
        print("\n HTTP 2 is not supported")

    # Fethc response
    print("\n Fetching response...")
    response = fetch_http_response(host, port, path, use_https)

    if not response:
        print(" Failed to fetch response. Possible invalid uri. Please try again")
        return

    # Split headers and body
    headers, body = response.split("\r\n\r\n", 1) if "\r\n\r\n" in response else (response, "")

    # Handle redirects
    if any(code in headers for code in ("301", "302", "307", "308")):
        redirect_url = get_redirect_location(headers)
        if redirect_url:
            redirect_url = urllib.parse.urljoin(url, redirect_url)  # Handle relative redirects
            print(f"\n Redirecting to: {redirect_url}")
            host, port, path, use_https = process_uri(redirect_url)
            response = fetch_http_response(host, port, path, use_https)
            if not response:
                print(" Failed to follow redirect.")
                return
            headers, body = response.split("\r\n\r\n", 1) if "\r\n\r\n" in response else (response, "")

    # Extract and display cookies
    cookies = extract_cookies(headers)
    if cookies:
        print("\n Cookies Found:")
        for cookie in cookies:
            print(f" - {cookie['name']} (Domain: {cookie.get('domain')}, Expires: {cookie.get('expires')})")
    else:
        print("\n No cookies found.")

    # Check for password protection
    if detect_password_protection(headers, body):
        print("\n The page is password-protected.")
    else:
        print("\n No password protection detected.")

if __name__ == "__main__":
    main()
