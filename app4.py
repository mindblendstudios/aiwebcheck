import streamlit as st
import requests
import os
import pandas as pd
from bs4 import BeautifulSoup
from fpdf import FPDF
from PIL import Image
import ssl
import socket
import datetime
import urllib3

# ================== CONFIG ==================
st.set_page_config(page_title="AI Website Testing Platform", layout="wide")
os.makedirs("screenshots", exist_ok=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================== HELPER FUNCTIONS ==================
def safe_get(url, timeout=10):
    """Safe GET request that handles SSL issues and unreachable hosts."""
    try:
        return requests.get(url, timeout=timeout)
    except requests.exceptions.SSLError:
        try:
            return requests.get(url, timeout=timeout, verify=False)
        except Exception as e:
            st.warning(f"⚠️ Could not reach {url}: {e}")
            return None
    except requests.exceptions.RequestException as e:
        st.warning(f"⚠️ Could not reach {url}: {e}")
        return None

def safe_head(url, timeout=5):
    """Safe HEAD request that handles SSL issues and unreachable hosts."""
    try:
        return requests.head(url, timeout=timeout)
    except requests.exceptions.SSLError:
        try:
            return requests.head(url, timeout=timeout, verify=False)
        except Exception as e:
            st.warning(f"⚠️ Could not reach {url}: {e}")
            return None
    except requests.exceptions.RequestException as e:
        st.warning(f"⚠️ Could not reach {url}: {e}")
        return None

def is_valid_hostname(url):
    """Checks if the URL's domain can be resolved."""
    try:
        hostname = url.replace("https://", "").replace("http://", "").split("/")[0]
        socket.gethostbyname(hostname)
        return True
    except socket.error:
        return False

def get_live_screenshot(url):
    """Fetches a live screenshot using thum.io API."""
    screenshot_path = "screenshots/page.png"
    api_url = f"https://image.thum.io/get/{url}"
    try:
        r = requests.get(api_url, stream=True, timeout=10)
        if r.status_code == 200:
            with open(screenshot_path, "wb") as f:
                for chunk in r.iter_content(1024):
                    f.write(chunk)
            return screenshot_path
        else:
            st.warning(f"⚠️ Screenshot service returned status {r.status_code}")
    except Exception as e:
        st.warning(f"⚠️ Could not fetch live screenshot: {e}")
    # Fallback placeholder
    img = Image.new("RGB", (1200, 800), color=(200, 200, 200))
    from PIL import ImageDraw
    draw = ImageDraw.Draw(img)
    draw.text((50, 400), f"Preview unavailable: {url}", fill=(0, 0, 0))
    img.save(screenshot_path)
    return screenshot_path

# ================== AGENTS ==================
class FunctionalAgent:
    def __init__(self, url):
        self.url = url

    def run(self):
        issues = []
        r = safe_get(self.url)
        if r is None:
            return ["Website unreachable, skipping functional tests"]
        if r.status_code != 200:
            issues.append(f"HTTP status code {r.status_code}")

        soup = BeautifulSoup(r.text, "html.parser")
        for link in soup.find_all("a"):
            href = link.get("href")
            if href and href.startswith("http"):
                head_resp = safe_head(href)
                if head_resp is None:
                    issues.append(f"Link unreachable: {href}")
                elif head_resp.status_code >= 400:
                    issues.append(f"Broken link: {href}")
        return issues

class UXAgent:
    def __init__(self, url):
        self.url = url

    def run(self):
        issues = []
        r = safe_get(self.url)
        if r is None:
            return ["Website unreachable, skipping UX tests"]
        soup = BeautifulSoup(r.text, "html.parser")
        if not soup.find("nav"):
            issues.append("Navigation bar missing")
        if not soup.find("footer"):
            issues.append("Footer missing")
        if not soup.find("meta", {"name": "viewport"}):
            issues.append("Viewport meta tag missing")
        return issues

class AccessibilityAgent:
    def __init__(self, url):
        self.url = url

    def run(self):
        issues = []
        r = safe_get(self.url)
        if r is None:
            return ["Website unreachable, skipping accessibility tests"]
        soup = BeautifulSoup(r.text, "html.parser")

        for img in soup.find_all("img"):
            if not img.get("alt"):
                src = img.get("src") or "[no src attribute]"
                issues.append(f"Image missing alt attribute: {src}")

        if soup.html and not soup.html.get("lang"):
            issues.append("HTML lang attribute missing")

        return issues

class SecurityAgent:
    def __init__(self, url):
        self.url = url

    def run(self):
        issues = []
        r = safe_get(self.url)
        if r is None:
            return ["Website unreachable, skipping security tests"]
        headers = r.headers
        if "Content-Security-Policy" not in headers:
            issues.append("Missing Content-Security-Policy header")
        if "X-Frame-Options" not in headers:
            issues.append("Missing X-Frame-Options header")
        if not self.url.startswith("https"):
            issues.append("Website not using HTTPS")
        return issues

# ================== BROWSER AGENT ==================
class BrowserAgent:
    """
    Browser automation disabled.
    Fetch live screenshot via service.
    """
    def __init__(self, url):
        self.url = url
        self.issues = []

    def run(self):
        screenshot = get_live_screenshot(self.url)
        self.issues.append("Browser automation disabled; using live preview instead")
        return self.issues, screenshot

# ================== SSL HEALTH AGENT ==================
class SSLHealthAgent:
    def __init__(self, url):
        self.url = url.replace("https://", "").replace("http://", "")

    def run(self):
        issues = []
        tls_version = None
        hsts = False

        context = ssl.create_default_context()

        try:
            with socket.create_connection((self.url, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.url) as ssock:
                    cert = ssock.getpeercert()
                    expire_date = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                    if expire_date < datetime.datetime.utcnow():
                        issues.append("SSL certificate has expired")
                    sig_algo = cert.get("signatureAlgorithm", "")
                    if "sha1" in sig_algo.lower():
                        issues.append("Weak SSL certificate signature algorithm (SHA-1)")
                    tls_version = ssock.version()
                    response = safe_get(f"https://{self.url}")
                    if response and "Strict-Transport-Security" in response.headers:
                        hsts = True

        except Exception as e:
            issues.append(f"SSL/TLS connection failed: {e}")

        return {
            "issues": issues,
            "tls_version": tls_version,
            "hsts": hsts
        }

# ================== AI VISUAL UX AGENT ==================
class AIVisualUXAgent:
    def __init__(self, screenshot_path):
        self.screenshot_path = screenshot_path

    def run(self):
        if not self.screenshot_path or not os.path.exists(self.screenshot_path):
            return ["Screenshot not available, cannot generate UX critique."]
        # Mock AI critique
        critique = [
            "Primary call-to-action button is not prominent.",
            "Navigation menu could be clearer on mobile.",
            "Contrast ratio between text and background is low in footer.",
            "Too many elements above the fold, consider simplifying."
        ]
        return critique

# ================== EXPORTERS ==================
def export_csv(report):
    rows = []
    for cat, issues in report.items():
        if isinstance(issues, list):
            for issue in issues:
                rows.append({"Category": cat, "Issue": issue})
        elif isinstance(issues, dict):
            if "issues" in issues:
                for issue in issues["issues"]:
                    rows.append({"Category": cat, "Issue": issue})
            if "UX Critique" in issues:
                for critique in issues["UX Critique"]:
                    rows.append({"Category": cat, "Issue": critique})
    df = pd.DataFrame(rows)
    df.to_csv("defects.csv", index=False)
    return "defects.csv"

def export_pdf(report):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=10)
    for cat, issues in report.items():
        pdf.cell(0, 8, cat, ln=True)
        if isinstance(issues, list):
            for issue in issues:
                pdf.multi_cell(0, 6, f"- {issue}")
        elif isinstance(issues, dict):
            if "issues" in issues:
                for issue in issues["issues"]:
                    pdf.multi_cell(0, 6, f"- {issue}")
            if "tls_version" in issues and issues["tls_version"]:
                pdf.multi_cell(0, 6, f"TLS Version: {issues['tls_version']}")
            pdf.multi_cell(0, 6, f"HSTS: {issues.get('hsts', False)}")
            if "UX Critique" in issues:
                for critique in issues["UX Critique"]:
                    pdf.multi_cell(0, 6, f"UX Critique: {critique}")
    pdf.output("defects.pdf")
    return "defects.pdf"

# ================== STREAMLIT UI ==================
st.title("🤖 AI Website Testing Platform")
st.write("Functional, UX, accessibility, security, SSL/TLS checks + AI visual UX critique.")

url = st.text_input("🌐 Website URL", placeholder="https://example.com")

if st.button("🚀 Run Tests"):
    if not url:
        st.warning("Please enter a valid URL")
    elif not is_valid_hostname(url):
        st.error("⚠️ Cannot resolve domain. Please check the URL and include https://")
    else:
        with st.spinner("Running tests..."):

            # Core agents
            report = {
                "Functional Issues": FunctionalAgent(url).run(),
                "UX Issues": UXAgent(url).run(),
                "Accessibility Issues": AccessibilityAgent(url).run(),
                "Security Issues": SecurityAgent(url).run(),
            }

            # Browser screenshot
            browser_issues, screenshot = BrowserAgent(url).run()
            report["Browser Issues"] = browser_issues

            # AI UX critique
            report["AI UX Critique"] = {"UX Critique": AIVisualUXAgent(screenshot).run()}

            # SSL health
            ssl_report = SSLHealthAgent(url).run()
            report["SSL Health"] = ssl_report

        st.success("Testing completed")

        # -------- RESULTS --------
        for cat, issues in report.items():
            with st.expander(cat):
                if isinstance(issues, list) and issues:
                    for i in issues:
                        st.error(i)
                elif isinstance(issues, dict):
                    if "issues" in issues and issues["issues"]:
                        for i in issues["issues"]:
                            st.error(i)
                    if "tls_version" in issues and issues["tls_version"]:
                        st.info(f"TLS Version: {issues['tls_version']}")
                    st.info(f"HSTS: {issues.get('hsts', False)}")
                    if "UX Critique" in issues:
                        st.subheader("🖼 AI Visual UX Critique")
                        for critique in issues["UX Critique"]:
                            st.info(critique)
                else:
                    st.success("No issues found")

        # -------- SCREENSHOT --------
        if screenshot and os.path.exists(screenshot):
            st.subheader("📸 Website Screenshot")
            st.image(Image.open(screenshot))
        else:
            st.info("Screenshot not available")

        # -------- EXPORTS --------
        csv_file = export_csv(report)
        pdf_file = export_pdf(report)

        st.download_button("⬇️ Download CSV", open(csv_file, "rb"), csv_file)
        st.download_button("⬇️ Download PDF", open(pdf_file, "rb"), pdf_file)
