import streamlit as st
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import ssl
import pandas as pd
from fpdf import FPDF
from PIL import Image, ImageDraw
import io

st.set_page_config(page_title="AI Web Checker", layout="wide")
st.title("🌐 AI Website Checker (Cloud Compatible)")

# --------------------------
# Helper Functions
# --------------------------

def fetch_url(url):
    """Fetch URL content safely, handle DNS or connection errors"""
    try:
        response = requests.get(url, timeout=10, verify=True)
        response.raise_for_status()
        return response.text
    except requests.exceptions.SSLError:
        st.error("SSL verification failed for this site.")
        return None
    except requests.exceptions.ConnectionError:
        st.error("Connection error: DNS resolution failed or host unreachable.")
        return None
    except Exception as e:
        st.error(f"Error fetching URL: {e}")
        return None

def analyze_accessibility(html, base_url):
    """Check for missing alt attributes in images"""
    soup = BeautifulSoup(html, "html.parser")
    img_tags = soup.find_all("img")
    issues = []
    for img in img_tags:
        if not img.get("alt"):
            src = img.get("src")
            if src and not src.startswith("http"):
                src = base_url + src
            issues.append({"tag": str(img), "src": src})
    return issues

def ssl_health(url):
    """Simple SSL check: weak certs, TLS version, HSTS"""
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 443
    context = ssl.create_default_context()
    result = {"tls_version": None, "hsts": False, "weak_cert": False}
    try:
        with ssl.create_default_context().wrap_socket(socket=ssl.SSLSocket, server_hostname=hostname) as s:
            s.connect((hostname, port))
            result["tls_version"] = s.version()
            # HSTS and weak cert detection simplified
            # Placeholder for advanced SSL checks
    except Exception:
        result["tls_version"] = "Unavailable"
    return result

def get_placeholder_screenshot(url):
    """Return a placeholder screenshot since browser testing is disabled"""
    img = Image.new("RGB", (800, 600), color=(220, 220, 220))
    draw = ImageDraw.Draw(img)
    draw.text((150, 280), "Screenshot unavailable\nBrowser testing disabled in cloud", fill=(0, 0, 0))
    return img

def ai_ux_critique(html):
    """Mock AI UX critique based on simple heuristics"""
    critiques = []
    soup = BeautifulSoup(html, "html.parser")
    # Example heuristic: long paragraphs without headings
    paragraphs = soup.find_all("p")
    for i, p in enumerate(paragraphs):
        if len(p.get_text(strip=True)) > 300:
            critiques.append(f"Paragraph {i+1} is very long; consider breaking into smaller chunks for readability.")
    # Missing H1
    if not soup.find("h1"):
        critiques.append("No H1 heading found; consider adding a main heading for clarity and SEO.")
    return critiques

def export_csv_pdf(data, csv_filename="report.csv", pdf_filename="report.pdf"):
    """Export accessibility and UX issues to CSV and PDF"""
    df = pd.DataFrame(data)
    df.to_csv(csv_filename, index=False)

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Website Report", ln=True, align="C")
    pdf.ln(5)
    for row in data:
        for k, v in row.items():
            pdf.multi_cell(0, 8, f"{k}: {v}")
        pdf.ln(3)
    pdf.output(pdf_filename)

# --------------------------
# Streamlit UI
# --------------------------

url = st.text_input("Enter Website URL (include https://)")

if url:
    st.info("Fetching website...")
    html = fetch_url(url)
    if html:
        base_url = url.rstrip("/")
        
        # Accessibility
        st.subheader("🟢 Accessibility Report")
        accessibility_issues = analyze_accessibility(html, base_url)
        if accessibility_issues:
            st.warning(f"{len(accessibility_issues)} image(s) missing alt attributes:")
            for issue in accessibility_issues:
                st.markdown(f"- `{issue['src']}`")
        else:
            st.success("All images have alt attributes.")

        # SSL/TLS
        st.subheader("🔒 SSL / TLS Health")
        try:
            import socket
            ssl_info = ssl_health(url)
            st.write(ssl_info)
        except Exception:
            st.warning("Advanced SSL/TLS check unavailable in this environment.")

        # Screenshot placeholder
        st.subheader("📸 Website Screenshot")
        screenshot = get_placeholder_screenshot(url)
        st.image(screenshot)

        # AI UX critique
        st.subheader("🤖 AI UX Critique")
        critiques = ai_ux_critique(html)
        if critiques:
            for c in critiques:
                st.markdown(f"- {c}")
        else:
            st.success("No major UX issues detected by AI heuristic analysis.")

        # Export CSV / PDF
        st.subheader("💾 Export Report")
        export_data = []
        for issue in accessibility_issues:
            export_data.append({"type": "Accessibility", "detail": f"Missing alt: {issue['src']}"})
        for c in critiques:
            export_data.append({"type": "UX", "detail": c})
        
        if export_data:
            export_csv_pdf(export_data)
            st.download_button("Download CSV Report", "report.csv")
            st.download_button("Download PDF Report", "report.pdf")
        else:
            st.info("No issues to export.")

