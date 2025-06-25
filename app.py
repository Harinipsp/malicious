import streamlit as st
import joblib
from urllib.parse import urlparse
import re
import tldextract

# Load the trained model
model = joblib.load("malicious_url_rfc_model.pkl")

def extract_features(url):
    try:
        parsed = urlparse(str(url))
        hostname = parsed.netloc
        path = parsed.path
        tld = tldextract.extract(url).suffix
    except:
        hostname = ''
        path = ''
        tld = ''

    return [
        len(url), len(hostname), len(path),
        len(path.split('/')[1]) if len(path.split('/')) > 1 else 0,
        len(tld), url.count('-'), url.count('@'), url.count('?'),
        url.count('%'), url.count('.'), url.count('='), url.count('http'),
        url.count('www'), sum(c.isdigit() for c in url),
        sum(c.isalpha() for c in url), path.count('/'),
        1 if re.match(r"\d+\.\d+\.\d+\.\d+", hostname) else 0,
        1 if len(url) < 54 else 0
    ]

st.set_page_config(page_title="Malicious URL Detector", layout="centered")
st.title("🔍 Malicious URL Detection")
st.markdown("Enter a URL to check if it's **Malicious** or **Benign**.")

url_input = st.text_input("🔗 Enter URL:")
if st.button("Predict"):
    if url_input:
        features = extract_features(url_input)
        prediction = model.predict([features])[0]
        if prediction == 1:
            st.error("⚠️ Malicious URL Detected!")
        else:
            st.success("✅ This URL is Safe (Benign).")
    else:
        st.warning("Please enter a URL.")
