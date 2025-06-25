# app.py

import streamlit as st
import joblib
from urllib.parse import urlparse
import re
import tldextract

# Load the trained Random Forest model
model = joblib.load("malicious_url_rfc_model.pkl")

# ========== Feature Extraction Function ==========
def extract_features(url):
    try:
        parsed = urlparse(str(url))
        hostname = parsed.netloc
        path = parsed.path
        tld = tldextract.extract(url).suffix
    except:
        hostname, path, tld = '', '', ''

    # Binary features
    def is_ip(hostname):
        return 1 if re.match(r"\d+\.\d+\.\d+\.\d+", hostname) else 0

    def is_short_url(url):
        shortening_services = re.compile(
            'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
            'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
            'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
            'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
            'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
            'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
            'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
            'tr\.im|link\.zip\.net'
        )
        return 1 if shortening_services.search(url) else 0

    # Return feature vector (18 features)
    return [
        len(hostname),                                # hostname_length
        len(path),                                    # path_length
        len(path.split('/')[1]) if len(path.split('/')) > 1 else 0,  # fd_length
        len(tld),                                     # tld_length
        url.count('-'),                               # count-
        url.count('@'),                               # count@
        url.count('?'),                               # count?
        url.count('%'),                               # count%
        url.count('.'),                               # count.
        url.count('='),                               # count=
        url.count('http'),                            # count-http
        url.count('https'),                           # count-https
        url.count('www'),                             # count-www
        sum(c.isdigit() for c in url),                # count-digits
        sum(c.isalpha() for c in url),                # count-letters
        path.count('/'),                              # count_dir
        is_ip(hostname),                              # use_of_ip
        is_short_url(url)                             # short_url
    ]

# ========== Streamlit UI ==========
st.set_page_config(page_title="Malicious URL Detector", layout="centered")
st.title("🔍 Malicious URL Detection")
st.markdown("Enter a URL below to check if it is **Malicious** or **Benign**.")

# Input box
url_input = st.text_input("🔗 Enter URL:")

# Predict button
if st.button("Predict"):
    if url_input:
        features = extract_features(url_input)
        prediction = model.predict([features])[0]

        if prediction == 1:
            st.error("⚠️ Warning: This URL is **Malicious**.")
        else:
            st.success("✅ This URL is **Benign** and Safe.")
    else:
        st.warning("🚨 Please enter a URL to analyze.")
