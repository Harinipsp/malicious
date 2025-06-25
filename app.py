import streamlit as st
import joblib
from urllib.parse import urlparse
import re
import tldextract

# ========== Load the trained model ==========
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

    def is_ip(hostname):
        return 1 if re.match(r"\d+\.\d+\.\d+\.\d+", hostname) else 0

    return [
        len(hostname),                              # hostname_length
        len(path),                                  # path_length
        len(path.split('/')[1]) if len(path.split('/')) > 1 else 0,  # fd_length
        len(tld),                                   # tld_length
        url.count('-'),                             # count-
        url.count('@'),                             # count@
        url.count('?'),                             # count?
        url.count('%'),                             # count%
        url.count('.'),                             # count.
        url.count('='),                             # count=
        url.count('http'),                          # count-http
        url.count('https'),                         # count-https
        url.count('www'),                           # count-www
        sum(c.isdigit() for c in url),              # count-digits
        sum(c.isalpha() for c in url),              # count-letters
        path.count('/'),                            # count_dir
        is_ip(hostname)                             # use_of_ip
    ]

# ========== Streamlit UI ==========
st.set_page_config(page_title="Malicious URL Detector", layout="centered")
st.title("🔍 Malicious URL Detection using Random Forest")
st.markdown("Enter a URL below to check if it is **Malicious** or **Benign**.")

url_input = st.text_input("🔗 Enter URL here:")

if st.button("Predict"):
    if url_input:
        features = extract_features(url_input)
        prediction = model.predict([features])[0]

        if prediction == 1:
            st.error("⚠️ Malicious URL Detected!")
        else:
            st.success("✅ This URL is Safe (Benign).")
    else:
        st.warning("Please enter a valid URL.")
