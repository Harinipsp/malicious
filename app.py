import streamlit as st
import pandas as pd
import joblib
from urllib.parse import urlparse
import re
import tldextract
import matplotlib.pyplot as plt

# Load trained model
model = joblib.load("malicious_url_rfc_model.pkl")

# ========== Feature Extraction ==========
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
        len(url),
        len(hostname),
        len(path),
        len(path.split('/')[1]) if len(path.split('/')) > 1 else 0,
        len(tld),
        url.count('-'),
        url.count('@'),
        url.count('?'),
        url.count('%'),
        url.count('.'),
        url.count('='),
        url.count('http'),
        url.count('https'),
        url.count('www'),
        sum(c.isdigit() for c in url),
        sum(c.isalpha() for c in url),
        path.count('/'),
        1 if re.match(r"\d+\.\d+\.\d+\.\d+", hostname) else 0,
        1 if len(url) < 54 else 0
    ]

# Streamlit UI
st.set_page_config(page_title="Malicious URL Detector", layout="centered")
st.title("🔍 Malicious URL Detection")
st.markdown("Check if a URL is **Malicious** or **Benign** (Single or Batch Mode)")

# ---- Single Prediction ----
st.header("🔗 Single URL Check")
url_input = st.text_input("Enter URL:")
if st.button("Predict"):
    if url_input:
        features = extract_features(url_input)
        prediction = model.predict([features])[0]
        if prediction == 1:
            st.error("⚠️ Malicious URL Detected!")
        else:
            st.success("✅ This URL is Safe (Benign).")
    else:
        st.warning("Please enter a URL")

# ---- Batch Prediction ----
st.header("📁 Batch URL Prediction")
uploaded_file = st.file_uploader("Upload a CSV file with a column named 'url'")

if uploaded_file is not None:
    try:
        df = pd.read_csv(uploaded_file)
        if 'url' not in df.columns:
            st.error("The CSV must have a column named 'url'")
        else:
            df['features'] = df['url'].apply(lambda x: extract_features(x))
            X = pd.DataFrame(df['features'].tolist())
            df['prediction'] = model.predict(X)
            df['prediction'] = df['prediction'].map({1: 'Malicious', 0: 'Benign'})

            st.success("Batch prediction complete!")
            st.dataframe(df[['url', 'prediction']])

            # Download option
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button("📥 Download Predictions", csv, "batch_predictions.csv", "text/csv")

            # Visualization
            st.subheader("📊 Prediction Distribution")
            counts = df['prediction'].value_counts()
            st.bar_chart(counts)

            fig, ax = plt.subplots()
            ax.pie(counts, labels=counts.index, autopct='%1.1f%%', startangle=90)
            ax.axis('equal')
            st.pyplot(fig)

    except Exception as e:
        st.error(f"Something went wrong: {e}")
