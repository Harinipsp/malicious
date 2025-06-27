import streamlit as st
import pandas as pd
import joblib
from urllib.parse import urlparse
import re
import tldextract
import matplotlib.pyplot as plt
import seaborn as sns

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

    def is_ip(hostname):
        return 1 if re.match(r"\d+\.\d+\.\d+\.\d+", hostname) else 0

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
        is_ip(hostname)                               # use_of_ip
    ]

# ========== Streamlit UI ==========
st.set_page_config(page_title="Malicious URL Detector", layout="centered")
st.title("🔍 Malicious URL Detection")
st.markdown("Check if a URL is **Malicious** or **Benign** using a trained ML model.")

tab1, tab2 = st.tabs(["🔗 Single URL Prediction", "📁 Batch Prediction"])

# ======= Tab 1: Single URL =======
with tab1:
    url_input = st.text_input("Enter a URL:")
    if st.button("Predict"):
        if url_input:
            features = extract_features(url_input)
            prediction = model.predict([features])[0]

            if prediction == 1:
                st.error("⚠️ This URL is **Malicious**.")
            else:
                st.success("✅ This URL is **Benign**.")
        else:
            st.warning("Please enter a valid URL.")

# ======= Tab 2: Batch Prediction =======
with tab2:
    st.markdown("Upload a CSV file with a column named **`url`** for batch prediction.")
    file = st.file_uploader("📤 Upload CSV", type=["csv"])

    if file is not None:
        try:
            df = pd.read_csv(file)
            if 'url' not in df.columns:
                st.error("❌ CSV must contain a 'url' column.")
            else:
                # Feature extraction for all URLs
                df['features'] = df['url'].apply(lambda x: extract_features(x))
                features_list = list(df['features'].values)
                predictions = model.predict(features_list)

                df['Prediction'] = predictions
                df['Prediction_Label'] = df['Prediction'].apply(lambda x: "Malicious" if x == 1 else "Benign")

                st.subheader("📊 Prediction Results")
                st.dataframe(df[['url', 'Prediction_Label']])

                # Visualization
                st.subheader("📈 Visual Summary")
                count_data = df['Prediction_Label'].value_counts()

                col1, col2 = st.columns(2)
                with col1:
                    fig1, ax1 = plt.subplots()
                    ax1.pie(count_data, labels=count_data.index, autopct='%1.1f%%', colors=['red', 'green'], startangle=90)
                    ax1.axis('equal')
                    st.pyplot(fig1)

                with col2:
                    fig2, ax2 = plt.subplots()
                    sns.barplot(x=count_data.index, y=count_data.values, palette=['red', 'green'], ax=ax2)
                    ax2.set_ylabel("Number of URLs")
                    st.pyplot(fig2)

                st.download_button("⬇ Download Results as CSV", data=df.to_csv(index=False), file_name="url_predictions.csv", mime="text/csv")
        except Exception as e:
            st.error(f"Something went wrong: {e}")
