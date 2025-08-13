import streamlit as st
import pandas as pd
import joblib
import re
import matplotlib.pyplot as plt

# ---------------------------
# Load the trained Random Forest model
# ---------------------------
model = joblib.load("random_forest_model.pkl")

# ---------------------------
# Feature Extraction Function
# ---------------------------
def extract_features(url):
    features = {}
    
    # 1. URL Length
    features['url_length'] = len(url)
    
    # 2. Number of digits
    features['num_digits'] = sum(c.isdigit() for c in url)
    
    # 3. Number of special characters
    features['num_special_chars'] = sum(not c.isalnum() for c in url)
    
    # 4. Count of '.'
    features['count_dot'] = url.count('.')
    
    # 5. Count of '-'
    features['count_hyphen'] = url.count('-')
    
    # 6. Count of '@'
    features['count_at'] = url.count('@')
    
    # 7. Count of '?'
    features['count_question'] = url.count('?')
    
    # 8. Count of '='
    features['count_equal'] = url.count('=')
    
    # 9. Has IP address
    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    features['has_ip'] = 1 if re.search(ip_pattern, url) else 0
    
    # 10. Uses shortening service
    shortening_services = r"(bit\.ly|goo\.gl|tinyurl\.com|ow\.ly)"
    features['is_shortened'] = 1 if re.search(shortening_services, url) else 0
    
    return features

# ---------------------------
# Predict Function
# ---------------------------
def predict_url(url):
    features = extract_features(url)
    df = pd.DataFrame([features])
    prediction = model.predict(df)[0]
    return "Malicious" if prediction == 1 else "Safe"

# ---------------------------
# Streamlit UI
# ---------------------------
st.title("🔍 Malicious URL Detection App")
st.write("Enter a single URL or upload a CSV file for batch prediction.")

# Single URL Prediction
st.subheader("Single URL Prediction")
user_url = st.text_input("Enter a URL:")

if st.button("Predict"):
    if user_url.strip():
        result = predict_url(user_url)
        st.success(f"The URL is **{result}**")
    else:
        st.warning("Please enter a valid URL.")

# Batch Prediction
st.subheader("Batch Prediction via CSV")
uploaded_file = st.file_uploader("Upload CSV with a 'url' column", type=["csv"])

if uploaded_file:
    df_urls = pd.read_csv(uploaded_file)
    if 'url' not in df_urls.columns:
        st.error("CSV must contain a 'url' column.")
    else:
        df_urls['Prediction'] = df_urls['url'].apply(predict_url)
        
        # Show results
        st.write(df_urls)
        
        # Pie chart of results
        counts = df_urls['Prediction'].value_counts()
        fig, ax = plt.subplots()
        ax.pie(counts, labels=counts.index, autopct="%1.1f%%", startangle=90)
        st.pyplot(fig)
        
        # Download option
        csv_download = df_urls.to_csv(index=False).encode('utf-8')
        st.download_button("Download Predictions", csv_download, "predictions.csv", "text/csv")

