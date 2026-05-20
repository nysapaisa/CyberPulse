import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import re

def clean_text(text):
    text = str(text).lower()
    text = re.sub(r'[^a-z0-9\s]', '', text)
    return text

def get_threat_category(description):
    """Rule-based category tagging"""
    desc = description.lower()
    if any(w in desc for w in ['sql','injection','xss','cross-site']):
        return 'Web Attack'
    elif any(w in desc for w in ['ransomware','malware','trojan','virus']):
        return 'Malware'
    elif any(w in desc for w in ['buffer overflow','memory','heap']):
        return 'Memory Exploit'
    elif any(w in desc for w in ['privilege','escalation','root','admin']):
        return 'Privilege Escalation'
    elif any(w in desc for w in ['phishing','social engineering','credential']):
        return 'Phishing'
    elif any(w in desc for w in ['iot','firmware','device','router']):
        return 'IoT Vulnerability'
    elif any(w in desc for w in ['cloud','aws','azure','container']):
        return 'Cloud Security'
    else:
        return 'Other'

def train_severity_model(df):
    """Train ML model to predict severity from description"""
    df = df.dropna(subset=['Description','Severity'])
    df = df[df['Severity'] != 'UNKNOWN']
    
    if len(df) < 10:
        return None, None
    
    df['Clean_Desc'] = df['Description'].apply(clean_text)
    
    vectorizer = TfidfVectorizer(max_features=500, ngram_range=(1,2))
    X = vectorizer.fit_transform(df['Clean_Desc'])
    y = df['Severity']
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    print("Model Performance:")
    print(classification_report(y_test, y_pred, zero_division=0))
    
    return model, vectorizer

def predict_severity(model, vectorizer, description):
    if model is None:
        return "UNKNOWN"
    clean = clean_text(description)
    vec   = vectorizer.transform([clean])
    return model.predict(vec)[0]