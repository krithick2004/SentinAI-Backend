from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import csv
from datetime import datetime
import requests
import hashlib

app = FastAPI()

# Load the AI Brain
model = joblib.load("phishing_model.pkl")

# 1. Add a Logging Function
def log_threat(content, status, threat_type):
    with open("scan_logs.csv", "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        # Columns: Timestamp, Content Checked, Status, Threat Type
        writer.writerow([datetime.now().strftime("%H:%M:%S"), content[:30], status, threat_type])

# Define Data Structure
class TextData(BaseModel):
    content: str

class FileData(BaseModel):
    file_hash: str

@app.get("/")
def home():
    return {"status": "SentinAI Server Running"}

# --- FEATURE 1: PREVENT SOCIAL ENGINEERING ---
@app.post("/scan-text")
def scan_text(data: TextData):
    prediction = model.predict([data.content])[0]
    
    # Custom Keywords for extra security
    keywords = ["password", "bank", "urgent", "verify", "lottery"]
    flagged_keywords = [word for word in keywords if word in data.content.lower()]

    if prediction == 1 or len(flagged_keywords) > 0:
        # LOG IT AS DANGER
        log_threat(data.content, "DANGER", "Phishing")
        return {
            "status": "DANGER",
            "message": "Phishing/Social Engineering Detected!",
            "triggers": flagged_keywords
        }
    
    # LOG IT AS SAFE
    log_threat(data.content, "SAFE", "Clean")
    return {"status": "SAFE", "message": "Content looks clean."}

# --- FEATURE 2: PREVENT MALWARE (Real VirusTotal Integration) ---
@app.post("/scan-file")
def scan_file(data: FileData):
    # 1. Get the Hash from the mobile app
    file_hash = data.file_hash
    
    # 2. Ask VirusTotal: "Is this hash bad?"
    api_key = "f22885994c740f889a6791c5ecae1db926830063720c4c46d9dc4762379bd131"
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        # VirusTotal knows this file!
        stats = response.json()['data']['attributes']['last_analysis_stats']
        malicious_count = stats['malicious']
        
        if malicious_count > 0:
            log_threat(f"File: {file_hash[:10]}...", "DANGER", "Malware")
            return {
                "status": "DANGER", 
                "message": f"DANGER: Detected by {malicious_count} antivirus engines!",
                "data": stats
            }
        else:
            log_threat(f"File: {file_hash[:10]}...", "SAFE", "Clean File")
            return {"status": "SAFE", "message": "File is Clean."}
            
    elif response.status_code == 404:
        # File is new/unknown to VirusTotal
        log_threat(f"File: {file_hash[:10]}...", "WARNING", "Unknown File")
        return {"status": "WARNING", "message": "Unknown file. Proceed with caution."}
    
    else:
        return {"status": "ERROR", "message": "Could not connect to Scanner."}

# --- FEATURE 3: SCAN URL (Download & Analyze) ---
@app.post("/scan-url")
def scan_url_endpoint(data: TextData):
    target_url = data.content
    
    try:
        # 1. Server downloads the file (Safely in RAM)
        print(f"Downloading file from: {target_url}")
        response = requests.get(target_url, stream=True, timeout=30)
        
        # 2. Calculate Hash while downloading (Don't save to disk)
        sha256_hash = hashlib.sha256()
        for chunk in response.iter_content(chunk_size=4096):
            if chunk:
                sha256_hash.update(chunk)
                
        file_hash = sha256_hash.hexdigest()
        
        # 3. Check VirusTotal using the existing logic
        api_key = "f22885994c740f889a6791c5ecae1db926830063720c4c46d9dc4762379bd131"
        vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": api_key}

        vt_response = requests.get(vt_url, headers=headers)

        if vt_response.status_code == 200:
            stats = vt_response.json()['data']['attributes']['last_analysis_stats']
            malicious_count = stats['malicious']
            
            if malicious_count > 0:
                log_threat(f"URL: {target_url[:30]}...", "DANGER", "Malware URL")
                return {
                    "status": "DANGER", 
                    "message": f"DANGER: Detected by {malicious_count} antivirus engines!",
                    "hash": file_hash,
                    "data": stats
                }
            else:
                log_threat(f"URL: {target_url[:30]}...", "SAFE", "Clean URL")
                return {"status": "SAFE", "message": "Link analyzed. File hash clean.", "hash": file_hash}
                
        elif vt_response.status_code == 404:
            log_threat(f"URL: {target_url[:30]}...", "WARNING", "Unknown URL")
            return {"status": "WARNING", "message": "Unknown file. Proceed with caution.", "hash": file_hash}
        else:
            return {"status": "ERROR", "message": "Could not verify with VirusTotal."}
        
    except Exception as e:
        log_threat(f"URL: {target_url[:30]}...", "ERROR", "URL Scan Failed")
        return {"status": "ERROR", "message": f"Could not access link: {str(e)}"}