from fastapi import FastAPI, UploadFile, File
from pydantic import BaseModel
import joblib
import csv
from datetime import datetime
import requests
import hashlib
from pypdf import PdfReader
import io
from PIL import Image, ExifTags

app = FastAPI()

# Load the AI Brain
model = joblib.load("phishing_model.pkl")

# 1. Add a Logging Function
def log_threat(content, status, threat_type):
    with open("scan_logs.csv", "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        # Columns: Timestamp, Content Checked, Status, Threat Type
        writer.writerow([datetime.now().strftime("%H:%M:%S"), content[:30], status, threat_type])

# Helper function to convert GPS coordinates to degrees
def get_decimal_from_dms(dms, ref):
    degrees = dms[0]
    minutes = dms[1]
    seconds = dms[2]
    decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
    if ref in ['S', 'W']:
        decimal = -decimal
    return decimal

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

# --- FEATURE 4: SCAN PDF FILES ---
@app.post("/scan-pdf")
async def scan_pdf(file: UploadFile = File(...)):
    try:
        # 1. Read the file into memory
        contents = await file.read()
        pdf_file = io.BytesIO(contents)
        
        # 2. Extract Text from PDF
        reader = PdfReader(pdf_file)
        extracted_text = ""
        for page in reader.pages:
            text = page.extract_text()
            if text:
                extracted_text += text + " "
        
        # 3. If PDF is empty (scanned image), warn user
        if len(extracted_text.strip()) < 5:
            return {
                "status": "WARNING", 
                "message": "No text found. This might be an image-only PDF (requires OCR)."
            }

        # 4. Use your existing AI Model to check the text
        # (We reuse the predict_phishing function you already have!)
        prediction = model.predict([extracted_text])[0]
        probability = model.predict_proba([extracted_text])[0][1] * 100
        
        if prediction == 1:
            log_threat(f"PDF: {file.filename[:30]}...", "DANGER", "Phishing PDF")
            return {
                "status": "DANGER", 
                "message": f"Malicious Content Detected in PDF.\nConfidence: {probability:.1f}%"
            }
        else:
            log_threat(f"PDF: {file.filename[:30]}...", "SAFE", "Clean PDF")
            return {
                "status": "SAFE", 
                "message": "PDF Content Analysis: Clean."
            }

    except Exception as e:
        return {"status": "ERROR", "message": f"Failed to parse PDF: {str(e)}"}

# --- FEATURE 5: IMAGE FORENSICS (Privacy Threat Detection) ---
@app.post("/scan-image-forensics")
async def scan_image_forensics(file: UploadFile = File(...)):
    try:
        # 1. Open Image
        image_data = await file.read()
        image = Image.open(io.BytesIO(image_data))
        
        # 2. Extract EXIF Data (Metadata)
        exif_data = image._getexif()
        result = {
            "status": "SAFE",
            "message": "No hidden metadata found.",
            "device": "Unknown",
            "location": None
        }

        if not exif_data:
            return result

        # 3. Analyze Tags
        threat_level = "SAFE"
        warnings = []
        
        for tag, value in exif_data.items():
            tag_name = ExifTags.TAGS.get(tag, tag)
            
            # Check for Camera Model (Privacy Leak)
            if tag_name == 'Model':
                result['device'] = str(value)
                warnings.append(f"Device Model Exposed: {value}")

            # Check for GPS Info (Major Privacy Threat)
            if tag_name == 'GPSInfo':
                threat_level = "PRIVACY_RISK"
                warnings.append("⚠️ GPS GEOLOCATION FOUND! Your exact location is embedded in this file.")
                
                # (Optional) Attempt to parse coordinates here
                result['location'] = "Embedded"

        if threat_level == "PRIVACY_RISK":
            result['status'] = "DANGER"
            result['message'] = "\n".join(warnings)
            log_threat(f"Image: {file.filename[:30]}...", "DANGER", "Privacy Risk - GPS")
        elif warnings:
            result['status'] = "WARNING"
            result['message'] = "\n".join(warnings)
            log_threat(f"Image: {file.filename[:30]}...", "WARNING", "Privacy Risk - Metadata")
        else:
            log_threat(f"Image: {file.filename[:30]}...", "SAFE", "No Privacy Threats")

        return result

    except Exception as e:
        return {"status": "ERROR", "message": f"Forensics failed: {str(e)}"}