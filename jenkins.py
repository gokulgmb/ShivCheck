import requests
import mimetypes
import json
import time 
file_path = "/tmp/securestore/Doom_iOS.ipa"
url = "http://192.168.0.26:9000/bmb-upload/"
mime_type, encoding = mimetypes.guess_type(file_path)

if mime_type is None:
    mime_type = "application/octet-stream"

# First POST request: Upload file
with open(file_path, "rb") as file:
    files = {"file": ("Doom_iOS.ipa", file, mime_type)}
    headers = {
        "accept": "application/json"
    }
    response = requests.post(url, files=files, headers=headers)
    print(f"Response Status Code: {response.status_code}")    
    response_data = json.loads(response.text) 
    
    sha256 = response_data.get("Upload sucessful SHA256 hash is ", "").strip()
    filename = response_data.get("Upload sucessful file name is ", "").strip()

    if sha256 and filename:
        print(f"SHA256={sha256}")
        print(f"FILENAME={filename}")
    else:
        print(response_data)

    if sha256 and filename:
        scan_url = f"http://192.168.0.26:9000/scan?hash={sha256}&name={filename}"
        scan_headers = {
            "accept": "application/json"
        }
        scan_response = requests.post(scan_url, headers=scan_headers, data="")
        print(f"Scan Response Status Code: {scan_response.status_code}")
        print(f"Scan Response Text: {scan_response.text}")
        
        print("intiating time delay ...........")
        time.sleep(60)
        print("after time delay")
        analysis_url = f"http://192.168.0.26:9000/analysis?hash={sha256}&name={filename}"
        analysis_headers = {
            "accept": "application/json"
        }
        analysis_response = requests.post(analysis_url, headers=analysis_headers, data="")
        print(f"Analysis Response Status Code: {analysis_response.status_code}")
        print(f"Analysis Response Text: {analysis_response.text}")
    else:
        print("Missing SHA256 or filename, not triggering scan.")

