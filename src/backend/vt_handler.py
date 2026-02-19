import requests
import hashlib
import os
import time

class VirusTotalHandler:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"

    def scan_file_hash(self, file_hash):
        if not self.api_key:
            return {"error": "No API Key"}

        headers = {
            "x-apikey": self.api_key
        }
        
        try:
            response = requests.get(f"{self.base_url}/files/{file_hash}", headers=headers)
            if response.status_code == 200:
                data = response.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                return {
                    "hash": file_hash,
                    "malicious": stats["malicious"],
                    "suspicious": stats["suspicious"],
                    "harmless": stats["harmless"],
                    "link": f"https://www.virustotal.com/gui/file/{file_hash}"
                }
            elif response.status_code == 404:
                return {"hash": file_hash, "result": "Unknown (Not in VT)"}
            else:
                return {"error": f"API Error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def calculate_hash(file_path):
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return None
