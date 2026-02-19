import json
import os

CONFIG_FILE = "config.json"

DEFAULT_CONFIG = {
    "eula_accepted": False,
    "virustotal_api_key": "",
    "yara_rules_path": "resources/rules",
    "theme": "light"
}

def load_config():
    if not os.path.exists(CONFIG_FILE):
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG
    
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return DEFAULT_CONFIG

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)
