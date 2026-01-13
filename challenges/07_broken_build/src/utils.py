import json
import os

def load_config():
    # Helper to load config
    path = "/app/config.json"
    if not os.path.exists(path):
        raise FileNotFoundError("Config missing!")
    with open(path) as f:
        return json.load(f)
