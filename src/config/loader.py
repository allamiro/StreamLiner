import configparser
import os

def load_config(path: str) -> dict:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")

    config = configparser.ConfigParser()
    config.read(path)

    cfg_dict = {section: dict(config[section]) for section in config.sections()}
    return cfg_dict
