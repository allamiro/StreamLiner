import argparse
from config.loader import load_config
from parsers.dummy import parse_log
from connectors.elastic import send_to_elastic

def main():
    parser = argparse.ArgumentParser(description="StreamLiner - Universal Log Parser (Community Edition)")
    parser.add_argument("--config", required=True, help="Path to streamliner.ini")
    parser.add_argument("--log", required=True, help="Log line to parse and send")
    args = parser.parse_args()

    config = load_config(args.config)
    print(f"[INFO] Loaded config: {config}")

    parsed_event = parse_log(args.log)
    print(f"[INFO] Parsed event: {parsed_event}")

    send_to_elastic(parsed_event, config)

if __name__ == "__main__":
    main()
