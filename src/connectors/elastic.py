def send_to_elastic(event: dict, config: dict):
    """
    Dummy function to simulate sending to Elastic/OpenSearch.
    Currently just prints to console.
    """
    elastic_cfg = config.get("output.elastic", {})
    print(f"[INFO] Sending to Elastic index '{elastic_cfg.get('index', 'default')}' -> {event}")
