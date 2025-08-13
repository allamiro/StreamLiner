def parse_log(log_line: str) -> dict:
    """
    Very basic parser: just wraps the line in a dict.
    Later you can replace this with schema mapping (CEE/ECS/CLS).
    """
    return {
        "message": log_line.strip(),
        "length": len(log_line),
        "source": "dummy-parser"
    }
