import json


def parse_json_line(raw_line: str) -> dict:
    raw_line = raw_line.strip()
    if not raw_line:
        return {"quarantine_reason": "empty_line"}
    try:
        return json.loads(raw_line)
    except json.JSONDecodeError:
        return {"quarantine_reason": "invalid_json"}


def read_source_file(path: str):
    """Yields (line_number, parsed_dict_or_quarantine_dict) for every line
    in a JSONL file. line_number is 1-indexed, matching a text editor.
    Every line in the file is yielded exactly once - nothing is silently
    dropped, unlike DuckDB's ignore_errors=true."""
    with open(path, "r", encoding="utf-8") as f:
        for line_number, raw_line in enumerate(f, start=1):
            parsed = parse_json_line(raw_line)
            yield line_number, parsed
