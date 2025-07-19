def parse_key_value_string(key_value_string: str) -> dict:
    """
    Parse a string in the format "KEY1:VALUE1,KEY2:VALUE2" into a dictionary.

    Args:
        key_value_string: String in the format "KEY1:VALUE1,KEY2:VALUE2".

    Returns:
        dict: Dictionary with the parsed key-value pairs.
    """
    if not key_value_string:
        return {}

    result = {}
    pairs = key_value_string.split('|')

    for pair in pairs:
        if ':' in pair:
            key, value = pair.split(':', 1)  # Split on first occurrence of ':'
            result[key.strip()] = value.strip()

    return result
