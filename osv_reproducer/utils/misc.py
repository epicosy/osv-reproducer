
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


def parse_section(section):
    parsed = {}

    for line in section.split('\n'):
        if not line:
            continue

        key, value = line.split(': ')
        key = key.lower().replace(" ", "_")
        parsed[key] = value

    return parsed

def parse_oss_fuzz_report_to_dict(text: str):
    parsed = {}
    text_fmt = text.replace("\n  \n", "\n\n")
    text_fmt = text_fmt.replace("Recommended Security Severity: ", "Severity: ")
    text_fmt = text_fmt.replace("Regressed: ", "Regressed url: ")
    text_fmt = text_fmt.replace("Reproducer Testcase: ", "Testcase url: ")
    sections = text_fmt.split('\n\n')

    for section in sections[1:]:
        if section.startswith('Crash'):
            section = section.replace(":\n  ", ": ")
            section = section.replace("\n  ", ", ")

        parsed_section = parse_section(section)
        parsed.update(parsed_section)

    return parsed
