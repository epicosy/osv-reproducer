import re
from typing import List

MEMORY_ACCESS_PATTERN = r'(\w+) of size (\d+) at (0x[0-9a-fA-F]+) thread (T\d+)'
DESCRIPTION_PATTERN = r'(\w[\w\-]+) on address (0x[0-9a-fA-F]+) at pc (0x[0-9a-fA-F]+) bp (0x[0-9a-fA-F]+) sp (0x[0-9a-fA-F]+)'


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


def find_error_start(log_lines: List[str]) -> tuple:
    """
    Find the start line of an error in sanitizer logs and extract the description.

    Args:
        log_lines: List of strings containing the log output

    Returns:
        tuple: (start_index, description) where:
            - start_index: Index of the error line in log_lines, or -1 if not found
            - description: Error description if found, or None
    """

    for i, line in enumerate(log_lines):
        if line.strip().startswith("==") and "==ERROR" in line:
            # Extract the error description from this line
            description_parts = line.split(":")

            if len(description_parts) > 2:
                match = re.search(DESCRIPTION_PATTERN, description_parts[-1])

                if match:
                    return i, {"impact": match.group(1), "address": match.group(2)}

    return -1, None


def extract_error_info(log_lines: List[str], start_idx: int) -> dict:
    """
    Extract error information from the line following the error start line.

    Args:
        log_lines: List of strings containing the log output
        start_idx: Index of the error start line

    Returns:
        dict: Dictionary with error information (operation, size, address)
    """
    error_info = {}

    if start_idx == -1 or start_idx + 1 >= len(log_lines):
        return error_info

    error_line = log_lines[start_idx + 1]
    match = re.search(MEMORY_ACCESS_PATTERN, error_line)

    if match:
        error_info['operation'] = match.group(1)
        error_info['size'] = match.group(2)
        error_info['address'] = match.group(3)

    return error_info


def extract_scariness(log_lines: List[str], start_idx: int) -> tuple:
    """
    Extract scariness information if available.

    Args:
        log_lines: List of strings containing the log output
        start_idx: Index of the error start line

    Returns:
        tuple: (scariness_info, next_index) where:
            - scariness_info: Scariness information if found, or None
            - next_index: Index to continue parsing from
    """
    i = start_idx + 2

    if i < len(log_lines) and "SCARINESS:" in log_lines[i]:
        scariness_line = log_lines[i]
        scariness_parts = scariness_line.split(":", 1)
        scariness = scariness_parts[1].strip() if len(scariness_parts) > 1 else None
        return scariness, i + 1

    return None, i


def collect_stack_trace(log_lines: List[str], start_idx: int) -> tuple:
    """
    Collect stack trace lines from the log.

    Args:
        log_lines: List of strings containing the log output
        start_idx: Index to start collecting from

    Returns:
        tuple: (trace_lines, next_index) where:
            - trace_lines: List of stack trace lines
            - next_index: Index to continue parsing from
    """
    trace_lines = []
    i = start_idx
    main_trace_ended = False

    while i < len(log_lines) and not log_lines[i].startswith("SUMMARY:"):
        line = log_lines[i].strip()
        if line.startswith("#"):
            if not main_trace_ended:
                trace_lines.append(line)
        elif trace_lines and not line.startswith("DEDUP_TOKEN:"):
            # We've reached the end of the first stack trace
            main_trace_ended = True
        i += 1

    return trace_lines, i


def parse_reproduce_output_to_dict(log_lines: List[str]) -> dict:
    """
    Parse sanitizer output logs to extract error information and stack trace.

    This function parses logs from sanitizers like AddressSanitizer to extract:
    - Error description (from the line starting with ==NUMBER==ERROR)
    - Error type and details (from the next line, e.g., "WRITE of size 1 at 0x5070000000e0 thread T0")
    - Scariness information if available
    - Stack trace lines
    - Summary information (sanitizer, error kind, file, and function)

    Args:
        log_lines: List of strings containing the log output

    Returns:
        dict: Dictionary containing parsed information with keys like:
            - description: Description of the error
            - operation: Type of operation (e.g., "WRITE", "READ")
            - size: Size of the memory access
            - address: Memory address of the access
            - scariness: Scariness information if available
            - trace_lines: List of stack trace lines
            - sanitizer: Name of the sanitizer (e.g., "AddressSanitizer")
            - error_kind: Kind of error (e.g., "heap-buffer-overflow")
            - file: File where the error occurred
            - function: Function where the error occurred
    """
    parsed = {}

    # Find the error start line and extract description
    start_idx, info = find_error_start(log_lines)

    if start_idx == -1:
        return parsed  # No error found

    parsed.update(info)

    # Extract error information
    error_info = extract_error_info(log_lines, start_idx)
    parsed.update(error_info)

    # Extract scariness information
    # scariness, next_idx = extract_scariness(log_lines, start_idx)
    # if scariness:
    #    parsed['scariness'] = scariness

    # Collect stack trace lines
    trace_lines, _ = collect_stack_trace(log_lines, start_idx)
    parsed['stack_trace'] = trace_lines

    if trace_lines:
        _, location = trace_lines[0].split(" in ")
        parsed['function'], parsed['file'] = location.split(" ")

    return parsed
