import re
from typing import Dict, Any, Optional, List

from osv_reproducer.utils.parse.common import create_frame, create_stack_dict


def parse_section(section: str) -> Dict[str, str]:
    """
    Parse a section of text into a dictionary of key-value pairs.

    Args:
        section: Section text with key-value pairs separated by ': '

    Returns:
        Dictionary of parsed key-value pairs
    """
    parsed = {}

    for line in section.split('\n'):
        if not line:
            continue

        key, value = line.split(': ')
        key = key.lower().replace(" ", "_")
        parsed[key] = value

    return parsed


def parse_crash_type(crash_type: str) -> Dict[str, Any]:
    """
    Parse the crash type string to extract impact, operation, and size.

    Args:
        crash_type: String in the format "Impact OPERATION SIZE" or "Impact OPERATION"

    Returns:
        dict: Dictionary with impact, operation, and size
    """
    result = {}

    # Extract impact (e.g., "Heap-buffer-overflow")
    impact_match = re.match(r'([A-Za-z\-]+)', crash_type)
    if impact_match:
        result['impact'] = impact_match.group(1).lower()

    # Extract operation and size (e.g., "READ 8")
    op_size_match = re.search(r'([A-Z]+) (\d+)', crash_type)
    if op_size_match:
        result['operation'] = op_size_match.group(1)
        result['size'] = int(op_size_match.group(2))
    else:
        # Check for the {*} placeholder which means size unknown (set to None)
        op_placeholder_match = re.search(r'([A-Z]+) \{\*\}', crash_type)
        if op_placeholder_match:
            result['operation'] = op_placeholder_match.group(1)
            result['size'] = None
        else:
            # Extract operation only (e.g., "READ" in "UNKNOWN READ")
            op_match = re.search(r'([A-Z]+)$', crash_type)
            if op_match:
                result['operation'] = op_match.group(1)
                result['size'] = None

    return result


def create_stack_from_state(crash_state: str) -> Optional[Dict[str, Any]]:
    """
    Create a stack dictionary from the crash state.

    Args:
        crash_state: String with function names separated by commas

    Returns:
        Dict: Dictionary representing a stack with frames
    """
    if not crash_state:
        return None

    # Split the crash state into function names
    functions = [func.strip() for func in crash_state.split(',')]

    # Create frames for each function
    frames = []
    for func in functions:
        if not func:
            continue

        frames.append(create_frame(func, ""))

    if not frames:
        return None

    # Create and return a dictionary representing the stack
    return create_stack_dict(frames)


def preprocess_report_text(text: str) -> str:
    """
    Preprocess the report text to standardize format.

    Args:
        text: Raw report text

    Returns:
        Preprocessed text
    """
    text_fmt = text.replace("\n  \n", "\n\n")
    text_fmt = text_fmt.replace("Recommended Security Severity: ", "Severity: ")
    text_fmt = text_fmt.replace("Regressed: ", "Regressed url: ")
    text_fmt = text_fmt.replace("Crash Revision: ", "Regressed url: ")
    text_fmt = text_fmt.replace("Reproducer Testcase: ", "Testcase url: ")
    return text_fmt


def process_sections(sections: List[str]) -> Dict[str, str]:
    """
    Process report sections into a dictionary.

    Args:
        sections: List of report sections

    Returns:
        Dictionary of parsed sections
    """
    parsed = {}

    # Skip the first section (usually URL)
    for section in sections[1:]:
        if section.startswith('Crash'):
            section = section.replace(":\n  ", ": ")
            section = section.replace("\n  ", ", ")

        parsed_section = parse_section(section)
        parsed.update(parsed_section)

    return parsed


def extract_crash_info(parsed: Dict[str, str]) -> Dict[str, Any]:
    """
    Extract crash information from parsed report data.

    Args:
        parsed: Dictionary of parsed report data

    Returns:
        Dictionary with crash information
    """
    crash_info = {}

    # Parse crash type
    if 'crash_type' in parsed:
        crash_info.update(parse_crash_type(parsed['crash_type']))

    # Add crash address
    if 'crash_address' in parsed:
        crash_info['address'] = parsed['crash_address']

    # Create stack from crash state
    if 'crash_state' in parsed:
        stack = create_stack_from_state(parsed['crash_state'])
        if stack:
            crash_info['stack'] = stack

    return crash_info


def parse_oss_fuzz_report_to_dict(text: str) -> Dict[str, Any]:
    """
    Parse an OSS-Fuzz report into a dictionary.

    Args:
        text: The report text

    Returns:
        dict: Dictionary with parsed report data
    """
    if not text:
        return {}

    # Preprocess the text
    text_fmt = preprocess_report_text(text)

    # Split into sections
    sections = text_fmt.split('\n\n')

    # Process sections
    parsed = process_sections(sections)

    # Normalize old field names
    if 'fuzzer' in parsed and 'fuzzing_engine' not in parsed:
        # the split is for cases such as 'libFuzzer_unrar_fuzzer'
        parsed['fuzzing_engine'] = parsed.pop('fuzzer').split("_")[0]

    if 'fuzz_target_binary' in parsed and 'fuzz_target' not in parsed:
        parsed['fuzz_target'] = parsed.pop('fuzz_target_binary')

    if 'sanitizer' in parsed:
        parsed['sanitizer'] = parsed['sanitizer'].lower().split(" ")[0]

    # Extract crash info
    crash_info = extract_crash_info(parsed)

    # Add crash_info to parsed if we have required fields
    if crash_info and 'impact' in crash_info and 'stack' in crash_info:
        parsed['crash_info'] = crash_info

    # Remove old crash fields
    # TODO: improve this by performing the conversion before hand
    for field in ['crash_type', 'crash_address', 'crash_state']:
        if field in parsed:
            del parsed[field]

    return parsed
