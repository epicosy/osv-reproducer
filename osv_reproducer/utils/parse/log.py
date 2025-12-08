import re
from typing import List, Dict, Any, Optional

from osv_reproducer.utils.parse.common import create_frame, create_stack_dict

MEMORY_ACCESS_PATTERN = r'(\w+) of size (\d+) at (0x[0-9a-fA-F]+) thread (T\d+)'
SIGNAL_PATTERN = r'The signal is caused by a (\w+) memory access\.'
DESCRIPTION_PATTERN = r'(\w[\w\-]+) on address (0x[0-9a-fA-F]+) at pc (0x[0-9a-fA-F]+) bp (0x[0-9a-fA-F]+) sp (0x[0-9a-fA-F]+)'
SEGV_PATTERN = r'SEGV on unknown address (0x[0-9a-fA-F]+)'
MAKE_ERROR_PATTERN = re.compile(
    r'^make:\s+\*\*\*\s+\[(?P<file>[^:\]]+):(?P<line>\d+):\s*(?P<target>[^\]]+)\]\s+Error\s+(?P<code>\d+)\s*$'
)


def find_make_error(lines: List[str]) -> Optional[int]:
    for line in lines:
        match = re.match(MAKE_ERROR_PATTERN, line)

        if match:
            match_dict = match.groupdict()
            return match_dict['code']

    return None


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

                # Check for SEGV errors which have a different format
                segv_match = re.search(SEGV_PATTERN, description_parts[-1])
                if segv_match:
                    return i, {"impact": "SEGV", "address": segv_match.group(1)}

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
        error_info['size'] = int(match.group(2))
        error_info['address'] = match.group(3)
    elif error_line.strip().startswith("=="):
        # Check for SEGV errors which have a different format
        signal_match = re.search(SIGNAL_PATTERN, error_line)
        if signal_match:
            error_info['operation'] = signal_match.group(1)
            # For SEGV errors, size is None
            error_info['size'] = None

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


def parse_stack_frame(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a stack frame line and create a frame dictionary.

    Args:
        line: Stack frame line in the format "#N address in function file" or "#N address (module)"

    Returns:
        dict: Frame dictionary or None if the line couldn't be parsed
    """
    # Check if the line starts with a frame number
    if not line.startswith("#"):
        return None

    # Extract the frame ID and address
    frame_parts = line.split(" ", 2)
    if len(frame_parts) < 2:
        return None

    frame_num = frame_parts[0]  # e.g., "#0"
    address = frame_parts[1]    # e.g., "0x55c8c1c740d8"

    # Check if the line has the " in " format
    if len(frame_parts) > 2 and " in " in line:
        parts = line.split(" in ", 1)
        frame_id = parts[0].strip()  # e.g., "#0 0x55c8c1c740d8"
        location_part = parts[1].strip()  # e.g., "MqttClient_DecodePacket mqtt_client.c"

        # Check if the location part starts with a function name followed by a module in parentheses
        if location_part.strip().endswith(")") and "(" in location_part and not location_part.strip().startswith("("):
            # This is likely a function name followed by a module in parentheses
            # Extract the function name (everything before the first open parenthesis)
            function_parts = location_part.split("(", 1)
            function = function_parts[0].strip()

            # The module is everything from the first open parenthesis to the end
            file = "(" + function_parts[1]
        # Check if the function name includes a signature (has parentheses)
        elif "(" in location_part and ")" in location_part and location_part.find("(") < location_part.find(")"):
            # Extract the function name without the signature
            function = location_part.split("(", 1)[0].strip()
            # Extract the file part which comes after the closing parenthesis and a space
            file_parts = location_part.split(")", 1)
            file = file_parts[1].strip() if len(file_parts) > 1 else ""
        else:
            # Handle the case where there's no signature
            location_parts = location_part.split(" ", 1)
            function = location_parts[0].strip()
            file = location_parts[1].strip() if len(location_parts) > 1 else ""
    else:
        # Handle the case where there's no function name (just address)
        function = ""

        # Check if there's a module part
        if len(frame_parts) > 2:
            module_part = frame_parts[2].strip()

            # Keep the module part as is, including parentheses if present
            file = module_part
        else:
            file = address

    # Create a frame dictionary using the common function
    frame = create_frame(function, file)

    # Add the address as the ID for the frame
    frame["id"] = address

    return frame


def parse_reproduce_logs_to_dict(log_lines: List[str]) -> dict:
    """
    Parse sanitizer output logs to extract error information and stack trace.

    This function parses logs from sanitizers like AddressSanitizer to extract:
    - Error description (from the line starting with ==NUMBER==ERROR)
    - Error type and details (from the next line, e.g., "WRITE of size 1 at 0x5070000000e0 thread T0")
    - Stack trace lines

    Args:
        log_lines: List of strings containing the log output

    Returns:
        dict: Dictionary containing parsed information with keys like:
            - impact: Description of the error type (e.g., "heap-buffer-overflow")
            - operation: Type of operation (e.g., "WRITE", "READ")
            - size: Size of the memory access
            - address: Memory address of the access
            - stack: Dictionary with the structure expected by CrashInfo for deserialization
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

    # Collect stack trace lines
    trace_lines, _ = collect_stack_trace(log_lines, start_idx)

    # Parse stack frames
    frames = [frame for line in trace_lines if (frame := parse_stack_frame(line))]

    # Create a stack dictionary if we have frames
    if frames:
        parsed['stack'] = create_stack_dict(frames)

    return parsed
