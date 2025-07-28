import unittest

from pathlib import Path
from osv_reproducer.utils.parse.log import parse_reproduce_logs_to_dict

# Global configuration for test data
LOG_FILES = {
    'OSV-2020-55.txt': {
        'impact': 'stack-buffer-overflow',
        'operation': 'WRITE',
        'size': 52545,
        'address': '0x7f2ec015cb05',
        'first_frame_function': '__asan_memcpy',
        'first_frame_module': '/src/llvm-project/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:63:3',
        'num_frames': 12
    },
    'OSV-2021-1204.txt': {
        'impact': 'heap-buffer-overflow',
        'operation': 'WRITE',
        'size': 1,
        'address': '0x5070000000e0',
        'first_frame_function': 'MqttClient_DecodePacket',
        'first_frame_module': 'mqtt_client.c',
        'num_frames': 11
    },
    'OSV-2021-1352.txt': {
        'impact': 'SEGV',
        'operation': 'WRITE',
        'size': None,
        'address': '0x000000bd00c5',
        'first_frame_function': 'MqttProps_Free',
        'first_frame_module': '(/out/wolfmqtt-fuzzer+0x256516)',
        'num_frames': 11
    },
    'OSV-2021-1358.txt': {
        'impact': 'stack-buffer-overflow',
        'operation': 'WRITE',
        'size': 1,
        'address': '0x7f6dfaf4fe30',
        'first_frame_function': 'MqttClient_DecodePacket',
        'first_frame_module': 'mqtt_client.c',
        'num_frames': 12
    },
    'OSV-2021-1361.txt': {
        'impact': 'stack-buffer-overflow',
        'operation': 'READ',
        'size': 8,
        'address': '0x7f107ca710d8',
        'first_frame_function': 'MqttClient_DecodePacket',
        'first_frame_module': 'mqtt_client.c',
        'num_frames': 12
    }
}

def read_log_file(filename):
    """Read a log file and return its contents as a list of lines."""
    log_path = Path(__file__).parent.parent / 'data' / 'logs' / filename
    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    with log_path.open(mode='r') as f:
        # Skip lines that are not part of the actual log output
        # (e.g., command execution lines at the beginning)
        lines = f.readlines()
        # Find the line that starts with "Running" which is typically the start of the actual log
        for i, line in enumerate(lines):
            if line.strip().startswith("Running"):
                return [l.strip() for l in lines[i:]]

    # If we couldn't find a good starting point, return all lines
    return [line.strip() for line in lines]


def extract_log_section(filename, start_line=None, end_line=None, include_lines=None, exclude_lines=None):
    """
    Extract a section of a log file based on various criteria.

    Args:
        filename: Name of the log file in data/logs/
        start_line: Line content to start extraction from (inclusive)
        end_line: Line content to end extraction at (exclusive)
        include_lines: List of line contents that must be included
        exclude_lines: List of line contents that must be excluded

    Returns:
        List of log lines that match the criteria
    """
    log_lines = read_log_file(filename)

    if not log_lines:
        return []

    # If no criteria specified, return all lines
    if not any([start_line, end_line, include_lines, exclude_lines]):
        return log_lines

    # Find start and end indices
    start_idx = 0
    end_idx = len(log_lines)

    if start_line:
        for i, line in enumerate(log_lines):
            if start_line in line:
                start_idx = i
                break

    if end_line:
        for i in range(start_idx, len(log_lines)):
            if end_line in log_lines[i]:
                end_idx = i
                break

    # Extract the section
    section = log_lines[start_idx:end_idx]

    # Filter based on include/exclude criteria
    if include_lines:
        section = [line for line in section if any(incl in line for incl in include_lines)]

    if exclude_lines:
        section = [line for line in section if not any(excl in line for excl in exclude_lines)]

    return section


class TestParseLog(unittest.TestCase):
    """Test cases for the parse_reproduce_logs_to_dict function."""

    def test_parse_reproduce_output_with_valid_data(self):
        """Test parsing valid reproduce output with error and stack trace."""
        # Test with each log file
        for filename, expected in LOG_FILES.items():
            with self.subTest(filename=filename):
                # Read log lines from the actual log file
                log_lines = read_log_file(filename)
                result = parse_reproduce_logs_to_dict(log_lines)

                # Check that basic fields are parsed correctly
                self.assertEqual(result.get('impact'), expected['impact'])
                self.assertEqual(result.get('operation'), expected['operation'])
                self.assertEqual(result.get('size'), expected['size'])
                self.assertEqual(result.get('address'), expected['address'])

                # Check that a stack dictionary was created
                self.assertIsInstance(result.get('stack'), dict)

                # Check that the stack has the correct number of frames
                self.assertEqual(len(result['stack']['frames']), expected['num_frames'])

                # Check the first frame
                first_frame = result['stack']['frames'][0]
                self.assertIsInstance(first_frame, dict)
                self.assertEqual(first_frame['location']['logical_locations'][0]['name'], 
                                expected['first_frame_function'])
                self.assertEqual(first_frame['module'], expected['first_frame_module'])

    def test_parse_reproduce_output_with_empty_data(self):
        """Test parsing empty log output."""
        # Use an empty list to simulate empty log data
        log_lines = []
        result = parse_reproduce_logs_to_dict(log_lines)

        # Should return an empty dict
        self.assertEqual(result, {})

    def test_parse_reproduce_output_with_no_error(self):
        """Test parsing log output with no error."""
        # Use the first log file for this test
        filename = list(LOG_FILES.keys())[0]

        # Extract only the header lines from the log file, excluding any error information
        log_lines = extract_log_section(
            filename,
            start_line="Running",
            end_line="ERROR",
            exclude_lines=["ERROR", "WRITE", "READ", "heap-buffer-overflow", "stack-buffer-overflow"]
        )

        # Add a line indicating no errors were found
        log_lines.append("No errors found.")

        result = parse_reproduce_logs_to_dict(log_lines)

        # Should return an empty dict since no error was found
        self.assertEqual(result, {})

    def test_parse_reproduce_output_with_error_but_no_stack(self):
        """Test parsing log output with error but no stack trace."""
        # Test with each log file
        for filename, expected in LOG_FILES.items():
            with self.subTest(filename=filename):
                # Extract only the error lines from the log file, excluding the stack trace
                log_lines = extract_log_section(
                    filename,
                    include_lines=["ERROR", expected['operation'], "SUMMARY"],
                    exclude_lines=["#0", "#1", "#2", "#3", "SCARINESS"]
                )

                result = parse_reproduce_logs_to_dict(log_lines)

                # Should have impact, operation, size, address but no stack
                self.assertEqual(result.get('impact'), expected['impact'])
                self.assertEqual(result.get('operation'), expected['operation'])
                self.assertEqual(result.get('size'), expected['size'])
                self.assertEqual(result.get('address'), expected['address'])
                self.assertNotIn('stack', result)


if __name__ == '__main__':
    unittest.main()
