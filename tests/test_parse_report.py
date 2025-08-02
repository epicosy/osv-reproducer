import unittest
from pathlib import Path

from osv_reproducer.utils.parse.report import parse_oss_fuzz_report_to_dict

# Global configuration for test data
REPORT_FILES = {
    'OSV-2017-104.txt':{
        'project': 'unrar',
        'fuzzing_engine': 'libFuzzer',
        'fuzz_target': 'unrar_fuzzer',
        'job_type': 'libfuzzer_asan_unrar',
        'platform_id': 'linux',
        'sanitizer': 'address (ASAN)',
        'severity': 'High',
        'impact': 'heap-buffer-overflow',
        'operation': 'WRITE',
        'size': 1,
        'address': '0x7f0e45e76800',
        'crash_state_functions': ['Unpack::CopyString', 'Unpack::Unpack5', 'CmdExtract::ExtractCurrentFile']
    },
    'OSV-2020-55.txt': {
        'project': 'opensc',
        'fuzzing_engine': 'libFuzzer',
        'fuzz_target': 'fuzz_pkcs15_reader',
        'job_type': 'libfuzzer_asan_opensc',
        'platform_id': 'linux',
        'sanitizer': 'address (ASAN)',
        'severity': 'High',
        'impact': 'stack-buffer-overflow',
        'operation': 'WRITE',
        'size': None,
        'address': '0x7ffe76440645',
        'crash_state_functions': ['tcos_decipher', 'sc_decipher', 'use_key']
    },
    'OSV-2021-1204.txt': {
        'project': 'wolfmqtt',
        'fuzzing_engine': 'libFuzzer',
        'fuzz_target': 'wolfmqtt-fuzzer',
        'job_type': 'libfuzzer_asan_wolfmqtt',
        'platform_id': 'linux',
        'sanitizer': 'address (ASAN)',
        'severity': 'High',
        'impact': 'heap-buffer-overflow',
        'operation': 'WRITE',
        'size': 1,
        'address': '0x607000000070',
        'crash_state_functions': ['MqttClient_DecodePacket', 'MqttClient_HandlePacket', 'MqttClient_WaitType']
    },
    'OSV-2021-1352.txt': {
        'project': 'wolfmqtt',
        'fuzzing_engine': 'libFuzzer',
        'fuzz_target': 'wolfmqtt-fuzzer',
        'job_type': 'libfuzzer_asan_wolfmqtt',
        'platform_id': 'linux',
        'sanitizer': 'address (ASAN)',
        'severity': 'Medium',
        'impact': 'unknown',
        'operation': 'READ',
        'size': None,
        'address': '0x000097b34018',
        'crash_state_functions': ['MqttProps_Free', 'MqttClient_Unsubscribe', 'wolfMQTTFuzzer::unsubscribe']
    },
    'OSV-2021-1358.txt': {
        'project': 'wolfmqtt',
        'fuzzing_engine': 'libFuzzer',
        'fuzz_target': 'wolfmqtt-fuzzer',
        'job_type': 'libfuzzer_asan_wolfmqtt',
        'platform_id': 'linux',
        'sanitizer': 'address (ASAN)',
        'severity': 'Medium',
        'impact': 'heap-buffer-overflow',
        'operation': 'READ',
        'size': 8,
        'address': '0x602000000198',
        'crash_state_functions': ['MqttClient_DecodePacket', 'MqttClient_WaitType', 'MqttClient_Ping_ex']
    },
    'OSV-2021-1361.txt': {
        'project': 'wolfmqtt',
        'fuzzing_engine': 'libFuzzer',
        'fuzz_target': 'wolfmqtt-fuzzer',
        'job_type': 'libfuzzer_asan_wolfmqtt',
        'platform_id': 'linux',
        'sanitizer': 'address (ASAN)',
        'severity': 'High',
        'impact': 'heap-buffer-overflow',
        'operation': 'WRITE',
        'size': 1,
        'address': '0x6070000001f0',
        'crash_state_functions': ['MqttClient_DecodePacket', 'MqttClient_WaitType', 'MqttClient_Subscribe']
    }
}


def read_report_file(filename):
    """Read a report file and return its contents."""
    report_path = Path(__file__).parent.parent / 'data' / 'reports' / filename
    if not report_path.exists():
        raise FileNotFoundError(f"Report file not found: {report_path}")

    with report_path.open(mode='r') as f:
        return f.read()

def modify_report_content(report_content, omit_sections=None):
    """Modify a report by omitting specified sections.

    Args:
        report_content (str): The original report content
        omit_sections (list): List of section prefixes to omit from the report

    Returns:
        str: The modified report content
    """
    if omit_sections is None:
        omit_sections = []

    # Split the report into lines
    lines = report_content.split('\n')

    # Filter out lines that start with any of the omit_sections
    filtered_lines = []
    skip_next_line = False

    for line in lines:
        # Check if we should skip this line based on previous line
        if skip_next_line:
            if line.strip() == "":  # If this is a blank line after a section we're skipping
                skip_next_line = False
            continue

        # Check if this line starts with any of the sections to omit
        should_omit = False
        for section in omit_sections:
            if line.strip().startswith(section):
                should_omit = True
                skip_next_line = True  # Skip the next line too (usually a blank line)
                break

        if not should_omit:
            filtered_lines.append(line)

    return "\n".join(filtered_lines)


class TestParseReport(unittest.TestCase):
    """Test cases for the parse_oss_fuzz_report_to_dict function."""

    def test_parse_report_with_valid_data(self):
        """Test parsing valid OSS-Fuzz reports."""
        # Test with each report file
        for filename, expected in REPORT_FILES.items():
            with self.subTest(filename=filename):
                # Read report content from the actual file
                report_content = read_report_file(filename)
                result = parse_oss_fuzz_report_to_dict(report_content)

                # Check that basic fields are parsed correctly
                self.assertEqual(result.get('project'), expected['project'])
                self.assertEqual(result.get('fuzzing_engine'), expected['fuzzing_engine'])
                self.assertEqual(result.get('fuzz_target'), expected['fuzz_target'])
                self.assertEqual(result.get('job_type'), expected['job_type'])
                self.assertEqual(result.get('platform_id'), expected['platform_id'])
                self.assertEqual(result.get('sanitizer'), expected['sanitizer'])
                self.assertEqual(result.get('severity'), expected['severity'])

                # Check that crash_info was created and has the correct fields
                self.assertIn('crash_info', result)
                crash_info = result['crash_info']
                self.assertEqual(crash_info['impact'], expected['impact'])
                self.assertEqual(crash_info['operation'], expected['operation'])
                self.assertEqual(crash_info['size'], expected['size'])
                self.assertEqual(crash_info['address'], expected['address'])

                # Check that the stack has the correct functions
                self.assertIsNotNone(crash_info['stack'])
                frames = crash_info['stack']['frames']
                self.assertEqual(len(frames), len(expected['crash_state_functions']))

                # Check each function in the stack
                for i, func_name in enumerate(expected['crash_state_functions']):
                    self.assertEqual(frames[i]['location']['logical_locations'][0]['name'], func_name)

    def test_parse_report_with_empty_data(self):
        """Test parsing empty report content."""
        # Use an empty string to simulate empty report data
        report_content = ""
        result = parse_oss_fuzz_report_to_dict(report_content)

        # Should return an empty dict
        self.assertEqual(result, {})

    def test_parse_report_with_missing_crash_info(self):
        """Test parsing report with missing crash information."""
        # Use an existing report file and remove all crash-related sections
        filename = list(REPORT_FILES.keys())[0]  # Get the first report file
        original_content = read_report_file(filename)
        report_content = modify_report_content(
            original_content, omit_sections=["Crash Type:", "Crash Address:", "Crash State:"]
        )
        result = parse_oss_fuzz_report_to_dict(report_content)

        # Should have basic fields but no crash_info
        self.assertEqual(result.get('project'), REPORT_FILES[filename]['project'])
        self.assertEqual(result.get('fuzzing_engine'), REPORT_FILES[filename]['fuzzing_engine'])
        self.assertNotIn('crash_info', result)

    def test_parse_report_with_partial_crash_info(self):
        """Test parsing report with partial crash information."""
        # Use an existing report file and remove the crash state section
        filename = list(REPORT_FILES.keys())[0]  # Get the first report file
        original_content = read_report_file(filename)
        report_content = modify_report_content(
            original_content, omit_sections=["Crash State:"]
        )
        result = parse_oss_fuzz_report_to_dict(report_content)

        # Should have basic fields but no crash_info (since stack is missing)
        self.assertEqual(result.get('project'), REPORT_FILES[filename]['project'])
        self.assertNotIn('crash_info', result)  # crash_info should not be created without stack


if __name__ == '__main__':
    unittest.main()
