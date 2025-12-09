from ..core.exc import VerifierError
from ..core.common.enums import ReproductionMode
from ..core.interfaces import FileProvisionInterface
from ..core.models import CrashInfo, OSSFuzzIssueReport


def _check_basic_fields(
        issue_report: OSSFuzzIssueReport, crash_info: CrashInfo, check_size: bool = False, check_address: bool = False
):
    # Check impact
    if crash_info.impact != issue_report.crash_info.impact:
        raise VerifierError(f"Impact mismatch: {crash_info.impact} != {issue_report.crash_info.impact}")

    # Check operation
    if crash_info.operation != issue_report.crash_info.operation:
        raise VerifierError(f"Operation mismatch: {crash_info.operation} != {issue_report.crash_info.operation}")

    # Check size
    if check_size and issue_report.crash_info.size and crash_info.size != issue_report.crash_info.size:
        raise VerifierError(f"Size mismatch: {crash_info.size} != {issue_report.crash_info.size}")

    # Check address
    if check_address and crash_info.address != issue_report.crash_info.address:
        raise VerifierError(f"Address mismatch: {crash_info.address} != {issue_report.crash_info.address}")


def _compute_stack_shift(issue_report: OSSFuzzIssueReport, crash_info: CrashInfo,):
    # Check if we need to shift the crash_info stack frames
    # This handles cases where the first frame could be a sanitizer function (like __asan_memcpy)
    shift = 0

    if len(crash_info.stack.frames) > 1:
        report_first_frame = issue_report.crash_info.stack.frames[0].location.logical_locations[0].name
        crash_first_frame = crash_info.stack.frames[0].location.logical_locations[0].name

        if report_first_frame != crash_first_frame:
            # Try to find a matching frame by shifting through the crash frames
            for potential_shift in range(1, len(crash_info.stack.frames)):
                crash_frame = crash_info.stack.frames[potential_shift].location.logical_locations[0].name

                if report_first_frame == crash_frame:
                    print(f"First frame did not match, shifting stack frames by {potential_shift}")
                    return potential_shift

            raise VerifierError("No matching stack frames found after shifting through all frames")

    return shift


def _check_stack_frames(
        issue_report: OSSFuzzIssueReport, crash_info: CrashInfo, shift: int, min_match: int = 1
) -> list:
    # Check stack frames
    report_frames_count = len(issue_report.crash_info.stack.frames)

    # Check if we have at least one frame to compare
    if report_frames_count == 0 or len(crash_info.stack.frames) == 0:
        raise VerifierError("No stack frames to compare")

    matched_frames = []

    # Compare stack frames (only as many as in the OSSFuzzIssueReport)
    for i in range(min(report_frames_count, len(crash_info.stack.frames) - shift)):
        report_frame_name = issue_report.crash_info.stack.frames[i].location.logical_locations[0].name
        crash_frame_name = crash_info.stack.frames[i + shift].location.logical_locations[0].name

        if report_frame_name == crash_frame_name:
            matched_frames.append(report_frame_name)

    if len(matched_frames) < min_match:
        raise VerifierError(f"Not enough matching stack frames found: {matched_frames}")

    return matched_frames


class VerifierService:
    def __init__(self, file_provision_handler: FileProvisionInterface):
        self.file_provision_handler = file_provision_handler

    def __call__(self, osv_id: str, mode: ReproductionMode):
        context = self.file_provision_handler.load_context(osv_id, mode)

        if not context:
            raise VerifierError(f"Context for OSV {osv_id} in mode {mode.value} not found")

        crash_info = self.file_provision_handler.load_crash_info(osv_id, context.mode.value)

        if crash_info:
            if mode == ReproductionMode.FIX:
                raise VerifierError(f"{context.id} patch did not address the crash:\n{crash_info}")
            else:
                _check_basic_fields(context.issue_report, crash_info)
                shift = _compute_stack_shift(context.issue_report, crash_info)
                _check_stack_frames(context.issue_report, crash_info, shift)
        else:
            if mode == ReproductionMode.CRASH:
                raise VerifierError(f"Could not reproduce crash for {context.id}")
            if not self.file_provision_handler.load_runner_logs(osv_id, context.mode.value):
                raise VerifierError(f"Could not find runner logs for {context.id} {context.mode.value}")

        return True
