import json

from pathlib import Path
from cement import Handler
from typing import Optional, Dict, List

# TODO: use domain models instead of OSV directly
from osvutils.types.osv import OSV
from cement.core.log import LogInterface

from ..handlers import HandlersInterface
from ..core.common.enums import ReproductionMode
from ..core.interfaces.file_provision import FileProvisionInterface
from ..core.models import ReproductionContext, OSSFuzzIssueReport, ProjectInfo, CrashInfo


def _load_json_file(file_path: Path, logger: LogInterface) -> dict:
    """Helper method to load and parse JSON files.

    Args:
        file_path: Path to the JSON file
        logger: Cement logger instance

    Returns:
        Parsed JSON data or None if loading fails
    """
    if not file_path.exists():
        logger.warning(f"No mappings file found at {file_path}")
        return {}

    try:
        with file_path.open('r') as f:
            data = json.load(f)
        logger.info(f"Loaded mappings from {file_path}")
        return data
    except json.JSONDecodeError:
        logger.warning(f"Invalid JSON format in file: {file_path}")
    except Exception as e:
        logger.warning(f"Failed to load file {file_path}: {str(e)}")

    return {}


FILE_STORE_PATHS = [
    "context", "issues", "mappings", "outputs", "projects", "records", "repositories", "snapshots", "testcases",
]


# TODO: too much responsibility (mixes local filesystem caching, remote downloads, etc.), break it into sub-handlers
class FileProvisionHandler(FileProvisionInterface, HandlersInterface, Handler):
    class Meta:
        label = 'file_provision'

    def __init__(self, base_path: Path = None, **kw):
        super().__init__(**kw)
        self.base_path = Path.home() / ".osv_reproducer" if not base_path else base_path
        self.osv_issue_ids = {}
        self.osv_timestamp_ids = {}
        self.timestamp_commit_ids = {}

    def _init_paths(self):
        # Create base and subdirectories
        for name in FILE_STORE_PATHS:
            path = self.base_path / name
            path.mkdir(exist_ok=True, parents=True)
            setattr(self, f"{name}_path", path)

        self.osv_issue_ids_path = self.mappings_path / "osv_issue_ids.json"
        self.osv_timestamp_ids_path = self.mappings_path / "osv_timestamp_ids.json"
        self.timestamp_commit_ids_path = self.mappings_path / "timestamp_commit_ids.json"

    def _setup(self, app) -> None:
        """Initialize handler by loading required mapping files."""
        super()._setup(app)
        self._init_paths()

        # Load mapping files
        self.osv_issue_ids = _load_json_file(self.osv_issue_ids_path, app.log)
        self.osv_timestamp_ids = _load_json_file(self.osv_timestamp_ids_path, app.log)
        self.timestamp_commit_ids = _load_json_file(self.timestamp_commit_ids_path, app.log)

    def get_osv_record(self, osv_id: str) -> Optional[OSV]:
        """
        Get an OSV record by ID. First checks if the record exists locally,
        and if not, fetches it from the OSV API and saves it locally.

        Args:
            osv_id: The OSV ID of the vulnerability.

        Returns:
            OSV: The vulnerability record.
        """
        try:
            record_path = self.records_path / f"{osv_id}.json"

            if record_path.exists():
                self.app.log.info(f"Loading vulnerability {osv_id} from local storage")

                with record_path.open(mode='r') as f:
                    json_dict = json.load(f)

                return OSV(**json_dict)
        except Exception as e:
            self.app.log.error(f"Error loading vulnerability {osv_id} from local storage: {str(e)}")

        return None

    def save_osv_record(self, osv: OSV) -> Optional[Path]:
        try:
            record_path = self.records_path / f"{osv.id}.json"

            self.app.log.info(f"Saving vulnerability {osv.id} to local storage")

            with record_path.open(mode='w') as f:
                # Now serialize to JSON and save
                osv_data = osv.model_dump_json(indent=4)
                f.write(osv_data)

            return record_path
        except Exception as e:
            self.app.log.warning(f"Error saving vulnerability to local storage: {str(e)}")

        return None

    def get_issue_id(self, osv_id: str) -> Optional[int]:
        # Check if the OSV ID exists in the mappings
        if osv_id in self.osv_issue_ids:
            self.app.log.info(f"Found issue ID for {osv_id} in local mappings")
            return self.osv_issue_ids[osv_id]

        return None

    def get_osv_timestamp(self, osv_id: str) -> Optional[str]:
        if osv_id in self.osv_timestamp_ids:
            self.app.log.info(f"Found timestamp for {osv_id} in local mappings")
            return self.osv_timestamp_ids[osv_id]

        return None

    def get_oss_fuzz_repo_sha(self, timestamp: str) -> Optional[str]:
        if timestamp in self.timestamp_commit_ids:
            self.app.log.info(f"Found OSS-Fuzz repo SHA for {timestamp} in local mappings")
            return self.timestamp_commit_ids[timestamp]

        return None

    def set_issue_id(self, osv_id: str, issue_id: int) -> bool:
        """
        Setter for the mappings dictionary. Updates the mappings dictionary and saves it to the file.

        Args:
            osv_id (str): The OSV ID to map.
            issue_id (str): The issue ID to map to.
        """
        self.osv_issue_ids[osv_id] = issue_id

        try:
            # Save the updated mappings
            with self.osv_issue_ids_path.open('w') as f:
                json.dump(self.osv_issue_ids, f, indent=4)

            self.app.log.info(f"Updated mappings with {osv_id} -> {issue_id}")

            return True
        except Exception as e:
            self.app.log.warning(f"Error updating mappings file: {str(e)}")

        return False

    def set_osv_timestamp(self, osv_id: str, timestamp: str) -> bool:
        self.osv_timestamp_ids[osv_id] = timestamp

        try:
            with self.osv_timestamp_ids_path.open('w') as f:
                json.dump(self.osv_timestamp_ids, f, indent=4)

            self.app.log.info(f"Updated mappings with {osv_id} -> {timestamp}")
            return True
        except Exception as e:
            self.app.log.warning(f"Error updating mappings file: {str(e)}")

        return False

    def set_oss_fuzz_repo_sha(self, timestamp: str, oss_fuzz_repo_sha: str) -> bool:
        self.timestamp_commit_ids[timestamp] = oss_fuzz_repo_sha

        try:
            # Save the updated mappings
            with self.timestamp_commit_ids_path.open('w') as f:
                json.dump(self.timestamp_commit_ids, f, indent=4)

            self.app.log.info(f"Updated mappings with {timestamp} -> {oss_fuzz_repo_sha}")
            return True
        except Exception as e:
            self.app.log.warning(f"Error updating mappings file: {str(e)}")

        return False

    def load_issue_report(self, issue_id: int) -> Optional[OSSFuzzIssueReport]:
        issue_report_path = self.issues_path / f"{issue_id}.json"

        if issue_report_path.exists():
            oss_fuzz_issue_report_dict = _load_json_file(issue_report_path, self.app.log)

            if oss_fuzz_issue_report_dict:
                return OSSFuzzIssueReport(**oss_fuzz_issue_report_dict)

        return None

    def save_issue_report(self, issue_report: OSSFuzzIssueReport) -> Path:
        issue_report_path = self.issues_path / f"{issue_report.id}.json"

        with issue_report_path.open(mode="w") as f:
            oss_fuzz_issue_report_json = issue_report.model_dump_json(indent=4)
            f.write(oss_fuzz_issue_report_json)

        return issue_report_path

    def get_testcase_path(self, testcase_id: int) -> Optional[Path]:
        testcase_path = self.testcases_path / str(testcase_id)

        # Check if the file already exists
        if testcase_path.exists():
            self.app.log.info(f"Test case file already exists at {testcase_path}")
            return testcase_path

        return None

    def get_output_path(self, osv_id: str, mode: str, file_name: str = None, mkdir: bool = False) -> Optional[Path]:
        output_path = self.outputs_path / mode / osv_id

        if mkdir:
            output_path.mkdir(parents=True, exist_ok=True)

        if file_name:
            output_file = output_path / file_name

            if output_file.exists():
                return output_file

            return None

        return output_path

    def save_testcase(self, testcase_id: int, content: bytes) -> Optional[Path]:
        testcase_path = self.testcases_path / str(testcase_id)
        try:
            with testcase_path.open(mode='wb') as f:
                f.write(content) # type: ignore[arg-type]

            self.app.log.info(f"Test case saved to {testcase_path}")
            return testcase_path
        except Exception as e:
            self.app.log.error(f"Error saving test case: {str(e)}")
            return None

    def load_context(self, osv_id: str, mode: ReproductionMode) -> Optional[ReproductionContext]:
        context_path = self.context_path / f"{osv_id}-{mode.value}.json"

        if context_path.exists():
            context_dict = _load_json_file(context_path, self.app.log)

            if context_dict:
                return ReproductionContext(**context_dict)

        return None

    def save_context(self, context: ReproductionContext) -> Path:
        context_path = self.context_path / f"{context.id}-{context.mode.value}.json"

        with context_path.open(mode="w") as f:
            json_str = context.model_dump_json(indent=4, exclude_unset=True, exclude_none=True)
            f.write(json_str)

        return context_path

    def load_snapshot(self, project_name: str, sanitizer: str, timestamp: str) -> Optional[dict]:
        snapshot_file_path = self.snapshots_path / f"{project_name}-{sanitizer}-{timestamp}.json"

        if snapshot_file_path.exists():
            self.app.log.info(f"Using cached snapshot from {snapshot_file_path}")

            return _load_json_file(snapshot_file_path, self.app.log)

        return None

    def save_snapshot(self, srcmap: dict, project_name: str, sanitizer: str, timestamp: str) -> Path:
        snapshot_file_path = self.snapshots_path / f"{project_name}-{sanitizer}-{timestamp}.json"
        snapshot_file_path.parent.mkdir(parents=True, exist_ok=True)

        with snapshot_file_path.open(mode="w") as f:
            json.dump(srcmap, f, indent=2)

        return snapshot_file_path

    def load_project_info(self, project_name: str, oss_fuzz_repo_sha: str) -> Optional[ProjectInfo]:
        try:
            project_info_path = self.projects_path / project_name / oss_fuzz_repo_sha / "project.json"

            if project_info_path.exists():
                project_info_dict = _load_json_file(project_info_path, self.app.log)

                if project_info_dict:
                    return ProjectInfo(**project_info_dict)

        except Exception as e:
            self.app.log.error(f"Error loading project info: {e}")

        return None

    def save_project_info(self, project_info: ProjectInfo) -> Optional[Path]:
        try:
            project_info_path = self.projects_path / project_info.name / project_info.oss_fuzz_repo_sha / "project.json"
            project_info_path.parent.mkdir(parents=True, exist_ok=True)

            with project_info_path.open(mode="w") as f:
                project_info_json_str = project_info.model_dump_json(indent=4)
                f.write(project_info_json_str)

                return project_info_path
        except Exception as e:
            self.app.log.error(f"Error saving project info: {e}")

        return None

    def get_project_files(self, name: str, oss_fuzz_repo_sha: str) -> Optional[Dict[str, bytes]]:
        project_files_path = self.projects_path / name / oss_fuzz_repo_sha

        if not project_files_path.exists():
            return None

        results = {}

        for file in project_files_path.iterdir():
            if file.name == "project.json":
                continue

            if file.is_file():
                results[file.name] = file.read_bytes()

        return results

    def get_project_path(self, project_name: str, oss_fuzz_repo_sha: str) -> Optional[Path]:
        project_path = self.projects_path / project_name / oss_fuzz_repo_sha

        if project_path.exists():
            return project_path

        return None

    def get_project_file_path(self, project_name: str, oss_fuzz_repo_sha: str, file_name: str) -> Optional[Path]:
        project_files_path = self.projects_path / project_name / oss_fuzz_repo_sha / file_name

        if project_files_path.exists():
            return project_files_path

        return None

    def save_project_files(self, name: str, oss_fuzz_repo_sha: str, project_files: Dict[str, bytes]) -> bool:
        project_files_path = self.projects_path / name / oss_fuzz_repo_sha
        project_files_path.mkdir(parents=True, exist_ok=True)

        try:
            for file_name, file_content in project_files.items():
                project_file_path = project_files_path / file_name

                with project_file_path.open(mode="wb") as f:
                    f.write(file_content) # type: ignore[arg-type]
            return True
        except Exception as e:
            self.app.log.error(f"Error saving project files: {e}")

        return False

    def get_repository_path(self, owner: str, repository: str, version: str, check: bool = True) -> Optional[Path]:
        repo_path = self.repositories_path / f"{owner}/{repository}/{version}"

        if not check:
            return repo_path

        if repo_path.exists():
            return repo_path

        return None

    def load_crash_info(self, osv_id: str, mode: str) -> Optional[CrashInfo]:
        crash_info_file = self.outputs_path / mode / osv_id / "crash_info.json"

        if crash_info_file.exists():
            crash_info_dict = _load_json_file(crash_info_file, self.app.log)

            if crash_info_dict:
                return CrashInfo(**crash_info_dict)

        return None

    def save_crash_info(self, osv_id: str, mode: str, crash_info: CrashInfo) -> Optional[Path]:
        crash_info_file = self.outputs_path / mode / osv_id / "crash_info.json"

        with crash_info_file.open(mode="w") as f:
            crash_info_json_str = crash_info.model_dump_json(indent=4)
            f.write(crash_info_json_str)

        return crash_info_file

    def load_runner_logs(self, osv_id: str, mode: str) -> Optional[List[str]]:
        log_file = self.outputs_path / mode / osv_id / "runner.log"

        if log_file.exists():
            with log_file.open(mode="r") as f:
                return f.readlines()

        return None

    def save_runner_logs(self, osv_id: str, mode: str, logs: List[str]):
        log_file = self.outputs_path / mode / osv_id / "runner.log"

        with log_file.open(mode="w") as f:
            f.writelines(logs)

        return log_file
