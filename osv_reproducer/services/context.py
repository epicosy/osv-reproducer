from typing import Optional, Dict
from osvutils.types.osv import OSV
from datetime import datetime, timedelta

from ..core.exc import ContextError
from ..core.common.enums import ReproductionMode
from ..utils.parse.dockerfile import parse_mount_sources
from ..core.models import ReproductionContext, OSSFuzzIssueReport, ProjectInfo
from ..core.interfaces import OSVInterface, OSSFuzzInterface, FileProvisionInterface, GCSInterface, GithubInterface


# TODO: too many things happening here, maybe the project related parts should be moved to a separate class
class ContextService:
    def __init__(
            self, file_provision_handler: FileProvisionInterface, gcs_handler: GCSInterface,
            github_handler: GithubInterface, oss_fuzz_handler: OSSFuzzInterface, osv_handler: OSVInterface
    ):
        self.file_provision_handler = file_provision_handler
        self.gcs_handler = gcs_handler
        self.github_handler = github_handler
        self.oss_fuzz_handler = oss_fuzz_handler
        self.osv_handler = osv_handler

    def _get_osv_record(self, osv_id: str) -> OSV:
        osv_record = self.file_provision_handler.get_osv_record(osv_id)

        if not osv_record:
            osv_record = self.osv_handler.fetch_vulnerability(osv_id)

            if not osv_record:
                raise ContextError(f"Could not fetch OSV record for {osv_id}")

            self.file_provision_handler.save_osv_record(osv_record)

        return osv_record

    def _get_issue_id(self, osv_record: OSV) -> Optional[int]:
        issue_id = self.file_provision_handler.get_issue_id(osv_record.id)

        if not issue_id:
            # If not found in mappings, fetch from references
            for ref in osv_record.references:
                _, issue_id = self.oss_fuzz_handler.fetch_issue_id(ref.url)

                if issue_id:
                    if not self.file_provision_handler.set_issue_id(osv_record.id, issue_id):
                        raise ContextError(f"Could not save issue ID for {osv_record.id}")
                    break

            if not issue_id:
                raise ContextError(f"Could not find an OSS-Fuzz Issue Report for {osv_record.id}")

        return issue_id

    def _get_issue_report(self, issue_id: int) -> OSSFuzzIssueReport:
        issue_report = self.file_provision_handler.load_issue_report(issue_id)

        if not issue_report:
            issue_report = self.oss_fuzz_handler.fetch_issue_report(issue_id)

            if not issue_report:
                raise ContextError(f"Could not fetch OSS-Fuzz Issue Report for {issue_id}")

            self.file_provision_handler.save_issue_report(issue_report)

        return issue_report

    def _check_testcase(self, issue_report: OSSFuzzIssueReport):
        if not self.file_provision_handler.get_testcase_path(issue_report.testcase_id):
            testcase = self.oss_fuzz_handler.fetch_test_case_content(issue_report.testcase_url)

            if not testcase:
                raise ContextError(f"Could not fetch test case content for {issue_report.testcase_url}")

            if not self.file_provision_handler.save_testcase(issue_report.testcase_id, testcase):
                raise ContextError(f"Could not save test case content for {issue_report.testcase_id}")

    def _get_snapshot(self, osv_id: str, timestamp: str, issue_report: OSSFuzzIssueReport) -> dict:
        snapshot = self.file_provision_handler.load_snapshot(
            project_name=issue_report.project, sanitizer=issue_report.sanitizer, timestamp=timestamp
        )

        if not snapshot:
            snapshot = self.gcs_handler.fetch_snapshot_by_timestamp(
                project_name=issue_report.project, sanitizer=issue_report.sanitizer, timestamp=timestamp
            )

            if not snapshot:
                raise ContextError(
                    f"Could not get {issue_report.project}-{issue_report.sanitizer}-{timestamp} snapshot")

            self.file_provision_handler.save_snapshot(
                snapshot, issue_report.project, issue_report.sanitizer, timestamp
            )
            self.file_provision_handler.set_osv_timestamp(osv_id, timestamp)

        return snapshot

    def _get_oss_fuzz_repo_sha(self, timestamp: str):
        oss_fuzz_repo_sha = self.file_provision_handler.get_oss_fuzz_repo_sha(timestamp)

        if not oss_fuzz_repo_sha:
            report_date = datetime.strptime(timestamp, "%Y%m%d%H%M")
            oss_fuzz_repo_sha = self.github_handler.find_oss_fuzz_repo_commit(report_date)

            if not oss_fuzz_repo_sha:
                raise ContextError(f"Could not find OSS-Fuzz repository commit at timestamp {timestamp}")

            if not self.file_provision_handler.set_oss_fuzz_repo_sha(timestamp, oss_fuzz_repo_sha):
                raise ContextError(f"Could not save OSS-Fuzz repository commit at timestamp {timestamp}")

        return oss_fuzz_repo_sha

    def _get_project_info(self, project_name: str, oss_fuzz_repo_sha: str) -> ProjectInfo:
        project_info = self.file_provision_handler.load_project_info(project_name, oss_fuzz_repo_sha)

        if not project_info:
            project_info = self.github_handler.fetch_project_info(project_name, oss_fuzz_repo_sha)

            if not project_info:
                raise ContextError(f"Could not fetch project info for {project_name}")

            if not self.file_provision_handler.save_project_info(project_info):
                raise ContextError(f"Could not save project info for {project_info.name}")

        return project_info

    def _get_project_files(self, project_name: str, oss_fuzz_repo_sha: str) -> Dict[str, bytes]:
        project_files = self.file_provision_handler.get_project_files(project_name, oss_fuzz_repo_sha)

        if not project_files:
            project_files = self.github_handler.fetch_project_files(project_name, oss_fuzz_repo_sha)

            if not project_files:
                raise ContextError(f"Could not fetch project files for {project_name}")

            # Save project files
            if not self.file_provision_handler.save_project_files(
                    project_name, oss_fuzz_repo_sha=oss_fuzz_repo_sha, project_files=project_files
            ):
                raise ContextError(f"Could not save project files for {project_name}")

        return project_files

    def _init_repositories(self, snapshot: dict) -> dict:
        # TODO: maybe the mapping should be done in the snapshot itself
        repositories = {}

        for path, _values in snapshot.items():
            if _values["type"] != "git":
                # TODO: support other types of repositories
                print(f"Unsupported host type: {_values['type']} for {path}")
                continue

            owner, repo = self.github_handler.check_repo_url(_values["url"])

            if not owner or not repo:
                print(f"Invalid repository URL: {_values['url']} for {path}.")
                continue

            repositories[path] = {
                "owner": owner,
                "repository": repo,
                "version": _values["rev"]
            }

            repo_path = self.file_provision_handler.get_repository_path(
                owner=owner, repository=repo, version=_values["rev"], check=False
            )

            if not self.github_handler.clone_repository(
                    repo_url=_values["url"], commit=_values["rev"], to_path=repo_path
            ):
                raise ContextError(f"Could not clone repository {_values['url']} at commit {_values['rev']}")

        if not repositories:
            raise ContextError("No valid repositories found in the snapshot")

        return repositories

    def __call__(self, osv_id: str, mode: ReproductionMode):
        context = self.file_provision_handler.load_context(osv_id, mode)

        if context:
            return True

        osv_record = self._get_osv_record(osv_id)
        # TODO: find a way to select the correct project if there are multiple
        project_ranges = self.osv_handler.get_project_ranges(osv_record)

        if not project_ranges:
            raise ContextError(f"No project ranges found for {osv_id}")

        issue_id = self._get_issue_id(osv_record)
        issue_report = self._get_issue_report(issue_id)

        self._check_testcase(issue_report)

        timestamp = self.file_provision_handler.get_osv_timestamp(osv_id)

        if timestamp:
            snapshot = self._get_snapshot(osv_id, timestamp, issue_report)
        else:
            if mode == ReproductionMode.FIX:
                start, end = self.github_handler.get_fix_date_range(project_ranges)
                end += timedelta(hours=6) # considering the max daily build rate of four, one each 6 hours
            else:
                start, end = issue_report.range

            if not start or not end:
                raise ContextError(f"Could not find a valid reproduction date range for {osv_id}")

            timestamp, snapshot = self.gcs_handler.fetch_snapshot_by_range(
                issue_report.project, issue_report.sanitizer, start_timestamp=start, end_timestamp=end
            )

            if not snapshot:
                raise ContextError(f"Could not get {issue_report.project}-{issue_report.sanitizer}-{timestamp} snapshot")

            self.file_provision_handler.save_snapshot(snapshot, issue_report.project, issue_report.sanitizer, timestamp)
            self.file_provision_handler.set_osv_timestamp(osv_id, timestamp)

        oss_fuzz_repo_sha = self._get_oss_fuzz_repo_sha(timestamp)
        project_info = self._get_project_info(issue_report.project, oss_fuzz_repo_sha)
        project_files = self._get_project_files(issue_report.project, oss_fuzz_repo_sha)

        if not "Dockerfile" in project_files:
            raise ContextError(f"Dockerfile not found for {issue_report.project}")

        dockerfile_lines = project_files["Dockerfile"].decode("utf-8").splitlines()
        downloadable_files, mount_files = parse_mount_sources(dockerfile_lines)
        build_context_files = {}

        for mount_file, mount_path in mount_files.items():
            if mount_file not in project_files:
                raise ContextError(f"Mount file {mount_file} not found in project files")

            build_context_files[mount_file] = mount_path

        repositories = self._init_repositories(snapshot)

        context = ReproductionContext(
            id=osv_id,
            mode=mode,
            project_info=project_info,
            mount_files=build_context_files,
            issue_report=issue_report,
            timestamp=timestamp,
            repositories=repositories
        )

        self.file_provision_handler.save_context(context)

        return True
