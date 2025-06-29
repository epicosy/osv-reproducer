import os
import json
import tempfile

from pathlib import Path
from cement import Handler
from typing import Optional
from google.cloud import storage
from google.cloud.exceptions import GoogleCloudError, NotFound

from ..core.exc import BuildError, GCSError
from ..core.models.build import BuildInfo
from ..core.models.project import ProjectInfo
from ..core.interfaces import HandlersInterface


class BuildHandler(HandlersInterface, Handler):
    """
        OSV handler
    """

    class Meta:
        label = 'build'

    def _setup(self, app):
        super()._setup(app)
        # TODO: should be moved somewhere else
        self.gcs_client = storage.Client.create_anonymous_client()
        self.app.log.info("GCS client initialized successfully")

    def download_file(
            self, bucket_name: str, source_blob_name: str, destination_file_path: Optional[str] = None
    ) -> str:
        # TODO: move to dedicated handler
        """
        Download a file from a GCS bucket.

        Args:
            bucket_name: Name of the GCS bucket.
            source_blob_name: Name of the blob to download.
            destination_file_path: Path to save the downloaded file. If None, creates a temporary file.

        Returns:
            str: Path to the downloaded file.

        Raises:
            GCSError: If downloading the file fails.
        """
        try:
            # Create destination file path if it doesn't exist
            if destination_file_path is None:
                fd, destination_file_path = tempfile.mkstemp(prefix="osv-gcs-")
                os.close(fd)

            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(destination_file_path)), exist_ok=True)

            self.app.log.info(f"Downloading file {source_blob_name} from bucket {bucket_name} to {destination_file_path}")

            # Download the file
            bucket = self.gcs_client.bucket(bucket_name)
            blob = bucket.blob(source_blob_name)
            blob.download_to_filename(destination_file_path)

            self.app.log.info(f"Successfully downloaded file {source_blob_name} from bucket {bucket_name}")
            return destination_file_path
        except NotFound as e:
            self.app.log.error(f"File {source_blob_name} not found in bucket {bucket_name}: {str(e)}")
            raise GCSError(f"File {source_blob_name} not found in bucket {bucket_name}: {str(e)}")
        except GoogleCloudError as e:
            self.app.log.error(f"Google Cloud error while downloading file {source_blob_name}: {str(e)}")
            raise GCSError(f"Failed to download file {source_blob_name}: {str(e)}")
        except Exception as e:
            self.app.log.error(f"Error while downloading file {source_blob_name}: {str(e)}")
            raise GCSError(f"Failed to download file {source_blob_name}: {str(e)}")

    def file_exists(self, bucket_name: str, blob_name: str) -> bool:
        """
        Check if a file exists in a GCS bucket.

        Args:
            bucket_name: Name of the GCS bucket.
            blob_name: Name of the blob to check.

        Returns:
            bool: True if the file exists, False otherwise.

        Raises:
            GCSError: If checking file existence fails.
        """
        try:
            self.app.log.info(f"Checking if file {blob_name} exists in bucket {bucket_name}")

            # Check if file exists
            bucket = self.gcs_client.bucket(bucket_name)
            blob = bucket.blob(blob_name)
            exists = blob.exists()

            self.app.log.info(f"File {blob_name} {'exists' if exists else 'does not exist'} in bucket {bucket_name}")
            return exists
        except NotFound:
            self.app.log.info(f"Bucket {bucket_name} not found")
            return False
        except GoogleCloudError as e:
            self.app.log.error(f"Google Cloud error while checking if file {blob_name} exists: {str(e)}")
            raise GCSError(f"Failed to check if file {blob_name} exists: {str(e)}")
        except Exception as e:
            self.app.log.error(f"Error while checking if file {blob_name} exists: {str(e)}")
            raise GCSError(f"Failed to check if file {blob_name} exists: {str(e)}")

    def download_srcmap(self, project: str, commit: str, destination_file_path: Optional[str] = None) -> Optional[str]:
        """
        Download a srcmap.json file for a specific project and commit.

        Args:
            project: Name of the project.
            commit: Commit hash.
            destination_file_path: Path to save the downloaded file. If None, creates a temporary file.

        Returns:
            Optional[str]: Path to the downloaded file, or None if the file doesn't exist.

        Raises:
            GCSError: If downloading the file fails.
        """
        try:
            # OSS-Fuzz srcmap bucket and path format
            bucket_name = "oss-fuzz-build-logs"
            blob_name = f"{project}/srcmap/{commit}.json"

            # Check if file exists
            if not self.file_exists(bucket_name, blob_name):
                self.app.log.warning(f"Srcmap for project {project} at commit {commit} not found")
                return None

            # Download the file
            return self.download_file(bucket_name, blob_name, destination_file_path)
        except GCSError:
            # Re-raise GCSError
            raise
        except Exception as e:
            self.app.log.error(f"Error while downloading srcmap for project {project} at commit {commit}: {str(e)}")
            raise GCSError(f"Failed to download srcmap for project {project} at commit {commit}: {str(e)}")

    def get_build_info(self, project_info: ProjectInfo, commit: str) -> BuildInfo:
        """
        Get build information for a project at a specific commit.

        Args:
            project_info: object with project info
            commit: Commit hash.

        Returns:
            BuildInfo: Build information.

        Raises:
            BuildError: If getting build information fails.
        """
        try:
            self.app.log.info(f"Getting build information for project {project_info.name} at commit {commit}")

            project_info_path = self.app.projects_dir / project_info.name

            # Get Dockerfile path
            dockerfile_path = project_info_path / "Dockerfile"
            if not dockerfile_path.exists():
                self.app.log.warning(f"Dockerfile not found for project {project_info.name}")

            # Get build script path
            build_script_path = project_info_path / "build.sh"
            if not build_script_path.exists():
                self.app.log.warning(f"Build script not found in cache for project {project_info.name}")

            # Get dependencies from srcmap.json
            dependencies = {}
            srcmap_path = self.download_srcmap(project_info.name, commit)

            if srcmap_path:
                with open(srcmap_path, "r") as f:
                    srcmap = json.load(f)
                dependencies = srcmap.get("dependencies", {})

            # Create BuildInfo
            build_info = BuildInfo(
                project=project_info.name,
                commit=commit,
                language=project_info.language,
                dockerfile_path=dockerfile_path,
                build_script_path=build_script_path,
                dependencies=dependencies,
            )

            self.app.log.info(f"Successfully got build information for project {project_info.name} at commit {commit}")
            return build_info
        except Exception as e:
            self.app.log.error(f"Error while getting build information for project {project_info.name} at commit {commit}: {str(e)}")
            raise BuildError(f"Failed to get build information for project {project_info.name} at commit {commit}: {str(e)}")
