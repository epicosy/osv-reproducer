import json

from pathlib import Path
from cement import Handler
from typing import Optional

from google.cloud import storage
from google.cloud.exceptions import GoogleCloudError, NotFound

from ..core.exc import GCSError
from ..core.interfaces import HandlersInterface


class GCSHandler(HandlersInterface, Handler):
    """
        Google Cloud Storage Handler
    """

    class Meta:
        label = "gcs"

    def _setup(self, app):
        super()._setup(app)
        self.config = self.app.config.get("handlers", "gcs")
        self.gcs_client = storage.Client.create_anonymous_client()
        self.app.log.info("GCS client initialized successfully")

    def download_file(self, bucket_name: str, source_blob_name: str, output_file_path: Path) -> Path:
        # TODO: move to dedicated handler
        """
        Download a file from a GCS bucket.

        Args:
            bucket_name: Name of the GCS bucket.
            source_blob_name: Name of the blob to download.
            output_file_path: Path to save the downloaded file.

        Returns:
            str: Path to the downloaded file.

        Raises:
            GCSError: If downloading the file fails.
        """
        try:
            # Create the directory if it doesn't exist
            output_file_path.parent.mkdir(exist_ok=True, parents=True)
            self.app.log.info(f"Downloading file {source_blob_name} from bucket {bucket_name} to {output_file_path}")

            # Download the file
            bucket = self.gcs_client.bucket(bucket_name)
            blob = bucket.blob(source_blob_name)
            blob.download_to_filename(output_file_path)

            self.app.log.info(f"Successfully downloaded file {source_blob_name} from bucket {bucket_name}")
            return output_file_path
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

    def get_snapshot(self, project_name: str, sanitizer: str, timestamp: str) -> Optional[dict]:
        """
        Downloads a timestamp.srcmap.json file for a specific OSS Fuzz issue.

        Args:
            project_name: Name of the OSS-Fuzz project.
            sanitizer: Name of the sanitizer.
            timestamp: Timestamp of the build.

        Returns:
            Optional[str]: Path to the downloaded file, or None if the file doesn't exist.

        Raises:
            GCSError: If downloading the file fails.
        """
        snapshot_file_path = self.app.snapshots_dir / f"{timestamp}.json"

        if snapshot_file_path.exists():
            self.app.log.info(f"Using cached snapshots for {self.app.pargs.osv_id}")
            with snapshot_file_path.open(mode="r") as f:
                return json.load(f)

        try:
            blob_name = f"{project_name}/{project_name}-{sanitizer}-{timestamp}.srcmap.json"

            # Check if file exists
            if not self.file_exists(self.config["bucket_name"], blob_name):
                self.app.log.warning(f"Srcmap for project {project_name} at {timestamp} not found")
                return None

            # Download the file
            path = self.download_file(self.config["bucket_name"], blob_name, snapshot_file_path)

            with path.open(mode="r") as f:
                srcmap = json.load(f)

            return srcmap

        except GCSError:
            # Re-raise GCSError
            raise
        except Exception as e:
            self.app.log.error(f"Error while downloading srcmap for project {project_name} at {timestamp}: {str(e)}")
            raise GCSError(f"Failed to download srcmap for project {project_name} at {timestamp}: {str(e)}")
