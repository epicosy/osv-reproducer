import json
from datetime import datetime

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

    def download_file(self, bucket_name: str, source_blob_name: str, output_file_path: Path = None) -> Path | bytes:
        # TODO: move to dedicated handler
        """
        Download a file from a GCS bucket.

        Args:
            bucket_name: Name of the GCS bucket.
            source_blob_name: Name of the blob to download.
            output_file_path: Optional path to save the downloaded file. If not provided, returns the file content.

        Returns:
            Path | bytes: Path to the downloaded file if output_file_path is provided, otherwise the file content as bytes.

        Raises:
            GCSError: If downloading the file fails.
        """
        try:
            self.app.log.info(f"Downloading file {source_blob_name} from bucket {bucket_name}")

            # Get the bucket and blob
            bucket = self.gcs_client.bucket(bucket_name)
            blob = bucket.blob(source_blob_name)

            if output_file_path:
                # Create the directory if it doesn't exist
                output_file_path.parent.mkdir(exist_ok=True, parents=True)
                self.app.log.info(f"Saving to {output_file_path}")

                # Download the file to the specified path
                blob.download_to_filename(output_file_path)

                self.app.log.info(f"Successfully downloaded file {source_blob_name} from bucket {bucket_name}")
                return output_file_path
            else:
                # Return the file content as bytes
                content = blob.download_as_bytes()
                self.app.log.info(f"Successfully downloaded content of {source_blob_name} from bucket {bucket_name}")
                return content
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

    def list_blobs_with_prefix(self, bucket_name: str, prefix: str, start_offset: Optional[str] = None) -> list:
        """
        List blobs in a bucket with a specific prefix.

        Args:
            bucket_name: Name of the GCS bucket.
            prefix: Prefix used to filter blobs.
            start_offset: Filter results to objects whose names are lexicographically equal to or after this value.

        Returns:
            list: List of blob names.

        Raises:
            GCSError: If listing blobs fails.
        """
        try:
            self.app.log.info(f"Listing blobs with prefix {prefix} in bucket {bucket_name}")

            # List blobs
            bucket = self.gcs_client.bucket(bucket_name)
            blobs = bucket.list_blobs(prefix=prefix, start_offset=start_offset)

            # Convert to list and sort
            blob_names = [blob.name for blob in blobs]
            blob_names.sort()

            self.app.log.info(f"Found {len(blob_names)} blobs with prefix {prefix} in bucket {bucket_name}")
            return blob_names
        except NotFound:
            self.app.log.info(f"Bucket {bucket_name} not found")
            return []
        except GoogleCloudError as e:
            self.app.log.error(f"Google Cloud error while listing blobs with prefix {prefix}: {str(e)}")
            raise GCSError(f"Failed to list blobs with prefix {prefix}: {str(e)}")
        except Exception as e:
            self.app.log.error(f"Error while listing blobs with prefix {prefix}: {str(e)}")
            raise GCSError(f"Failed to list blobs with prefix {prefix}: {str(e)}")

    def _get_cached_snapshot(self, project: str, timestamp: str) -> Optional[dict]:
        """
        Check if a snapshot is cached and load it if it exists.

        Args:
            timestamp: Timestamp of the build.

        Returns:
            Optional[dict]: The cached srcmap as a dictionary, or None if not cached.
        """
        snapshot_file_path = self.app.snapshots_dir / project / f"{timestamp}.json"

        if snapshot_file_path.exists():
            self.app.log.info(f"Using cached snapshot from {snapshot_file_path}")
            with snapshot_file_path.open(mode="r") as f:
                return json.load(f)
        return None

    def _find_alternative_snapshot(self, project_name: str, sanitizer: str, timestamp: str) -> Optional[str]:
        """
        Find an alternative snapshot if the requested one doesn't exist.

        Args:
            project_name: Name of the OSS-Fuzz project.
            sanitizer: Name of the sanitizer.
            timestamp: Timestamp of the build.

        Returns:
            Optional[str]: The blob name of the alternative snapshot, or None if not found.
        """
        self.app.log.info(f"Looking for the first snapshot before {timestamp} for project {project_name}")
        prefix = f"{project_name}/{project_name}-{sanitizer}-"

        # List all blobs with the prefix
        all_blob_names = self.list_blobs_with_prefix(self.config["bucket_name"], prefix)

        # Convert the target timestamp to a datetime object
        target_dt = datetime.strptime(timestamp, "%Y%m%d%H%M")

        # Filter blobs that are before the timestamp by comparing datetime objects
        before_timestamp_blobs = []
        for blob_name in all_blob_names:
            if blob_name.endswith(".zip"):
                continue
            # Extract timestamp from blob name
            try:
                blob_timestamp = blob_name.split('-')[-1].replace('.srcmap.json', '')
                blob_dt = datetime.strptime(blob_timestamp, "%Y%m%d%H%M")

                # Compare datetime objects
                if blob_dt < target_dt:
                    before_timestamp_blobs.append((blob_name, blob_dt))
            except ValueError:
                # Skip blobs with invalid timestamp format
                self.app.log.warning(f"Skipping blob with invalid timestamp format: {blob_name}")
                continue

        if not before_timestamp_blobs:
            self.app.log.warning(f"No snapshots found before {timestamp} for project {project_name}")
            return None

        # Sort by datetime and get the latest before the timestamp
        before_timestamp_blobs.sort(key=lambda x: x[1])  # Sort by datetime
        blob_name = before_timestamp_blobs[-1][0]  # Get the blob name with the latest datetime

        # Log the found snapshot
        new_timestamp = blob_name.split('-')[-1].replace('.srcmap.json', '')
        self.app.log.info(f"Found snapshot at {new_timestamp} for project {project_name}")

        return blob_name

    def _parse_snapshot_content(self, content) -> dict:
        """
        Parse the snapshot content.

        Args:
            content: The content to parse, either bytes or a Path.

        Returns:
            dict: The parsed srcmap.
        """
        if isinstance(content, bytes):
            return json.loads(content.decode('utf-8'))
        else:
            with content.open(mode="r") as f:
                return json.load(f)

    def _update_snapshot_version(self, srcmap: dict, project_name: str, commit_sha: str) -> dict:
        """
        Update the version information in the snapshot if needed.

        Args:
            srcmap: The srcmap to update.
            project_name: Name of the OSS-Fuzz project.
            commit_sha: The commit SHA to check against.

        Returns:
            dict: The updated srcmap.
        """
        if not commit_sha:
            return srcmap

        src_key = f"/src/{project_name}"
        prev_rev = srcmap[src_key].get('rev', None)

        if src_key in srcmap and prev_rev and prev_rev != commit_sha:
            self.app.log.info(f"Updating version for {src_key} from {prev_rev} to {commit_sha}")
            srcmap[src_key]["rev"] = commit_sha

        return srcmap

    def _save_snapshot(self, project_name: str, srcmap: dict, timestamp: str) -> None:
        """
        Save the snapshot to a file.

        Args:
            srcmap: The srcmap to save.
            timestamp: Timestamp to use in the filename.
        """
        snapshot_file_path = self.app.snapshots_dir / project_name / f"{timestamp}.json"

        if not snapshot_file_path.parent.exists():
            snapshot_file_path.parent.mkdir(parents=True)

        with snapshot_file_path.open(mode="w") as f:
            json.dump(srcmap, f, indent=2)

    def get_snapshot(self, project_name: str, sanitizer: str, timestamp: str, commit_sha: str = None) -> Optional[dict]:
        """
        Downloads a timestamp.srcmap.json file for a specific OSS Fuzz issue.

        Args:
            project_name: Name of the OSS-Fuzz project.
            sanitizer: Name of the sanitizer.
            timestamp: Timestamp of the build.
            commit_sha: The commit SHA to check against the snapshot version.

        Returns:
            Optional[dict]: The srcmap as a dictionary, or None if the file doesn't exist.

        Raises:
            GCSError: If downloading the file fails.
        """
        # Check for cached snapshot
        cached_snapshot = self._get_cached_snapshot(project_name, timestamp)
        if cached_snapshot:
            return cached_snapshot

        try:
            # Construct the blob name
            blob_name = f"{project_name}/{project_name}-{sanitizer}-{timestamp}.srcmap.json"

            # Check if file exists, find alternative if not
            if not self.file_exists(self.config["bucket_name"], blob_name):
                self.app.log.warning(f"Srcmap for project {project_name} at {timestamp} not found")

                blob_name = self._find_alternative_snapshot(project_name, sanitizer, timestamp)
                if not blob_name:
                    return None

            # Download and parse the snapshot
            content = self.download_file(self.config["bucket_name"], blob_name)
            # TODO: should account for all dependencies to be included
            srcmap = self._parse_snapshot_content(content)

            # Update version if needed
            srcmap = self._update_snapshot_version(srcmap, project_name, commit_sha)

            # Save the snapshot
            self._save_snapshot(project_name, srcmap, timestamp)

            return srcmap

        except GCSError:
            # Re-raise GCSError
            raise
        except Exception as e:
            self.app.log.error(f"Error while downloading srcmap for project {project_name} at {timestamp}: {str(e)}")
            raise GCSError(f"Failed to download srcmap for project {project_name} at {timestamp}: {str(e)}")
