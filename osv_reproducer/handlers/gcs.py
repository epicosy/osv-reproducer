import json

from cement import Handler
from datetime import datetime
from google.cloud import storage
from typing import Optional, Tuple, Union
from google.cloud.exceptions import GoogleCloudError, NotFound

from ..core.exc import GCSError
from ..handlers import HandlersInterface
from ..core.interfaces import GCSInterface


# --- Normalize timestamp inputs ---
def ts_to_str(ts):
    if isinstance(ts, datetime):
        return ts.strftime("%Y%m%d%H%M")
    return ts


class GCSHandler(GCSInterface, HandlersInterface, Handler):
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

    def fetch_file_content(self, bucket_name: str, source_blob_name: str) -> bytes:
        """
        Download a file from a GCS bucket.

        Args:
            bucket_name: Name of the GCS bucket.
            source_blob_name: Name of the blob to download.

        Returns:
            bytes: file content as bytes.

        Raises:
            GCSError: If downloading the file fails.
        """
        try:
            self.app.log.info(f"Downloading file {source_blob_name} from bucket {bucket_name}")

            # Get the bucket and blob
            bucket = self.gcs_client.bucket(bucket_name)
            blob = bucket.blob(source_blob_name)

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

    def fetch_snapshot_by_timestamp(self, project_name: str, sanitizer: str, timestamp: str) -> Optional[dict]:
        """
        Fetch the snapshot for the exact timestamp. No fallback or range search.

        Args:
            project_name: OSS-Fuzz project name.
            sanitizer: Sanitizer name.
            timestamp: Timestamp "YYYYMMDDHHMM".

        Returns:
            dict or None: Parsed srcmap, or None if the file does not exist.
        """
        try:
            # Construct exact filename
            blob_name = f"{project_name}/{project_name}-{sanitizer}-{timestamp}.srcmap.json"

            # Exact file check
            if not self.file_exists(self.config["bucket_name"], blob_name):
                self.app.log.warning(f"Snapshot not found for project {project_name} at timestamp {timestamp}")
                return None

            # Download & parse
            content = self.fetch_file_content(self.config["bucket_name"], blob_name)
            srcmap = json.loads(content.decode("utf-8"))
            return srcmap

        except GCSError as ge:
            self.app.log.error(f"Error downloading srcmap for project {project_name} at {timestamp}: {ge}")
        except Exception as e:
            self.app.log.error(f"Error downloading srcmap for project {project_name} at {timestamp}: {e}")

        return None

    def fetch_snapshot_by_range(
            self, project_name: str,  sanitizer: str, start_timestamp: Union[str, datetime], end_timestamp: Union[str, datetime]
    ) -> Tuple[Optional[str], Optional[dict]]:
        """
        Fetch the most recent snapshot (first match) whose timestamp falls within
        the inclusive range [start_timestamp, end_timestamp].

        Args:
            project_name: OSS-Fuzz project name.
            sanitizer: Sanitizer name.
            start_timestamp: Minimum timestamp (inclusive), string "YYYYMMDDHHMM" or datetime.
            end_timestamp: Maximum timestamp (inclusive), string "YYYYMMDDHHMM" or datetime.

        Returns:
            (timestamp, srcmap) tuple of the first match in reverse chronological order,
            or None if no snapshot matches.
        """

        try:

            if isinstance(start_timestamp, datetime) and isinstance(end_timestamp, datetime):
                if start_timestamp > end_timestamp:
                    raise ValueError(
                        f"start_timestamp {start_timestamp} is after end_timestamp {end_timestamp}"
                    )

            start_ts_str = ts_to_str(start_timestamp)
            end_ts_str = ts_to_str(end_timestamp)
            common_prefix_len = 0

            for a, b in zip(start_ts_str, end_ts_str):
                if a == b:
                    common_prefix_len += 1
                else:
                    break

            ts_prefix = start_ts_str[:common_prefix_len] if common_prefix_len >= 4 else ""
            prefix = f"{project_name}/{project_name}-{sanitizer}-" + ts_prefix

            self.app.log.info(f"Searching snapshot range for {project_name}:{sanitizer} {start_ts_str} → {end_ts_str}")

            # --- List blobs ---
            blob_names = self.list_blobs_with_prefix(self.config["bucket_name"], prefix)

            if not blob_names:
                self.app.log.info(f"No snapshots found for prefix {prefix}")
                return None, None

            # --- Build filtered list (timestamp extracted from file name) ---
            candidates = []

            for blob_name in blob_names:
                if not blob_name.endswith(".srcmap.json"):
                    continue

                try:
                    blob_ts = blob_name.split("-")[-1].replace(".srcmap.json", "")
                    datetime.strptime(blob_ts, "%Y%m%d%H%M")  # validate
                except ValueError:
                    self.app.log.warning(f"Skipping invalid snapshot name: {blob_name}")
                    continue

                # Timestamp within range?
                if start_ts_str <= blob_ts <= end_ts_str:
                    candidates.append((blob_name, blob_ts))

            if not candidates:
                self.app.log.info(f"No snapshots in range {start_ts_str} → {end_ts_str}")
                return None, None

            # --- Sort: newest → oldest ---
            candidates.sort(key=lambda x: x[1], reverse=True)

            # --- Return the FIRST valid match ---
            for blob_name, blob_ts in candidates:
                try:
                    content = self.fetch_file_content(self.config["bucket_name"], blob_name)
                    srcmap = json.loads(content.decode("utf-8"))

                    self.app.log.info(f"Match found: {blob_name} (timestamp={blob_ts})")
                    return blob_ts, srcmap

                except Exception as e:
                    self.app.log.warning(f"Skipping unreadable snapshot {blob_name}: {e}")
                    continue

            # If all candidates failed to load → no match
            self.app.log.info("No valid snapshots found after filtering")
            return None, None

        except GCSError as ge:
            self.app.log.error(f"Error fetching snapshot range for {project_name}: {ge}")
        except Exception as e:
            self.app.log.error(f"Error fetching snapshot range for {project_name}: {e}")

        return None, None
