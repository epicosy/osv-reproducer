from datetime import datetime
from abc import ABC, abstractmethod
from typing import Optional, Tuple, Union


# Google Cloud Storage (GCS)
class GCSInterface(ABC):
    @abstractmethod
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
        raise NotImplementedError()

    @abstractmethod
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
        raise NotImplementedError()

    @abstractmethod
    def fetch_snapshot_by_timestamp(self, project_name: str, sanitizer: str, timestamp: str) -> Optional[dict]:
        """
        Fetches a snapshot of data for a specified project and sanitizer at a given timestamp.

        This method is an abstract method intended to be implemented by subclasses.
        It retrieves a snapshot as a dictionary or returns None if no data is found
        corresponding to the given parameters. The timestamp should be provided in
        a suitable format that this method expects.

        Parameters:
            project_name (str): The name of the project for which snapshot data
                is requested.
            sanitizer (str): The identifier of the sanitizer associated with the
                project's data.
            timestamp (str): The timestamp for which the snapshot is requested, in
                the expected format.

        Returns:
            Optional[dict]: A dictionary containing the snapshot data if available,
                otherwise None.
        """
        raise NotImplementedError()

    @abstractmethod
    def fetch_snapshot_by_range(
            self, project_name: str,  sanitizer: str, start_timestamp: Union[str, datetime], end_timestamp: Union[str, datetime]
    ) -> Tuple[Optional[str], Optional[dict]]:
        """
        Defines an abstract method for fetching a data snapshot by a specified time range.

        Summary:
        This method is intended to be implemented by subclasses to enable retrieval
        of a specific range of snapshots for a given project and sanitizer. It takes
        a project name, sanitizer identifier, and the start and end timestamps of
        the desired range. The method must be implemented to return the snapshot
        data and its corresponding metadata or None if no valid snapshot is available.

        Args:
            project_name: The name of the project for which the snapshot is to be retrieved.
            sanitizer: The identifier of the sanitizer associated with the snapshot.
            start_timestamp: The starting point of the time range for snapshot retrieval,
                provided as either a string or a datetime object.
            end_timestamp: The ending point of the time range for snapshot retrieval,
                provided as either a string or a datetime object.

        Returns:
            A tuple containing the snapshot identifier as a string and its associated
            metadata as a dictionary. Returns None, None if no snapshot exists within the
            specified time range.
        """
        raise NotImplementedError()
