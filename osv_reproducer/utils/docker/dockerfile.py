"""
Utility functions for working with Dockerfiles and extracting artifacts.
"""
import os
import requests
from pathlib import Path
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional
from logging import Logger


def parse_dockerfile_instruction(line: str) -> Tuple[bool, List[str], str]:
    """
    Parse a Dockerfile COPY or ADD instruction.

    Args:
        line: A line from a Dockerfile.

    Returns:
        Tuple containing:
            - is_add: Whether the instruction is an ADD command.
            - sources: List of source paths.
            - destination: Destination path.
    """
    is_add = line.startswith('ADD ')
    parts = line.split(' ')

    # Get all source files (everything except the last part which is destination)
    sources = parts[1:-1]
    destination = parts[-1]

    return is_add, sources, destination


def process_destination_path(destination: str, logger: Logger) -> Optional[str]:
    """
    Process a destination path, handling variables.

    Args:
        destination: Destination path from a Dockerfile instruction.
        logger: Logger instance for logging warnings.

    Returns:
        Processed destination path, or None if the path contains unsupported variables.
    """
    # Handle destination with $SRC variable
    if '$SRC' in destination:
        return destination.replace('$SRC', '/src')
    # Skip if destination contains other variables
    elif '$' in destination:
        logger.warning(f"Skipping destination with unsupported variable: {destination}")
        return None
    # Add /src/ prefix if no path is specified (no / and doesn't start with /)
    elif '/' not in destination or not destination.startswith('/'):
        logger.info(f"Adding /src/ prefix to destination: {destination}")
        return f"/src/{destination}"

    return destination


def is_valid_source(source: str, logger: Logger) -> bool:
    """
    Check if a source path is valid (no variables or wildcards).

    Args:
        source: Source path from a Dockerfile instruction.
        logger: Logger instance for logging warnings.

    Returns:
        True if the source is valid, False otherwise.
    """
    # Skip if source contains variables
    if '$' in source:
        logger.warning(f"Skipping source with variable: {source}")
        return False

    # Skip if source contains wildcards
    if '*' in source:
        logger.warning(f"Skipping source with wildcard: {source}")
        return False

    return True


def download_file_from_url(source: str, dockerfile_dir: Path, destination: str, logger: Logger) -> Optional[Path]:
    """
    Download a file from a URL to the project's path.

    Args:
        source: URL to download from.
        dockerfile_dir: Directory containing the Dockerfile.
        destination: Destination filename from the ADD command.
        logger: Logger instance for logging.

    Returns:
        Path to the downloaded file, or None if download failed.
    """
    try:
        # Use the filename from the ADD command's destination
        filename = os.path.basename(destination)

        if not filename:
            logger.warning(f"Could not determine filename from destination: {destination}")
            return None

        # Download the file to the project's path
        download_path = dockerfile_dir / filename

        # Check if the file already exists
        if download_path.exists():
            logger.info(f"File {download_path} already exists, skipping download")
            return download_path

        logger.info(f"Downloading {source} to {download_path}")

        response = requests.get(source, stream=True)
        response.raise_for_status()  # Raise an exception for HTTP errors

        with open(download_path, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)

        logger.info(f"Successfully downloaded {source} to {download_path}")
        return download_path

    except Exception as e:
        logger.error(f"Error downloading file from {source}: {str(e)}")
        return None


def check_local_file(source: str, dockerfile_dir: Path, logger: Logger) -> Optional[Path]:
    """
    Check if a local file exists.

    Args:
        source: Source path from a Dockerfile instruction.
        dockerfile_dir: Directory containing the Dockerfile.
        logger: Logger instance for logging warnings.

    Returns:
        Path to the file if it exists, None otherwise.
    """
    file_path = dockerfile_dir / source

    if file_path.exists():
        return file_path
    else:
        logger.warning(f"File {file_path} referenced in Dockerfile does not exist")
        return None


def extract_artifacts_from_dockerfile(dockerfile_path: Path, logger: Logger) -> Dict[str, str]:
    """
    Extract artifacts (files being copied or added) from a Dockerfile.

    Args:
        dockerfile_path: Path to the Dockerfile.
        logger: Logger instance for logging.

    Returns:
        Dictionary with source:destination as key:value pairs of files being copied into the image.
    """
    if not dockerfile_path.exists():
        logger.error(f"Dockerfile not found at {dockerfile_path}")
        return {}

    artifacts = {}
    dockerfile_dir = dockerfile_path.parent

    try:
        with open(dockerfile_path, 'r') as f:
            for line in f:
                line = line.strip()

                if line.startswith('COPY ') or line.startswith('ADD '):
                    is_add, sources, destination = parse_dockerfile_instruction(line)

                    # Process destination path
                    processed_destination = process_destination_path(destination, logger)
                    if processed_destination is None:
                        continue

                    for source in sources:
                        # Validate source
                        if not is_valid_source(source, logger):
                            continue

                        # For ADD commands, check if source is a URL
                        if is_add and (source.startswith('http://') or source.startswith('https://')):
                            download_path = download_file_from_url(source, dockerfile_dir, destination, logger)

                            if download_path:
                                artifacts[str(download_path)] = processed_destination
                        else:
                            # Check if the file exists locally
                            file_path = check_local_file(source, dockerfile_dir, logger)

                            if file_path:
                                artifacts[str(file_path)] = processed_destination

        return artifacts

    except Exception as e:
        logger.error(f"Error parsing Dockerfile {dockerfile_path}: {str(e)}")
        return {}
