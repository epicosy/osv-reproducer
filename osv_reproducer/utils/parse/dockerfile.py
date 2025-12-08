from typing import List, Tuple, Optional, Dict


def parse_instruction(line: str) -> Tuple[List[str], str]:
    """
    Parse a Dockerfile COPY or ADD instruction.

    Args:
        line: A line from a Dockerfile.

    Returns:
        Tuple containing:
            - sources: List of source paths.
            - destination: Destination path.
    """
    parts = line.split(' ')

    # Get all source files (everything except the last part which is destination)
    sources = parts[1:-1]
    destination = parts[-1]

    return sources, destination


def process_destination(destination: str) -> Optional[str]:
    """
    Process a destination path, handling variables.

    Args:
        destination: Destination path from a Dockerfile instruction.

    Returns:
        Processed destination path, or None if the path contains unsupported variables.
    """
    # Handle destination with $SRC variable
    if '$SRC' in destination:
        return destination.replace('$SRC', '/src')
    # Skip if destination contains other variables
    elif '$' in destination:
        return None
    # Add /src/ prefix if no path is specified (no / and doesn't start with /)
    elif '/' not in destination or not destination.startswith('/'):
        return f"/src/{destination}"

    return destination


def is_valid_source(source: str) -> bool:
    """
    Check if a source path is valid (no variables or wildcards).

    Args:
        source: Source path from a Dockerfile instruction.

    Returns:
        True if the source is valid, False otherwise.
    """
    # Skip if source contains variables
    if '$' in source:
        return False

    # Skip if source contains wildcards
    if '*' in source:
        return False

    return True


def parse_mount_sources(dockerfile: List[str]) -> Tuple[Dict[str, str], Dict[str, str]]:
    """
    Parses the mountable and downloadable sources from a given Dockerfile.

    The function examines lines in a Dockerfile and identifies instructions that
    indicate files to be added or copied, such as ADD or COPY commands. It separates
    these sources into downloadable files (e.g., URLs) or mountable files based on
    their characteristics and processes their destinations accordingly.

    Args:
        dockerfile: A list of strings representing the lines of a Dockerfile.

    Returns:
        A tuple where the first element is a dictionary containing sources (keys) and
        their corresponding destinations (values) for downloadable files (e.g., URLs),
        and the second element is a dictionary containing sources (keys) and their
        destinations (values) for mountable files.
    """
    if not dockerfile:
        return {}, {}

    downloadable_files, mount_files = {}, {}

    for line in dockerfile:
        line = line.strip()

        if line.startswith('ADD '):
            sources, destination = parse_instruction(line)
            mount_path = process_destination(destination)

            if mount_path:
                for source in sources:
                    if source.startswith('http://') or source.startswith('https://'):
                        downloadable_files[source] = mount_path
                    elif is_valid_source(source):
                        mount_files[source] = mount_path
        if line.startswith('COPY '):
            sources, destination = parse_instruction(line)
            mount_path = process_destination(destination)

            if mount_path:
                for source in sources:
                    if is_valid_source(source):
                        if source in mount_path:
                            mount_files[source] = mount_path
                        else:
                            if mount_path[-1] == '/':
                                mount_files[source] = mount_path + source
                            else:
                                mount_files[source] = mount_path + '/' + source

    return downloadable_files, mount_files
