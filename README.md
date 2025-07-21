# OSV Reproducer

A Python package for reproducing OSS-Fuzz bugs listed by OSV (Open Source Vulnerabilities) as vulnerabilities.

## Description

OSV Reproducer is a tool that helps security researchers and developers reproduce vulnerabilities reported in the OSV database. It provides a simple CLI that takes an OSV-ID, fetches the vulnerability data, and reproduces the bug in a containerized environment.

The tool automates the following workflow:

1. Fetch OSV record by ID
2. Extract metadata (project name, vulnerable commit, fixed commit, etc.)
3. Retrieve OSS-Fuzz artifacts (test case, issue report)
4. Prepare the versioned environment (clone repository at specific commit)
5. Build and run the vulnerable version with the test case
6. Verify if the test case crashes the program and matches the issue report
7. Build and run the fixed version with the test case
8. Verify if the fix addresses the vulnerability

## Installation

```bash
pip install osv-reproducer
```

## Usage

OSV Reproducer provides two main commands:

- `reproduce`: Reproduces a vulnerability by building the vulnerable version and running it with the test case
- `verify`: Verifies if a fix addresses a vulnerability by building the fixed version and running it with the test case

### Basic Usage

```bash
# Reproduce a vulnerability
osv-reproducer -oid OSV-2023-XXXX reproduce

# Verify a fix
osv-reproducer -oid OSV-2023-XXXX verify
```

### Options

```bash
# Required arguments
-oid, --osv_id          Identifier of the vulnerability in the OSV database (e.g., OSV-2023-XXXX)

# Optional arguments
-v, --version           Show version information
-vb, --verbose          Enable verbose output
-o, --output-dir        Directory to store output artifacts (default: ./osv-results)
--build-extra-args      Additional build arguments to pass to the fuzzer container as environment variables
                        Format: 'KEY1:VALUE1|KEY2:VALUE2'
```

### Examples

```bash
# Reproduce a vulnerability with verbose output and custom output directory
osv-reproducer -vb -o ~/path/to/results/OSV-2023-1276 -oid OSV-2023-1276 reproduce

# Verify a fix with verbose output and custom output directory
osv-reproducer -vb -o ~/path/to/results/OSV-2023-1276_fix -oid OSV-2023-1276 verify

# Reproduce with additional build arguments
osv-reproducer -vb -o ~/path/to/results/OSV-2021-1361 -oid OSV-2021-1361 --build-extra-args "CFLAGS:-Werror,-Wunused-but-set-variable|CXXFLAGS:-Werror,-Wunused-but-set-variable" reproduce
```

## Workflow

```
graph TD
    A[Input: OSV-ID] --> B[Fetch OSV Record]
    B --> C[Extract Metadata]
    C --> D[Retrieve OSS-Fuzz Artifacts]
    D --> E[Prepare Versioned Environment]
    
    subgraph Reproduction Mode
        E --> F[Build Vulnerable Version]
        F --> G[Run Test Case]
        G --> H[Verify Crash]
    end
    
    subgraph Verification Mode
        E --> I[Build Fixed Version]
        I --> J[Run Test Case]
        J --> K[Verify No Crash]
    end
```

## Architecture

OSV Reproducer is built using the Cement framework and follows a modular architecture with handlers for different functionalities:

- **BuildHandler**: Builds Docker images and runs containers for fuzzing projects
- **DockerHandler**: Provides core Docker functionality
- **GCSHandler**: Interacts with Google Cloud Storage to retrieve project snapshots
- **GithubHandler**: Interacts with GitHub repositories to retrieve commits
- **OSSFuzzHandler**: Interacts with OSS-Fuzz to retrieve issue reports and test cases
- **OSVHandler**: Interacts with the OSV API to retrieve vulnerability records
- **ProjectHandler**: Manages project information and initialization
- **RunnerHandler**: Reproduces crashes and verifies them

This modular approach allows for flexibility in how core behaviors are implemented or swapped out, even at runtime or by user command-line options.

## Requirements

- Python 3.8+
- Docker
- Internet connection (to access OSV database, GitHub, and Google Cloud Storage)

## License

Apache License 2.0