# OSV Reproducer

A Python package for reproducing OSS-Fuzz bugs listed by OSV (Open Source Vulnerabilities) as vulnerabilities.

## Description

OSV Reproducer is a tool that helps security researchers and developers reproduce vulnerabilities reported in the OSV database. It provides a simple CLI that takes an OSV-ID, fetches the vulnerability data, and reproduces the bug in a containerized environment.

The tool automates the following workflow:

1. Fetch OSV record by ID
2. Extract metadata (project name, vulnerable commit, fixed commit, etc.)
3. Retrieve OSS-Fuzz artifacts
4. Prepare versioned environment
5. Build and verify the vulnerable version
6. Build and verify the fixed version
7. Generate a differential report

## Installation

```bash
pip install osv-reproducer
```

## Usage

### Basic Usage

```bash
osv-reproducer reproduce OSV-2023-XXXX
```

### Options

```bash
# Specify output directory for artifacts
osv-reproducer reproduce OSV-2023-XXXX --output-dir ./results

# Keep Docker containers after reproduction
osv-reproducer reproduce OSV-2023-XXXX --keep-containers

# Verbose output
osv-reproducer reproduce OSV-2023-XXXX --verbose
```

## Workflow

```
graph TD
    A[Input: OSV-ID] --> B[Fetch OSV Record]
    B --> C[Extract Metadata]
    C --> D[Retrieve OSS-Fuzz Artifacts]
    D --> E[Prepare Versioned Environment]
    E --> F[Build & Verify Vulnerable Version]
    F --> G[Build & Verify Fixed Version]
    G --> H[Generate Differential Report]
```

## Requirements

- Python 3.8+
- Docker
- Internet connection (to access OSV database, GitHub, and Google Cloud Storage)

## License

Apache License 2.0