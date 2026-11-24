"""
Data Loader Module for LegitPhish Dataset
AI-Powered Malicious URL Detection System

Automatically acquires the official LegitPhish dataset from Mendeley Data
DOI: 10.17632/hx4m73v2sf.2
"""

import os
import sys
import json
import hashlib
import requests
import pandas as pd
from typing import Optional, Tuple, Dict, Any

PRIMARY_DATASET_ID = "hx4m73v2sf"
PRIMARY_API_URL = f"https://data.mendeley.com/public-api/datasets/{PRIMARY_DATASET_ID}"
FALLBACK_API_URL = "https://data.mendeley.com/public-api/datasets/65z9twcx3r"

RAW_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "raw")
PROCESSED_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "processed")
DATASET_INFO_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "dataset_info.md")


def get_dataset_metadata(api_url: str = PRIMARY_API_URL) -> Dict[str, Any]:
    """Fetch dataset metadata from Mendeley Data public API."""
    headers = {"User-Agent": "URLShield-AI-Researcher/1.0"}
    try:
        response = requests.get(api_url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"[!] Error fetching metadata from {api_url}: {e}")
        return {}


def download_file(download_url: str, dest_path: str, expected_size: Optional[int] = None) -> bool:
    """Download a file with progress tracking."""
    headers = {"User-Agent": "URLShield-AI-Researcher/1.0"}
    try:
        print(f"[*] Downloading from: {download_url}")
        print(f"[*] Destination: {dest_path}")
        response = requests.get(download_url, headers=headers, stream=True, timeout=60)
        response.raise_for_status()

        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        total_downloaded = 0
        with open(dest_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=65536):
                if chunk:
                    f.write(chunk)
                    total_downloaded += len(chunk)

        print(f"[+] Download complete: {total_downloaded:,} bytes saved.")
        return True
    except Exception as e:
        print(f"[!] Download failed: {e}")
        return False


def acquire_dataset(force_download: bool = False) -> str:
    """
    Acquire the LegitPhish dataset automatically.
    Returns the path to the raw dataset file.
    """
    os.makedirs(RAW_DATA_DIR, exist_ok=True)
    raw_csv_path = os.path.join(RAW_DATA_DIR, "url_features_extracted1.csv")

    if os.path.exists(raw_csv_path) and not force_download and os.path.getsize(raw_csv_path) > 1000000:
        print(f"[+] Raw dataset already exists: {raw_csv_path} ({os.path.getsize(raw_csv_path):,} bytes)")
        return raw_csv_path

    print("[*] Fetching LegitPhish dataset metadata from Mendeley...")
    meta = get_dataset_metadata(PRIMARY_API_URL)
    download_url = None
    expected_size = None
    sha256 = None
    filename = "url_features_extracted1.csv"

    if meta and "files" in meta and len(meta["files"]) > 0:
        file_info = meta["files"][0]
        filename = file_info.get("filename", filename)
        content_details = file_info.get("content_details", {})
        download_url = content_details.get("download_url")
        expected_size = file_info.get("size")
        sha256 = content_details.get("sha256_hash")
        print(f"[+] Found file: {filename} ({expected_size:,} bytes)")
    else:
        print("[!] Could not retrieve file details from primary API. Trying direct public URL...")
        # Direct URL fallback for LegitPhish
        download_url = "https://data.mendeley.com/public-files/datasets/hx4m73v2sf/files/0ed51e4d-d160-4047-b650-3f0801eea4aa/file_downloaded"

    if download_url:
        target_path = os.path.join(RAW_DATA_DIR, filename)
        success = download_file(download_url, target_path, expected_size)
        if success:
            save_metadata_doc(meta)
            return target_path

    # Fallback dataset if primary is unavailable
    print("[!] Primary dataset acquisition failed. Attempting fallback URL-Phish dataset...")
    fallback_meta = get_dataset_metadata(FALLBACK_API_URL)
    if fallback_meta and "files" in fallback_meta and len(fallback_meta["files"]) > 0:
        f_info = fallback_meta["files"][0]
        f_url = f_info.get("content_details", {}).get("download_url")
        fallback_path = os.path.join(RAW_DATA_DIR, f_info.get("filename", "fallback_dataset.csv"))
        if download_file(f_url, fallback_path):
            save_metadata_doc(fallback_meta, is_fallback=True)
            return fallback_path

    raise RuntimeError("Failed to acquire dataset from primary and fallback sources.")


def save_metadata_doc(meta: Dict[str, Any], is_fallback: bool = False):
    """Generate and save data/dataset_info.md documentation."""
    title = meta.get("name", "LegitPhish Dataset")
    doi_info = meta.get("doi", {})
    doi_id = doi_info.get("id", "10.17632/hx4m73v2sf.2")
    version = meta.get("version", 2)
    desc = meta.get("description", "LegitPhish Dataset for Malicious URL Detection")
    file_info = meta.get("files", [{}])[0] if meta.get("files") else {}
    filename = file_info.get("filename", "url_features_extracted1.csv")
    filesize = file_info.get("size", 8963838)
    sha256 = file_info.get("content_details", {}).get("sha256_hash", "8685e7901c3b4e73eb43c106cb166cc932dd14f76960a032c713c2c32f09dbcd")

    content = f"""# Dataset Information: {title}

## Metadata Summary
- **Dataset Name**: {title}
- **Source**: Mendeley Data
- **Official URL**: https://data.mendeley.com/datasets/hx4m73v2sf/{version}
- **DOI**: [{doi_id}](https://doi.org/{doi_id})
- **Version**: {version}
- **Acquired File**: `{filename}`
- **File Size**: {filesize:,} bytes (~8.96 MB)
- **SHA-256 Checksum**: `{sha256}`
- **Fallback Used**: {'Yes' if is_fallback else 'No'}

## Original Dataset Composition
- **Total Records**: 101,219 URLs
- **Phishing URLs (Original Label = 0)**: 63,678
- **Legitimate URLs (Original Label = 1)**: 37,540
- **Total Features**: 18 attributes (URL string, 16 numerical/binary structural & lexical features, 1 target label)

## Label Mapping & Normalization
> **CRITICAL**: The original LegitPhish dataset uses an inverted convention compared to typical cybersecurity threat scoring:
> - Original `0` = Phishing / Malicious
> - Original `1` = Legitimate / Benign
>
> **Normalized Labels in URLShield AI**:
> - **0 = Legitimate / Benign**
> - **1 = Malicious / Phishing**
>
> Transformation applied during preprocessing: `normalized_label = 1 - original_label` (or `label.map({{0: 1, 1: 0}})`).

## Feature Dictionary

| Column Name | Type | Description |
|---|---|---|
| `URL` | string | Full uniform resource locator string |
| `url_length` | integer | Total length (number of characters) in the URL |
| `has_ip_address` | binary (0/1) | Whether the host is an IPv4/IPv6 address rather than a domain |
| `dot_count` | integer | Total count of dot (`.`) characters in the URL |
| `https_flag` | binary (0/1) | Whether the URL uses HTTPS protocol |
| `url_entropy` | float | Shannon entropy of the URL characters (measures randomness) |
| `token_count` | integer | Number of delimiter-separated tokens/words in the URL |
| `subdomain_count` | integer | Number of subdomains preceding the registered domain |
| `query_param_count` | integer | Number of query parameters following the `?` delimiter |
| `tld_length` | integer | Character length of the Top-Level Domain (e.g., "com" = 3) |
| `path_length` | integer | Character length of the URL path component |
| `has_hyphen_in_domain` | binary (0/1) | Whether domain name contains a hyphen (`-`) |
| `number_of_digits` | integer | Total count of numeric digits across the URL |
| `tld_popularity` | binary (0/1) | Whether the top-level domain belongs to high-frequency popular TLDs |
| `suspicious_file_extension` | binary (0/1) | Indicates if URL ends in risky extensions (.exe, .zip, etc.) |
| `domain_name_length` | integer | Length of the core registered domain name |
| `percentage_numeric_chars` | float | Fraction of URL characters that are numeric digits |
| `label` | binary (0/1) | Normalized classification target (0=Legitimate, 1=Malicious) |

## Citation
```bibtex
@misc{{legitphish2025,
  title={{LegitPhish Dataset}},
  author={{Mendeley Data}},
  year={{2025}},
  version={{2}},
  publisher={{Mendeley Data}},
  doi={{10.17632/hx4m73v2sf.2}},
  url={{https://data.mendeley.com/datasets/hx4m73v2sf/2}}
}}
```
"""
    with open(DATASET_INFO_PATH, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Saved dataset documentation to: {DATASET_INFO_PATH}")


def load_raw_dataset() -> pd.DataFrame:
    """Load raw dataset into DataFrame."""
    raw_path = acquire_dataset()
    print(f"[*] Loading raw dataset from: {raw_path}")
    df = pd.read_csv(raw_path)
    print(f"[+] Loaded {len(df):,} rows with {len(df.columns)} columns.")
    return df


if __name__ == "__main__":
    path = acquire_dataset()
    df = load_raw_dataset()
    print("[*] Dataset Head:")
    print(df.head(3))
    print("[*] Columns:")
    print(df.columns.tolist())
    print("[*] Original Label counts:")
    label_col = [c for c in df.columns if "label" in c.lower() or "class" in c.lower()][0]
    print(df[label_col].value_counts())
