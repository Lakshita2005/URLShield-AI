# Dataset Information: LegitPhish Dataset

## Metadata Summary
- **Dataset Name**: LegitPhish Dataset
- **Source**: Mendeley Data
- **Official URL**: https://data.mendeley.com/datasets/hx4m73v2sf/2
- **DOI**: [10.17632/hx4m73v2sf.2](https://doi.org/10.17632/hx4m73v2sf.2)
- **Version**: 2
- **Acquired File**: `url_features_extracted1.csv`
- **File Size**: 8,963,838 bytes (~8.96 MB)
- **SHA-256 Checksum**: `8685e7901c3b4e73eb43c106cb166cc932dd14f76960a032c713c2c32f09dbcd`
- **Fallback Used**: No

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
> Transformation applied during preprocessing: `normalized_label = 1 - original_label` (or `label.map({0: 1, 1: 0})`).

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
@misc{legitphish2025,
  title={LegitPhish Dataset},
  author={Mendeley Data},
  year={2025},
  version={2},
  publisher={Mendeley Data},
  doi={10.17632/hx4m73v2sf.2},
  url={https://data.mendeley.com/datasets/hx4m73v2sf/2}
}
```
