# Cookie Extraction Scripts

## Extract Chrome Cookies

This script allows you to automatically extract and decrypt cookies from Google Chrome's database.

### Installation

Install required dependencies:
```bash
pip install keyring pycryptodome
```

### Usage

**Extract all cookies for a domain:**
```bash
python scripts/extract_chrome_cookies.py --domain tettra.co
```

**Extract in JSON format:**
```bash
python scripts/extract_chrome_cookies.py --domain tettra.co --format json
```

**Extract all cookies:**
```bash
python scripts/extract_chrome_cookies.py
```

### Output Formats

- **string** (default): Cookie string format suitable for pasting into web forms
  - Example: `cookie1=value1; cookie2=value2; cookie3=value3`

- **json**: JSON array format suitable for programmatic use
  - Example:
    ```json
    [
      {
        "name": "cookie1",
        "value": "value1",
        "domain": ".example.com"
      }
    ]
    ```

### Platform Support

- **macOS**: Full support with automatic decryption
- **Linux/Windows**: Partial support (decryption not yet implemented)

### Notes

- Chrome must be closed for the script to access the cookies database
- The script creates a temporary copy of the database to avoid locking issues
- Cookies are decrypted using Chrome's keychain encryption key
