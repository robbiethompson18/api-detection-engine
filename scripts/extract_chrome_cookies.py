#!/usr/bin/env python3
"""
Extract cookies from Chrome's SQLite database and decrypt them.
Works on macOS, Linux, and Windows.
"""

import argparse
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path


def get_chrome_cookie_db_path():
    """Get the path to Chrome's cookies database based on OS."""
    home = Path.home()

    if sys.platform == "darwin":  # macOS
        return home / "Library/Application Support/Google/Chrome/Default/Cookies"
    elif sys.platform == "linux":
        return home / ".config/google-chrome/Default/Cookies"
    elif sys.platform == "win32":
        return home / "AppData/Local/Google/Chrome/User Data/Default/Network/Cookies"
    else:
        raise OSError(f"Unsupported platform: {sys.platform}")


def decrypt_cookie_macos(encrypted_value):
    """Decrypt Chrome cookie on macOS using keychain."""
    try:
        import keyring
        from Crypto.Cipher import AES
        from Crypto.Protocol.KDF import PBKDF2
    except ImportError:
        print("Error: Required libraries not installed.")
        print("Install with: pip install keyring pycryptodome")
        sys.exit(1)

    # Chrome uses 'Chrome Safe Storage' as the keychain entry
    try:
        password = keyring.get_password("Chrome Safe Storage", "Chrome")
        if not password:
            print("Error: Could not retrieve Chrome encryption key from keychain")
            return None

        # Generate the key using PBKDF2
        salt = b"saltysalt"
        iterations = 1003
        key = PBKDF2(password.encode(), salt, dkLen=16, count=iterations)

        # Chrome uses AES-128 CBC
        # The encrypted value format: 'v10' + IV (16 bytes) + encrypted_data
        if encrypted_value[:3] == b'v10':
            # Remove 'v10' prefix
            encrypted_value = encrypted_value[3:]
            # IV is the first 16 bytes (space characters)
            iv = b' ' * 16
            # Decrypt
            cipher = AES.new(key, AES.MODE_CBC, IV=iv)
            decrypted = cipher.decrypt(encrypted_value)
            # Remove PKCS7 padding
            padding_length = decrypted[-1]
            return decrypted[:-padding_length].decode('utf-8')

        return None
    except Exception as e:
        print(f"Error decrypting cookie: {e}")
        return None


def extract_cookies(domain=None, output_format="string"):
    """
    Extract cookies from Chrome database.

    Args:
        domain: Optional domain to filter cookies (e.g., 'tettra.co')
        output_format: 'string' for cookie string, 'json' for JSON format

    Returns:
        str: Cookie string or JSON based on format
    """
    cookie_db = get_chrome_cookie_db_path()

    if not cookie_db.exists():
        print(f"Error: Chrome cookies database not found at {cookie_db}")
        sys.exit(1)

    # Copy the database to a temp location (Chrome locks the original)
    temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    temp_db.close()
    shutil.copy2(cookie_db, temp_db.name)

    try:
        # Connect to the database
        conn = sqlite3.connect(temp_db.name)
        cursor = conn.cursor()

        # Query cookies
        if domain:
            query = "SELECT host_key, name, encrypted_value FROM cookies WHERE host_key LIKE ?"
            cursor.execute(query, (f"%{domain}%",))
        else:
            query = "SELECT host_key, name, encrypted_value FROM cookies"
            cursor.execute(query)

        cookies = []
        cookie_string_parts = []

        for host_key, name, encrypted_value in cursor.fetchall():
            # Decrypt the cookie value
            if sys.platform == "darwin":
                value = decrypt_cookie_macos(encrypted_value)
            else:
                print("Note: Automatic decryption only supported on macOS currently")
                value = "[encrypted]"

            if value:
                cookies.append({
                    "name": name,
                    "value": value,
                    "domain": host_key
                })
                cookie_string_parts.append(f"{name}={value}")

        conn.close()

        if output_format == "json":
            import json
            return json.dumps(cookies, indent=2)
        else:
            return "; ".join(cookie_string_parts)

    finally:
        # Clean up temp file
        os.unlink(temp_db.name)


def main():
    parser = argparse.ArgumentParser(
        description="Extract and decrypt cookies from Chrome"
    )
    parser.add_argument(
        "--domain",
        "-d",
        help="Filter cookies by domain (e.g., tettra.co)",
        default=None
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["string", "json"],
        default="string",
        help="Output format: 'string' for cookie string, 'json' for JSON"
    )

    args = parser.parse_args()

    try:
        result = extract_cookies(domain=args.domain, output_format=args.format)
        print(result)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
