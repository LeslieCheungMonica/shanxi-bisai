#!/usr/bin/env python3
"""Find all HTML files in a given directory."""

import os
import sys
from pathlib import Path


def find_html_files(directory: str, sub_dir: str | None = None) -> list[str]:
    """Find all HTML files in the given directory recursively."""
    html_files = []
    dir_path = Path(directory)

    if not dir_path.exists():
        raise FileNotFoundError(f"Directory not found: {directory}")

    if not dir_path.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory}")

    search_dir = directory
    if sub_dir:
        search_dir = os.path.join(directory, sub_dir)
        if not Path(search_dir).exists():
            raise FileNotFoundError(f"Sub directory not found: {sub_dir}")

    base_name = os.path.basename(os.path.abspath(directory))
    for root, _, files in os.walk(search_dir):
        for file in files:
            if file.endswith(".html"):
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, directory)
                rel_path = os.path.join(base_name, rel_path)
                rel_path = rel_path.lstrip("./")
                html_files.append(rel_path)

    return html_files


def main():
    if len(sys.argv) < 2:
        print("Usage: python find_html.py <directory_path> [sub_directory]")
        sys.exit(1)

    directory = sys.argv[1]
    sub_dir = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        html_files = find_html_files(directory, sub_dir)
        for file_path in html_files:
            print(file_path)
    except (FileNotFoundError, NotADirectoryError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
