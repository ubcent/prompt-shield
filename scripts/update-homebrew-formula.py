#!/usr/bin/env python3
"""Update Homebrew formula placeholders for a released version."""

from __future__ import annotations

import argparse
from pathlib import Path


def update_formula(path: Path, version: str, sha_arm64: str, sha_x86_64: str) -> None:
    text = path.read_text()
    text = text.replace('version "0.0.0"', f'version "{version.lstrip("v")}"')
    text = text.replace(
        'releases/download/v0.0.0/velar-darwin-arm64-v0.0.0.tar.gz',
        f'releases/download/{version}/velar-darwin-arm64-{version}.tar.gz',
    )
    text = text.replace(
        'releases/download/v0.0.0/velar-darwin-x86_64-v0.0.0.tar.gz',
        f'releases/download/{version}/velar-darwin-x86_64-{version}.tar.gz',
    )

    lines = text.splitlines()
    arm_set = False
    intel_set = False
    for i, line in enumerate(lines):
        if line.strip() == 'on_arm do':
            for j in range(i + 1, min(i + 8, len(lines))):
                if lines[j].strip().startswith('sha256 '):
                    lines[j] = f'      sha256 "{sha_arm64}"'
                    arm_set = True
                    break
        if line.strip() == 'on_intel do':
            for j in range(i + 1, min(i + 8, len(lines))):
                if lines[j].strip().startswith('sha256 '):
                    lines[j] = f'      sha256 "{sha_x86_64}"'
                    intel_set = True
                    break

    if not arm_set or not intel_set:
        raise RuntimeError(f'Failed to update sha256 in {path}')

    path.write_text('\n'.join(lines) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', required=True)
    parser.add_argument('--sha256-arm64', required=True)
    parser.add_argument('--sha256-x86_64', required=True)
    parser.add_argument('--formula', action='append', help='Formula path(s) to update')
    args = parser.parse_args()

    formulas = args.formula or ['homebrew-velar/Formula/velar.rb', 'Formula/velar.rb']
    for formula in formulas:
        update_formula(Path(formula), args.version, args.sha256_arm64, args.sha256_x86_64)
