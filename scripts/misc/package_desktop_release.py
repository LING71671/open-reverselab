#!/usr/bin/env python3
"""Stage committed runtime resources or package a signed Windows desktop release."""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[2]
STAGE = ROOT / 'desktop/src-tauri/release-resources'
OUTPUT = ROOT / 'dist/release'
RUNTIME_DIRS = {'kb', 'scripts', 'tools', 'schemas', 'fixtures', 'boards', 'templates'}


def git(*args: str) -> bytes:
    return subprocess.check_output(['git', '-C', str(ROOT), *args])


def source_archive() -> zipfile.ZipFile:
    if git('status', '--porcelain', '--untracked-files=normal').strip():
        raise SystemExit('Commit the reviewed release sources before staging or packaging.')
    return zipfile.ZipFile(io.BytesIO(git('archive', '--format=zip', 'HEAD')))


def version() -> str:
    config = json.loads((ROOT / 'desktop/src-tauri/tauri.conf.json').read_text(encoding='utf-8'))
    package = json.loads((ROOT / 'desktop/package.json').read_text(encoding='utf-8'))
    if config['version'] != package['version']:
        raise SystemExit('Desktop package and Tauri versions differ.')
    return config['version']


def stage() -> None:
    with source_archive() as archive:
        # This fixed generated directory never contains user workspaces.
        destination = STAGE.resolve()
        if destination != ROOT.resolve() / 'desktop/src-tauri/release-resources':
            raise SystemExit('Unexpected runtime staging directory.')
        if destination.exists():
            shutil.rmtree(destination)
        destination.mkdir(parents=True)
        for entry in archive.infolist():
            path = PurePosixPath(entry.filename)
            if entry.is_dir() or (len(path.parts) > 1 and path.parts[0] not in RUNTIME_DIRS):
                continue
            if path.is_absolute() or '..' in path.parts:
                raise SystemExit('Invalid path in Git archive.')
            out = destination.joinpath(*path.parts)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(archive.read(entry))
    (destination / 'RELEASE.json').write_text(json.dumps({
        'version': version(), 'commit': git('rev-parse', 'HEAD').decode().strip(),
        'platform': 'windows-x86_64',
    }, indent=2) + '\n', encoding='utf-8')
    print('Staged committed runtime resources.')


def package(installer: Path, notes: Path) -> None:
    release_version = version()
    manifest = json.loads((STAGE / 'RELEASE.json').read_text(encoding='utf-8'))
    commit = git('rev-parse', 'HEAD').decode().strip()
    if manifest['commit'] != commit or manifest['version'] != release_version:
        raise SystemExit('Runtime staging does not match HEAD/version. Stage and rebuild first.')
    binary = ROOT / 'desktop/src-tauri/target/release/desktop.exe'
    signature = Path(str(installer) + '.sig')
    if not binary.is_file() or not installer.is_file() or not signature.is_file():
        raise SystemExit('Build the signed NSIS installer before packaging.')
    source_extensions = {'.ts', '.tsx', '.rs', '.css', '.html', '.json', '.toml', '.lock', '.svg', '.png', '.ico'}
    sources = [ROOT / name for name in git('ls-files', 'desktop').decode().splitlines()]
    if any(path.suffix in source_extensions and path.stat().st_mtime > binary.stat().st_mtime for path in sources):
        raise SystemExit('Desktop source is newer than the binary. Rebuild before packaging.')
    # Tauri restores the original binary after patching an installer-specific copy,
    # so desktop.exe can legitimately have a later mtime than the installer.
    if installer.stat().st_mtime < (STAGE / 'RELEASE.json').stat().st_mtime or signature.stat().st_mtime < installer.stat().st_mtime:
        raise SystemExit('Installer or signature predates its input. Rebuild and sign together.')
    extractor = shutil.which('7z') or shutil.which('7zz')
    if not extractor:
        raise SystemExit('7-Zip is required to verify the installer runtime manifest.')
    bundled_manifest = json.loads(subprocess.check_output([extractor, 'e', '-so', str(installer), 'runtime/RELEASE.json']))
    if bundled_manifest != manifest:
        raise SystemExit('Installer runtime manifest does not match the staged release.')
    signed_text = base64.b64decode(signature.read_text(encoding='utf-8').strip()).decode('utf-8')
    comments = [line.removeprefix('trusted comment: ') for line in signed_text.splitlines() if line.startswith('trusted comment: ')]
    if len(comments) != 1 or f'version:{release_version}' not in comments[0].split('\t'):
        raise SystemExit('Installer signature does not bind the release version.')
    OUTPUT.mkdir(parents=True, exist_ok=True)
    filename = f'ReverseLab-v{release_version}-windows-x64-setup.exe'
    shutil.copy2(installer, OUTPUT / filename)
    shutil.copy2(signature, OUTPUT / (filename + '.sig'))
    portable = OUTPUT / f'ReverseLab-v{release_version}-windows-x64.zip'
    prefix = f'ReverseLab-{release_version}/'
    with source_archive() as source, zipfile.ZipFile(portable, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as dest:
        for entry in source.infolist():
            if not entry.is_dir():
                dest.writestr(prefix + entry.filename, source.read(entry))
        dest.write(binary, prefix + 'ReverseLab.exe')
        dest.write(STAGE / 'RELEASE.json', prefix + 'RELEASE.json')
    latest = {
        'version': release_version,
        'notes': notes.read_text(encoding='utf-8').strip(),
        'pub_date': datetime.now(timezone.utc).isoformat(),
        'platforms': {'windows-x86_64': {
            'signature': signature.read_text(encoding='utf-8').strip(),
            'url': f'https://github.com/LING71671/open-reverselab/releases/download/v{release_version}/{filename}',
        }},
    }
    (OUTPUT / 'latest.json').write_text(json.dumps(latest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    artifacts = [filename, filename + '.sig', portable.name, 'latest.json']
    (OUTPUT / 'SHA256SUMS').write_text(''.join(
        f'{hashlib.sha256((OUTPUT / name).read_bytes()).hexdigest()}  {name}\n' for name in artifacts
    ), encoding='utf-8')
    print(json.dumps({'version': release_version, 'commit': commit, 'artifacts': artifacts + ['SHA256SUMS']}, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('stage')
    pack = commands.add_parser('package')
    pack.add_argument('--installer', required=True, type=Path)
    pack.add_argument('--notes', required=True, type=Path)
    args = parser.parse_args()
    stage() if args.command == 'stage' else package(args.installer, args.notes)


if __name__ == '__main__':
    main()
