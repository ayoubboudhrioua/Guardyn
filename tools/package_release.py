"""Build a checksummed source bundle from Git-visible files, without committing."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile


def publication_files(root):
    names = subprocess.check_output(['git', 'ls-files', '-co', '--exclude-standard', '-z'], cwd=root)
    files = []
    for name in sorted(set(n.decode('utf-8') for n in names.split(b'\0') if n)):
        path = root / name
        if not path.exists():
            continue  # Deleted tracked files must not enter the bundle.
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError(f'Unsafe publication path: {name}')
        if path.name.startswith('.env') and path.name != '.env.example':
            raise ValueError(f'Environment file must not be published: {name}')
        if path.name in {'.netrc', 'id_rsa', 'id_ed25519', '.npmrc', '.pypirc'} or path.suffix in {'.pem', '.key'}:
            raise ValueError(f'Credential-like file must not be published: {name}')
        if path.is_file():
            if path.stat().st_size > 20_000_000:
                raise ValueError(f'Large file requires explicit review: {name}')
            files.append(path)
    return files


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True, help='New directory beneath dist/')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    if not output.is_relative_to(root / 'dist') or output == root / 'dist':
        raise SystemExit('Choose a new release subdirectory beneath dist/')
    files = publication_files(root)
    output.mkdir(parents=True, exist_ok=False)
    bundle = output / 'guardyn-source.zip'
    hashes = {}
    with zipfile.ZipFile(bundle, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            name = path.relative_to(root).as_posix()
            data = path.read_bytes()
            info = zipfile.ZipInfo('guardyn/' + name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
            hashes[name] = hashlib.sha256(data).hexdigest()
    with zipfile.ZipFile(bundle) as archive:
        assert archive.testzip() is None
        assert len(archive.namelist()) == len(hashes)
    manifest = {'archive': bundle.name, 'sha256': hashlib.sha256(bundle.read_bytes()).hexdigest(),
                'file_count': len(hashes), 'files': hashes,
                'git_base': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
                'note': 'Working-tree source bundle; not a Git commit, push, or claim that all benchmarks pass.'}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print(json.dumps({k: v for k, v in manifest.items() if k != 'files'}, indent=2))


if __name__ == '__main__':
    main()
