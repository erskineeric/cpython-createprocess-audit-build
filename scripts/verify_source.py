"""Hosted-only Sigstore verifier: hash-pinned wheels, no pip/setup/site hooks."""
import argparse
import importlib.metadata
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from buildlib import archive_inventory, checked_hash, download, extract_archive, require_hosted, write_json


def main():
    require_hosted()
    if sys.version_info[:2] != (3, 11) or not sys.flags.isolated or not sys.flags.no_site:
        raise RuntimeError('Verifier needs the runner CPython 3.11 with -I -S -B')
    parser = argparse.ArgumentParser()
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--records', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    pins = json.loads((root / 'pins.json').read_bytes())['source']
    lock = json.loads((root / 'sigstore-wheels.lock.json').read_bytes())
    paths = []
    wheel_records = {}
    for wheel in lock['wheels']:
        archive = download(wheel['url'], wheel['sha256'], args.work / 'wheels' / wheel['filename'])
        target = args.work / 'vendor' / wheel['name']
        extract_archive(archive, target, wheel=True)
        paths.append(str(target))
        wheel_records[wheel['name']] = archive_inventory(archive, wheel, target)
        write_json(args.records / 'verifier-inputs.json', wheel_records)
    # This is the first execution of downloaded verifier code, on the hosted runner only.
    # No site directory, entry-point installer, .pth processing, or dependency resolver.
    sys.path[0:0] = paths
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name
    from packaging.version import Version
    from packaging.markers import default_environment
    distributions = {canonicalize_name(d.metadata['Name']): d
                     for d in importlib.metadata.distributions(path=paths)}
    if len(distributions) != len(lock['wheels']):
        raise RuntimeError('Duplicate/missing locked distributions')
    checks = []
    for wheel in lock['wheels']:
        name = canonicalize_name(wheel['name'])
        dist = distributions[name]
        if dist.version != wheel['version'] or sorted(dist.requires or []) != sorted(wheel['requires_dist']):
            raise RuntimeError('Wheel metadata differs from reviewed wheel metadata')
        for text in dist.requires or []:
            req = Requirement(text)
            env = default_environment()
            active = any(req.marker is None or req.marker.evaluate(dict(env, extra=extra))
                         for extra in ['', *lock['extras'].get(name, [])])
            if not active:
                continue
            dep = canonicalize_name(req.name)
            if req.url or dep not in distributions or Version(distributions[dep].version) not in req.specifier:
                raise RuntimeError(f'Unsatisfied pinned dependency: {text}')
            if not req.extras.issubset(set(lock['extras'].get(dep, []))):
                raise RuntimeError(f'Unaccounted extras: {text}')
            checks.append({'from': name, 'requirement': text, 'resolved': distributions[dep].version})
    write_json(args.records / 'verifier-closure.json', checks)
    for key in list(os.environ):
        if key.startswith('SIGSTORE_'):
            del os.environ[key]
    os.environ['LOCALAPPDATA'] = str(args.work / 'verifier-cache')
    os.environ['APPDATA'] = str(args.work / 'verifier-config')
    os.environ['XDG_CACHE_HOME'] = str(args.work / 'verifier-cache')
    archive = args.work / 'downloads' / 'Python-3.14.7.tar.xz'
    bundle = archive.with_name(archive.name + '.sigstore')
    checked_hash(archive.read_bytes(), pins['sha256'])
    checked_hash(bundle.read_bytes(), pins['bundle_sha256'])
    from sigstore._cli import main as verify
    # Online TUF refresh and genuine certificate/signature/transparency validation.
    # There is intentionally no --offline, trusted-root override, or failure fallback.
    verify(['verify', 'identity', '--bundle', str(bundle),
            '--cert-identity', pins['identity'], '--cert-oidc-issuer', pins['issuer'], str(archive)])
    write_json(args.records / 'signature.json', {
        'verified': True, 'verifier': 'sigstore==4.5.0',
        'archive_sha256': pins['sha256'], 'bundle_sha256': pins['bundle_sha256'],
        'identity': pins['identity'], 'issuer': pins['issuer'],
        'method': 'Sigstore online verification with pinned verifier and TUF trust root'})


if __name__ == '__main__':
    main()
