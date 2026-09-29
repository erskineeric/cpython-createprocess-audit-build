"""Fail-closed byte/archive helpers. Importing this module starts no work."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
import urllib.parse
import urllib.request
import zipfile

BEFORE = 'b5370463a3994370f02dcd60bf467e46d2674b44e6303b824fd4831e6bf3ecde'
AFTER = 'e0df69dbaf096fee7f21932f7b282437a6e5d630345b5e8a3e29ace5e41a59e5'
PATCHLEVEL = '16a8955952cbaefd16f85909b73a0a6c182ec813f9544a12c28897c95b8d3f22'
OLD = b'PySys_Audit("_winapi.CreateProcess", "uuu", application_name,'
NEW = b'PySys_Audit("_winapi.CreateProcess", "uOu", application_name,'
MAX_EXPANDED = 1024 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def checked_hash(data, expected):
    if not re.fullmatch(r'[0-9a-f]{64}', expected):
        raise ValueError('Invalid SHA256 token')
    if digest(data) != expected:
        raise ValueError('SHA256 mismatch')
    return data


def patch_bytes(data):
    checked_hash(data, BEFORE)
    if data.count(OLD) != 1:
        raise ValueError('Expected exactly one audit call')
    result = data.replace(OLD, NEW)
    checked_hash(result, AFTER)
    if len(result) != len(data) or sum(a != b for a, b in zip(data, result)) != 1:
        raise ValueError('Patch must change exactly one byte')
    return result


def safe_member(name, root=''):
    """Return a Windows-safe relative member; reject rather than normalize."""
    name = name[:-1] if name.endswith('/') else name
    parts = name.split('/')
    devices = {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(10)),
               *(f'LPT{i}' for i in range(10)), 'COM¹', 'COM²', 'COM³',
               'LPT¹', 'LPT²', 'LPT³'}
    for part in parts:
        if (not part or part in ('.', '..') or part[-1:] in ('.', ' ')
                or any(ord(c) < 32 or c in '\\:<>"|?*' for c in part)
                or part.split('.')[0].upper() in devices):
            raise ValueError('Unsafe archive member')
    if root:
        if parts[0] != root:
            raise ValueError('Unexpected archive root')
        parts = parts[1:]
    return PurePosixPath(*parts) if parts else None


def _members(entries, root):
    seen = set()
    total = 0
    result = []
    for entry, name, size, directory, regular in entries:
        rel = safe_member(name, root)
        if not regular and not directory:
            raise ValueError('Links and special archive entries are prohibited')
        if rel is None:
            if not directory:
                raise ValueError('Archive root is not a directory')
            continue
        key = str(rel).casefold()
        if key in seen:
            raise ValueError('Duplicate/case-colliding archive path')
        seen.add(key)
        total += size
        if size < 0 or total > MAX_EXPANDED:
            raise ValueError('Archive expansion limit')
        result.append((entry, rel, directory))
    return result


def extract_archive(archive, destination, root='', *, wheel=False, omit_links=None):
    """Prevalidate every member, then manually copy into a NEW directory."""
    destination = Path(destination)
    if destination.exists():
        raise ValueError('Extraction destination must not exist')
    iszip = zipfile.is_zipfile(archive)
    with (zipfile.ZipFile(archive) if iszip else tarfile.open(archive, 'r:xz')) as src:
        if iszip:
            entries = [(m, m.filename, m.file_size,
                        m.is_dir() and stat.S_IFMT(m.external_attr >> 16) in (0, stat.S_IFDIR),
                        not m.is_dir() and stat.S_IFMT(m.external_attr >> 16) in (0, stat.S_IFREG))
                       for m in src.infolist()]
        else:
            entries = [(m, m.name, m.size, m.isdir(), m.isfile()) for m in src.getmembers()]
        # Two pinned zstd CLI-test symlinks are irrelevant to PCbuild. They may
        # be omitted only by exact path + symlink type + target-content hash.
        # No link is ever created, followed, or silently accepted as a file.
        if omit_links:
            if wheel or not iszip:
                raise ValueError('Link omission is restricted to dependency ZIPs')
            filtered = []
            omitted = set()
            for entry in entries:
                member, name, _, _, _ = entry
                relative = str(safe_member(name, root))
                if relative in omit_links:
                    if relative in omitted or stat.S_IFMT(member.external_attr >> 16) != stat.S_IFLNK:
                        raise ValueError('Invalid pinned link omission')
                    checked_hash(src.read(member), omit_links[relative])
                    omitted.add(relative)
                else:
                    filtered.append(entry)
            if omitted != set(omit_links):
                raise ValueError('Missing pinned omitted link')
            entries = filtered
        members = _members(entries, root)
        if wheel and any(str(rel).endswith('.pth') or '.data' in rel.parts[0]
                         for _, rel, _ in members):
            raise ValueError('Wheel needs an unsupported installation hook/layout')
        destination.mkdir(parents=True)
        for member, rel, directory in members:
            target = destination.joinpath(*rel.parts)
            if directory:
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with (src.open(member) if iszip else src.extractfile(member)) as reader:
                with target.open('xb') as writer:
                    shutil.copyfileobj(reader, writer)
            if not iszip:
                os.utime(target, (member.mtime, member.mtime))


def download(url, expected, destination):
    if not re.fullmatch(r'[0-9a-f]{64}', expected):
        raise ValueError('Invalid SHA256 token')
    allowed = {'www.python.org', 'codeload.github.com', 'files.pythonhosted.org'}
    if urllib.parse.urlparse(url).scheme != 'https' or urllib.parse.urlparse(url).hostname not in allowed:
        raise ValueError('Unexpected download origin')
    request = urllib.request.Request(url, headers={'User-Agent': 'cpython-audit-build'})
    with urllib.request.urlopen(request, timeout=180) as response:
        final = urllib.parse.urlparse(response.url)
        if final.scheme != 'https' or final.hostname not in allowed:
            raise ValueError('Unexpected redirect origin')
        data = response.read(MAX_EXPANDED + 1)
    if len(data) > MAX_EXPANDED:
        raise ValueError('Download too large')
    checked_hash(data, expected)
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('xb') as stream:
        stream.write(data)
    return destination


def require_hosted():
    expected = {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                'RUNNER_OS': 'Windows', 'RUNNER_ENVIRONMENT': 'github-hosted', 'ImageOS': 'win22'}
    if os.name != 'nt' or any(os.environ.get(k) != v for k, v in expected.items()):
        raise RuntimeError('Only a manually dispatched standard windows-2022 runner is supported')


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')


def file_hash(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _reparse(info):
    return bool(getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _bootstrap_directories(root):
    # Lexical, top-down checks: never resolve through an ancestor link/junction.
    if not root.is_absolute() or '..' in root.parts:
        raise ValueError('Bootstrap root must be an absolute ordinary directory')
    for path in [*reversed(root.parents), root]:
        info = path.lstat()
        if path.is_symlink() or _reparse(info) or not stat.S_ISDIR(info.st_mode):
            raise ValueError('Bootstrap directory/ancestor is not ordinary')


def _identity(info):
    return {name: getattr(info, 'st_' + name) for name in
            ('dev', 'ino', 'mode', 'nlink', 'size', 'mtime_ns', 'ctime_ns')}


def _bootstrap_alias(root, selected):
    """Validate ONE direct file symlink without opening it or resolving chains."""
    path, target = root / 'python3.exe', root / 'python.exe'
    info = path.lstat()
    attributes = getattr(info, 'st_file_attributes', 0)
    tag = getattr(info, 'st_reparse_tag', 0)
    classification = f'mode={info.st_mode}; attributes={attributes}; reparse_tag={tag}'
    def reject(reason, raw=None):
        detail = '' if raw is None else '; raw_target=' + ascii(raw[:512])
        if raw is not None and len(raw) > 512:
            detail += ' [truncated]'
        raise ValueError('Bootstrap alias rejected: python3.exe; ' + reason + '; '
                         + classification + detail)
    if (not stat.S_ISLNK(info.st_mode) or info.st_nlink != 1 or not info.st_ino
            or attributes & stat.FILE_ATTRIBUTE_DIRECTORY
            or (os.name == 'nt' and (not _reparse(info) or tag != stat.IO_REPARSE_TAG_SYMLINK))):
        reject('not an ordinary file symlink')
    raw = os.readlink(path)  # Preserve the actual raw string, not Path.readlink normalization.
    spelling = raw
    # Windows readlink may return the extended-length local-drive spelling.
    if os.name == 'nt' and spelling.startswith('\\\\?\\'):
        spelling = spelling[4:]
        if not re.match(r'^[A-Za-z]:\\', spelling):
            reject('unexpected extended target', raw)
    candidate = Path(spelling)
    if (spelling != 'python.exe' and
            (not candidate.is_absolute() or candidate != target
             or os.path.normcase(spelling) != os.path.normcase(str(target)))):
        reject('target is not direct same-root python.exe', raw)
    if Path(selected) != target or not Path(selected).is_absolute():
        reject('target is not the selected bootstrap interpreter', raw)
    try:
        target_info = target.lstat()
    except OSError:
        reject('target is missing or unreadable', raw)
    if (not stat.S_ISREG(target_info.st_mode) or _reparse(target_info)
            or target_info.st_nlink != 1 or not target_info.st_ino):
        reject('target is not an ordinary single-link file with identity', raw)
    return {'classification': 'selected-bootstrap-file-symlink', 'raw_target': raw,
            'resolved_relative_target': 'python.exe', 'selected_executable': str(selected),
            'link_identity': _identity(info), 'target_identity': _identity(target_info),
            'link_file_attributes': attributes, 'link_reparse_tag': tag}


def inventory(root, *, exclude_dirs=(), bootstrap_executable=None):
    """Strict by default; only bootstrap snapshots opt into the exact alias proof."""
    root = Path(root)
    bootstrap = bootstrap_executable is not None
    if bootstrap:
        _bootstrap_directories(root)
    if not root.is_dir() or root.is_symlink():
        raise ValueError("Inventory root must be a real directory: '.'")
    result = {}
    alias = None
    def failed_walk(error):
        raise error
    for directory, dirs, files in os.walk(root, onerror=failed_walk):
        candidate = False
        for name in dirs + files:
            path = Path(directory) / name
            if path.is_symlink() or (bootstrap and _reparse(path.lstat())):
                relative = path.relative_to(root).as_posix()
                if bootstrap and relative == 'python3.exe':
                    if name in dirs:
                        raise ValueError('Bootstrap alias rejected: python3.exe; directory entry; target not read')
                    candidate = True
                    continue
                # All other links: lexical diagnostic only, before target reads/descent.
                detail = ascii(relative[:512])
                if len(relative) > 512:
                    detail += ' [truncated]'
                raise ValueError('Unexpected filesystem link: ' + detail)
        if candidate:
            alias = _bootstrap_alias(root, bootstrap_executable)
        dirs[:] = sorted(n for n in dirs if n not in exclude_dirs)
        for name in sorted(files):
            path = Path(directory) / name
            if alias is not None and path == root / 'python3.exe':
                continue  # Represent explicitly below; NEVER open the alias.
            if not path.is_file():
                raise ValueError('Unexpected non-file input')
            result[path.relative_to(root).as_posix()] = file_hash(path)
    if alias is not None:
        _bootstrap_directories(root)
        if (_bootstrap_alias(root, bootstrap_executable) != alias
                or 'python.exe' not in result):
            raise ValueError('Bootstrap alias or target changed during inventory')
        result['python3.exe'] = dict(alias, sha256=result['python.exe'])
    return dict(sorted(result.items()))


def verify_inventory(root, expected):
    for name, value in expected.items():
        if str(safe_member(name)) != name or not re.fullmatch('[0-9a-f]{64}', value):
            raise ValueError('Invalid inventory entry')
    if inventory(root) != expected:
        raise ValueError('Inventory missing, extra, or changed paths')


RECIPE_FILES = frozenset({
    '.gitattributes', '.github/workflows/build.yml', 'README.md', 'pins.json',
    'sigstore-wheels.lock.json', 'scripts/buildlib.py', 'scripts/build.py',
    'scripts/verify_source.py', 'scripts/audit_gate.py', 'tests/test_build.py',
})


def recipe_inventory(root):
    files = inventory(root, exclude_dirs=('.git',))
    if set(files) != RECIPE_FILES:
        raise ValueError('Publication recipe path set differs from allowlist')
    return files


def export_recipe(root, destination, expected):
    if recipe_inventory(root) != expected:
        raise ValueError('Recipe changed since input snapshot')
    destination = Path(destination)
    destination.mkdir()
    for name in sorted(RECIPE_FILES):
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(Path(root) / name, target)
    verify_inventory(destination, expected)


def archive_inventory(archive, pin, extracted):
    checked_hash(Path(archive).read_bytes(), pin['sha256'])
    return {'archive': pin, 'archive_sha256': file_hash(archive),
            'files': inventory(extracted)}


def seal_directory(root, name='manifest.json'):
    root = Path(root)
    files = inventory(root)
    files.pop(name, None)
    record = {'schema': 1, 'self_exclusion': name, 'files': files}
    write_json(root / name, record)
    verify_inventory(root, {**files, name: file_hash(root / name)})
    return record


def assert_no_pth(root):
    if any(p.name.lower().endswith('._pth') for p in Path(root).rglob('*')):
        raise ValueError('Underscore-pth files are prohibited')


# Only invocation flags in two build files; NEVER another C/runtime patch.
BUILD_HELPER_EDITS = {
    'PCbuild/python.vcxproj': (
        'af1af9d053e147b8d319c9886af6bec34935f76a906bf39a266e256b5ca2f81f',
        br'"$(OutDir)$(PyExeName)$(PyDebugExt).exe" "$(PySourcePath)PC\validate_ucrtbase.py"',
    ),
    'PCbuild/regen.targets': (
        '7c8924059672e889cfefb7151ed2d3f1e240decce53686b20bab0d7b2bac4f30',
        br'"$(PythonExe)" Programs\freeze_test_frozenmain.py',
    ),
}


def amend_build_helpers(source):
    changes = {}
    pending = []
    for name, (expected, old) in BUILD_HELPER_EDITS.items():
        path = Path(source) / name
        data = checked_hash(path.read_bytes(), expected)
        if data.count(old) != 1:
            raise ValueError('Unexpected helper invocation')
        split = old.index(b'" ', 1) + 1
        new = old[:split] + b' -S -B -s' + old[split:]
        updated = data.replace(old, new)
        pending.append((path, updated))
        changes[name] = {'before': expected, 'after': digest(updated),
                         'old': old.decode(), 'new': new.decode(),
                         'scope': 'build-only no-site/no-bytecode flags; runtime unchanged'}
    for path, updated in pending:
        path.write_bytes(updated)
    return changes


# Separately approved packaging-only import relocation; no runtime-C change.
APPX_HELPER_PATH = 'PC/layout/support/appxmanifest.py'
APPX_HELPER_BEFORE = '2ebfde12fd1c8a12b3c48ac3081ab018e68c633cb64d59b1ad0bceec5ad8af21'
APPX_HELPER_AFTER = 'b80520a2a5098aa1e154216cbcb02bb77ff7f7e6ca3299929b3718d175e18e26'


def amend_packaging_helper(source):
    path = Path(source) / APPX_HELPER_PATH
    data = checked_hash(path.read_bytes(), APPX_HELPER_BEFORE)
    old = b'import ctypes\n'
    signature = b'def get_packagefamilyname(name, publisher_id):\n'
    inserted = b'    import ctypes\n\n'
    if data.count(old) != 1 or data.count(signature) != 1:
        raise ValueError('Unexpected packaging-helper import or function')
    updated = data.replace(old, b'').replace(signature, signature + inserted)
    checked_hash(updated, APPX_HELPER_AFTER)  # Validate all bytes before any write.
    path.write_bytes(updated)
    return {APPX_HELPER_PATH: {
        'before': APPX_HELPER_BEFORE, 'after': APPX_HELPER_AFTER,
        'removed': old.decode(), 'insert_after': signature.decode(), 'inserted': inserted.decode(),
        'scope': 'packaging-only deferred ctypes import for unselected APPX; runtime C unchanged',
    }}
