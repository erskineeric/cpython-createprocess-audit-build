"""Manual hosted build; importing this file does not run a compiler or probe."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from buildlib import (AFTER, BEFORE, PATCHLEVEL, amend_build_helpers, archive_inventory,
                      amend_packaging_helper,
                      assert_no_pth, checked_hash, digest, download, export_recipe,
                      extract_archive, file_hash, inventory, patch_bytes,
                      recipe_inventory, require_hosted, seal_directory,
                      verify_inventory, write_json)

ROOT = Path(__file__).resolve().parents[1]


def child_environment():
    # Forward no credentials or arbitrary Python/MSBuild/compiler/Git configuration.
    allowed = {'PATH', 'PATHEXT', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'TEMP', 'TMP',
               'PROGRAMFILES', 'PROGRAMFILES(X86)', 'PROGRAMW6432', 'SYSTEMDRIVE',
               'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'PROGRAMDATA',
               'PROCESSOR_ARCHITECTURE', 'PROCESSOR_IDENTIFIER', 'NUMBER_OF_PROCESSORS',
               'GITHUB_ACTIONS', 'GITHUB_EVENT_NAME', 'RUNNER_OS', 'RUNNER_ENVIRONMENT',
               'IMAGEOS', 'IMAGEVERSION', 'RUNNER_TEMP', 'RUNNER_TOOL_CACHE'}
    env = {k: v for k, v in os.environ.items() if k.upper() in allowed}
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    env['PYTHONNOUSERSITE'] = '1'
    if env.get('PATH') != os.environ.get('PATH'):
        raise RuntimeError('PATH must not be modified')
    return env


def run(command, log, *, cwd, env=None):
    # Exact argv, no shell, no automatic response files, retry or timeout cleanup.
    log = Path(log)
    receipt = log.with_suffix('.command.json')
    record = {'argv': [str(x) for x in command], 'cwd': str(cwd), 'state': 'started'}
    write_json(receipt, record)
    with log.open('w', encoding='utf-8') as stream:
        result = subprocess.run(record['argv'], cwd=cwd,
                                env=child_environment() if env is None else env,
                                stdout=stream, stderr=subprocess.STDOUT, check=False)
    record.update(state='finished', returncode=result.returncode, log_sha256=file_hash(log))
    write_json(receipt, record)
    if result.returncode:
        raise RuntimeError(f'{Path(command[0]).name} failed: {result.returncode}; see saved log')


def recorded_pipeline(records, operation):
    """Shared ordinary-failure boundary; tested with inert local fixtures."""
    write_json(records / 'status.json', {'state': 'running', 'runtime_exported': False})
    try:
        artifact = operation()
        write_json(records / 'status.json', {'state': 'passed', 'runtime_exported': False,
                                            'meaning': 'ready for success-gated Actions upload'})
        seal_directory(records)
        shutil.copytree(records, artifact / 'records')
        seal_directory(artifact)
        return artifact
    except BaseException as exc:
        # Never swallow failure or dump exception text/environment (possible credentials).
        write_json(records / 'status.json', {'state': 'failed', 'runtime_exported': False,
                                            'exception_type': type(exc).__name__})
        seal_directory(records)
        raise


def _root_record(name, path):
    excluded = ('site-packages',) if name == 'bootstrap' else ()
    options = {'bootstrap_executable': sys.executable} if name == 'bootstrap' else {}
    record = {'root': str(path), 'files': inventory(path, exclude_dirs=excluded, **options),
              'excluded_directories': list(excluded)}
    if name == 'bootstrap':
        record['selected_executable'] = sys.executable
    return record


def snapshot_roots(roots, records, *, expected=None):
    # A later toolchain snapshot must retain, not overwrite/rebaseline, initial proof.
    expected = {} if expected is None else expected
    if not expected.keys() <= roots.keys():
        raise RuntimeError('Missing previously snapshotted root')
    maps = {}
    for name, path in roots.items():
        record = _root_record(name, path)
        if name in expected:
            if record != expected[name]:
                raise RuntimeError('Toolchain input tree changed: ' + name)
        else:
            write_json(records / ('input-' + name + '.json'), record)
        maps[name] = record
    return maps


def verify_roots(maps):
    for name, record in maps.items():
        if _root_record(name, record['root']) != record:
            raise RuntimeError('Toolchain input tree changed: ' + name)


def version_tuple(text):
    return tuple(int(x) for x in text.split('.'))


def toolchain(work, records, bootstrap_inputs):
    installer = Path(os.environ['ProgramFiles(x86)']) / 'Microsoft Visual Studio/Installer/vswhere.exe'
    run([installer, '-products', '*', '-version', '[17.0,18.0)',
         '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
         '-latest', '-format', 'json', '-utf8'], records / 'vswhere.txt', cwd=work)
    installations = json.loads((records / 'vswhere.txt').read_text(encoding='utf-8-sig'))
    if len(installations) != 1:
        raise RuntimeError('Exactly one compatible Visual Studio 2022 installation required')
    installation = installations[0]
    vs = Path(installation['installationPath'])
    tools_version = (vs / 'VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt').read_text().strip()
    if not re.fullmatch(r'14\.(?:[3-9][0-9])\.\d+', tools_version):
        raise RuntimeError('Expected installed MSVC v143 toolset')
    vc = vs / 'VC/Tools/MSVC' / tools_version
    sdk = Path(os.environ['ProgramFiles(x86)']) / 'Windows Kits/10'
    versions = sorted((p.name for p in (sdk / 'Include').iterdir()
                       if re.fullmatch(r'10\.0\.\d+\.0', p.name)), key=version_tuple)
    if not versions or version_tuple(versions[-1]) < (10, 0, 19041, 0):
        raise RuntimeError('Compatible preinstalled Windows SDK required')
    sdk_version = versions[-1]
    msbuild = vs / 'MSBuild/Current/Bin/amd64/MSBuild.exe'
    compiler = vc / 'bin/Hostx64/x64'
    required = [installer, msbuild, compiler / 'cl.exe', compiler / 'link.exe', compiler / 'lib.exe',
                sdk / 'bin' / sdk_version / 'x64/rc.exe', sdk / 'bin' / sdk_version / 'x64/mt.exe',
                Path(sys.executable)]
    record = {'image_os': os.environ['ImageOS'], 'image_version': os.environ.get('ImageVersion'),
              'visual_studio_version': installation['installationVersion'],
              'vctools_version': tools_version, 'sdk_version': sdk_version,
              'bootstrap_python': sys.version,
              'executables': {str(p): digest(p.read_bytes()) for p in required}}
    run([msbuild, '/version', '/nologo', '/noAutoResponse'], records / 'msbuild-version.txt', cwd=work)
    # Use the installed toolset's declared redist, rather than a machine-global DLL.
    redist_version = (vs / 'VC/Auxiliary/Build/Microsoft.VCRedistVersion.default.txt').read_text().strip()
    crt = vs / 'VC/Redist/MSVC' / redist_version / 'x64/Microsoft.VC143.CRT'
    ucrt = sdk / 'Redist' / sdk_version / 'ucrt/DLLs/x64'
    if not (crt / 'vcruntime140.dll').is_file() or not (ucrt / 'ucrtbase.dll').is_file():
        raise RuntimeError('Selected app-local CRT/UCRT redistributables are missing')
    git = shutil.which('git.exe')
    if not git:
        raise RuntimeError('Preinstalled Git required for upstream build-info commands')
    roots = {'msvc': vc, 'msbuild': vs / 'MSBuild', 'vc-auxiliary': vs / 'VC/Auxiliary/Build',
             'sdk-headers': sdk / 'Include' / sdk_version,
             'sdk-ucrt-libs': sdk / 'Lib' / sdk_version / 'ucrt/x64',
             'sdk-um-libs': sdk / 'Lib' / sdk_version / 'um/x64',
             'sdk-tools': sdk / 'bin' / sdk_version / 'x64',
             'sdk-imports': sdk / 'DesignTime', 'crt': crt, 'ucrt': ucrt,
             'framework': Path(os.environ['WINDIR']) / 'Microsoft.NET/Framework64/v4.0.30319',
             'bootstrap': Path(sys.base_prefix), 'git': Path(git).resolve().parent.parent}
    maps = snapshot_roots(roots, records, expected=bootstrap_inputs)
    record['command_host'] = {os.environ['COMSPEC']: file_hash(os.environ['COMSPEC'])}
    record['input_manifests'] = {n: file_hash(records / ('input-' + n + '.json')) for n in maps}
    record['scope'] = ('Conservative selected available-input trees plus actual native read tlogs; '
                       'not a minimal used-file trace or bit-reproducibility claim. MSVC headers/libs, '
                       'SDK headers/x64 libs and tools, imported MSBuild props/targets/tasks, .NET host, '
                       'bootstrap files and Git are inventoried. Windows system DLLs/kernel, runner '
                       'services and online trust responses are outside this file closure. Bootstrap '
                       'site-packages excluded by -S; existing stdlib caches included because -B '
                       'prohibits writes, not reads. No environment or credential dump.')
    write_json(records / 'toolchain.json', record)
    return msbuild, vs, tools_version, sdk_version, crt, ucrt, git, maps


def layout_command(source, output, package, temp):
    # Built 3.14.7, not 3.11 bootstrap. All upstream layout options are opt-in.
    return [output / 'python.exe', '-S', '-B', '-s', source / 'PC/layout/main.py',
            '--source', source, '--build', output, '--copy', package, '--temp', temp,
            '--arch', 'amd64', '--include-stable']


def validate_package(package, crt, ucrt):
    assert_no_pth(package)
    for path in package.rglob('*'):
        if (path.name.lower() in {'test', 'tests', '__pycache__', 'ensurepip', 'pip', 'site-packages'}
                or path.suffix.lower() in {'.pyc', '.pyo', '.zip'}
                or (path.suffix.lower() == '.pyd'
                    and path.name.startswith(('_ctypes', '_tkinter', '_test', 'xxlimited')))):
            raise RuntimeError('Excluded package member: ' + path.relative_to(package).as_posix())
    for name in ['python.exe', 'pythonw.exe', 'python314.dll', 'python3.dll',
                 'Lib/os.py', 'Lib/encodings/__init__.py', 'LICENSE.txt', 'licenses/crtlicense.txt',
                 'DLLs/_bz2.pyd', 'DLLs/_hashlib.pyd', 'DLLs/_lzma.pyd', 'DLLs/_sqlite3.pyd',
                 'DLLs/_uuid.pyd', 'DLLs/_zstd.pyd', 'DLLs/unicodedata.pyd', 'DLLs/_ssl.pyd',
                 'DLLs/sqlite3.dll', 'DLLs/libcrypto-3.dll', 'DLLs/libssl-3.dll']:
        if not (package / name).is_file():
            raise RuntimeError('Missing package member: ' + name)
    for directory in (crt, ucrt):
        files = list(directory.glob('*.dll'))
        if not files:
            raise RuntimeError('Empty CRT DLL set')
        for file in files:
            checked_hash((package / file.name).read_bytes(), file_hash(file))


STOCK_SITE_README = 'Lib/site-packages/README.txt'
STOCK_SITE_SHA256 = 'cba8fece8f62c36306ba27a128f124a257710e41fc619301ee97be93586917cb'


def cleanup_stock_site_packages(source, package, records):
    """Remove only the exact upstream placeholder from the private package."""
    source, package = Path(source), Path(package)
    receipt = Path(records) / 'package-placeholder-cleanup.json'
    record = {'schema': 1, 'scope': 'package-only; source and runtime amendments unchanged',
              'expected': {'path': STOCK_SITE_README, 'sha256': STOCK_SITE_SHA256, 'size': 119},
              'state': 'running', 'phase': 'preflight',
              'removed_files': {}, 'removed_directories': []}
    write_json(receipt, record)  # No destructive action without an initial receipt.

    def ordinary(path, directory):
        info = path.lstat()  # Do not follow links; Python 3.11 has no is_junction().
        if (stat.S_ISLNK(info.st_mode)
                or getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
                or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
                or (not directory and info.st_nlink != 1)):
            raise ValueError('Unexpected stock-placeholder filesystem type')
        return info

    try:
        for root in (source, package):
            for relative in ('', 'Lib', 'Lib/site-packages'):
                ordinary(root / relative, True)
        source_root, package_root = source.resolve(), package.resolve()
        if source_root.is_relative_to(package_root) or package_root.is_relative_to(source_root):
            raise ValueError('Source and private package must not overlap')
        data = []
        for root in (source, package):
            directory = root / 'Lib/site-packages'
            if [p.name for p in directory.iterdir()] != ['README.txt']:
                raise ValueError('Unexpected stock-placeholder directory contents')
            path = root / STOCK_SITE_README
            if ordinary(path, False).st_size != 119:
                raise ValueError('Unexpected stock-placeholder size')
            data.append(checked_hash(path.read_bytes(), STOCK_SITE_SHA256))
        if data[0] != data[1]:
            raise ValueError('Source/package stock-placeholder bytes differ')
        record.update(source_sha256=digest(data[0]), package_sha256=digest(data[1]), phase='unlink')
        write_json(receipt, record)
        (package / STOCK_SITE_README).unlink()
        record['removed_files'][STOCK_SITE_README] = STOCK_SITE_SHA256
        record['phase'] = 'rmdir'
        write_json(receipt, record)  # Confirm the file removal before attempting rmdir.
        (package / 'Lib/site-packages').rmdir()  # Empty only; never recursive removal.
        record['removed_directories'].append('Lib/site-packages')
        record.update(state='passed', phase='complete')
        write_json(receipt, record)
    except BaseException as exc:
        # Confirm only completed operations, including a partial unlink/rmdir failure.
        # A disk failure/hard interruption may leave a running phase, never a success.
        record.update(state='failed', exception_type=type(exc).__name__)
        write_json(receipt, record)
        raise


def make_package(source, output, externals, package, crt, ucrt, temp, records, env):
    assert_no_pth(output)
    command = layout_command(source, output, package, temp)
    # Relocated build lacks a Lib landmark; -I would ignore these required private paths.
    layout_env = dict(env, PYTHONHOME=str(source), PYTHONPATH=str(output))
    run(command, records / 'layout-log.txt', cwd=source, env=layout_env)
    cleanup_stock_site_packages(source, package, records)
    for directory in (crt, ucrt):
        for file in directory.glob('*.dll'):
            shutil.copyfile(file, package / file.name)
    licenses = package / 'licenses'
    licenses.mkdir()
    shutil.copyfile(source / 'LICENSE', licenses / 'CPython.txt')
    shutil.copyfile(source / 'PC/crtlicense.txt', licenses / 'crtlicense.txt')
    for dependency in externals.iterdir():
        selected = [p for p in dependency.rglob('*') if p.is_file()
                    and p.name.lower().startswith(('license', 'copying', 'copyright'))
                    and p.suffix.lower() not in {'.py', '.c', '.h'}]
        if dependency.name == 'sqlite-3.50.4.0':
            header = (dependency / 'sqlite3.h').read_bytes()
            notice = header.split(b'*/', 1)[0] + b'*/\n'
            if b'The author disclaims copyright to this source code.' not in notice:
                raise RuntimeError('SQLite public-domain notice not found')
            destination = licenses / dependency.name
            destination.mkdir()
            (destination / 'NOTICE.txt').write_bytes(notice)
        elif not selected:
            raise RuntimeError(f'Missing dependency license: {dependency.name}')
        for file in selected:
            destination = licenses / dependency.name / file.relative_to(dependency)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(file, destination)
    write_json(package / 'build-binding.json', {
        name: digest((package / name).read_bytes()) for name in ['python.exe', 'python314.dll']})
    validate_package(package, crt, ucrt)


def capture_build_state(work, records):
    for name, directory in [('source-final.json', 'source'), ('dependencies-final.json', 'externals'),
                            ('intermediates.json', 'obj'), ('build-output.json', 'out')]:
        write_json(records / name, inventory(work / directory))


def native_inputs(work, records):
    inputs = {}
    command_count = 0
    logs = records / 'native-logs'
    logs.mkdir()
    for path in sorted((work / 'obj').rglob('*.tlog')):
        data = path.read_bytes()
        text = data.decode('utf-16') if data.startswith((b'\xff\xfe', b'\xfe\xff')) else data.decode('utf-8-sig')
        target = logs / path.relative_to(work / 'obj')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        if path.name.lower().startswith('cl.command.'):
            command_count += 1
            if '_Py_TIER2' in text or '_Py_JIT' in text:
                raise RuntimeError('Tier 2/JIT compiler definition detected')
        if '.read.' in path.name.lower():
            for line in text.splitlines():
                if not line or line.startswith('^'):
                    continue
                file = Path(line)
                if not file.is_absolute() or not file.is_file():
                    raise RuntimeError('Unresolved native input from read tlog')
                inputs[str(file)] = file_hash(file)
    if not command_count or not inputs:
        raise RuntimeError('Native input/compiler command tracking missing')
    write_json(records / 'native-read-inputs.json', inputs)
    write_json(records / 'compiler-configuration.json', {
        'cl_command_files': command_count, 'UseTIER2': '0', 'UseJIT': 'false',
        'tier2_or_jit_definitions_found': False})


def perform_build(work, records):
    work.mkdir()
    for name in ['temp', 'empty-user-props', 'out/amd64', 'obj']:
        (work / name).mkdir(parents=True)
    os.environ['TEMP'] = os.environ['TMP'] = str(work / 'temp')
    env = child_environment()
    recipe = recipe_inventory(ROOT)
    write_json(records / 'recipe.json', recipe)
    bootstrap_inputs = snapshot_roots({'bootstrap': Path(sys.base_prefix)}, records)
    pins = json.loads((ROOT / 'pins.json').read_bytes())
    source_pin = pins['source']
    archive = download(source_pin['url'], source_pin['sha256'], work / 'downloads/Python-3.14.7.tar.xz')
    download(source_pin['bundle_url'], source_pin['bundle_sha256'], archive.with_name(archive.name + '.sigstore'))
    shutil.copyfile(archive.with_name(archive.name + '.sigstore'), records / 'source.sigstore')
    verify_roots(bootstrap_inputs)
    run([sys.executable, '-I', '-S', '-B', ROOT / 'scripts/verify_source.py', '--work', work, '--records', records],
        records / 'signature-log.txt', cwd=work)
    signature = json.loads((records / 'signature.json').read_bytes())
    if signature.get('verified') is not True or signature['archive_sha256'] != source_pin['sha256']:
        raise RuntimeError('Cryptographic source verification is required')
    source = work / 'source'
    extract_archive(archive, source, source_pin['archive_root'])
    checked_hash((source / 'Include/patchlevel.h').read_bytes(), PATCHLEVEL)
    original = inventory(source)
    write_json(records / 'source-original.json', archive_inventory(archive, source_pin, source))
    run([sys.executable, '-I', '-S', '-B', ROOT / 'tests/test_build.py',
         '--source', source / 'Modules/_winapi.c', '--temp', work / 'temp', '-v'],
        records / 'static-tests.txt', cwd=work)
    target = source / 'Modules/_winapi.c'
    target.write_bytes(patch_bytes(target.read_bytes()))
    post_patch = inventory(source)
    write_json(records / 'source-post-patch.json', post_patch)
    changes = {p: {'before': original.get(p), 'after': post_patch.get(p)}
               for p in original.keys() | post_patch.keys() if original.get(p) != post_patch.get(p)}
    if changes != {'Modules/_winapi.c': {'before': BEFORE, 'after': AFTER}}:
        raise RuntimeError('Source tree changes exceed the single accepted patch')
    write_json(records / 'source-patch.json', {'source': source_pin, 'changes': changes,
                                                   'patchlevel_sha256': PATCHLEVEL})
    write_json(records / 'build-helper-amendments.json', amend_build_helpers(source))
    write_json(records / 'packaging-helper-amendment.json', amend_packaging_helper(source))
    prepared = inventory(source)
    write_json(records / 'source-build-prepared.json', prepared)
    externals = work / 'externals'
    externals.mkdir()
    dependencies = {}
    for dependency in pins['dependencies']:
        archive = download(dependency['url'], dependency['sha256'], work / 'downloads' / (dependency['name'] + '.zip'))
        extract_archive(archive, externals / dependency['name'], dependency['archive_root'],
                        omit_links=dependency.get('omit_links'))
        dependencies[dependency['name']] = archive_inventory(archive, dependency, externals / dependency['name'])
        write_json(records / 'dependencies.json', dependencies)
    msbuild, vs, vc_version, sdk_version, crt, ucrt, git, input_maps = toolchain(work, records, bootstrap_inputs)
    output = work / 'out/amd64'
    properties = dict(pins['properties'])
    properties.update({'PySourcePath': str(source) + '\\', 'Py_OutDir': str(work / 'out'),
                       'Py_IntDir': str(work / 'obj'), 'ExternalsDir': str(externals) + '\\',
                       'UserRootDir': str(work / 'empty-user-props') + '\\',
                       'VCToolsVersion': vc_version, 'WindowsTargetPlatformVersion': sdk_version,
                       'VisualStudioVersion': '17.0',
                       'VCTargetsPath': str(vs / 'MSBuild/Microsoft/VC/v170') + '\\',
                       'PythonForBuild': f'"{sys.executable}" -S -B -s',
                       'GIT': git, 'VCRuntimeDLL': str(crt / 'vcruntime140.dll'),
                       'zlibNgDir': str(externals / 'zlib-ng-2.2.4') + '\\'})
    command = [str(msbuild), str(source / 'PCbuild/pcbuild.proj'), '/t:Build', '/m:1',
               '/nr:false', '/noAutoResponse', '/nologo', '/verbosity:normal']
    command.extend(f'/p:{key}={value}' for key, value in properties.items())
    write_json(records / 'build-command.json', command)
    assert_no_pth(output)
    verify_roots(input_maps)
    try:
        run(command, records / 'build-log.txt', cwd=source / 'PCbuild', env=env)
    finally:
        capture_build_state(work, records)
    verify_roots(bootstrap_inputs)
    # Do not conceal upstream regeneration: original source members must stay byte-identical.
    unexpected = {p: (digest((source / p).read_bytes()) if (source / p).is_file() else None)
                  for p, value in prepared.items()
                  if not (source / p).is_file() or digest((source / p).read_bytes()) != value}
    if unexpected:
        write_json(records / 'unexpected-source-changes.json', unexpected)
        raise RuntimeError('Build regenerated original source bytes unexpectedly')
    for dependency in pins['dependencies']:
        verify_inventory(externals / dependency['name'], dependencies[dependency['name']]['files'])
    native_inputs(work, records)
    artifact = work / 'artifact'
    artifact.mkdir()
    package = artifact / 'python'
    make_package(source, output, externals, package, crt, ucrt, work / 'layout-temp', records, env)
    before_gate = inventory(package)
    run([package / 'python.exe', '-I', '-S', '-B', ROOT / 'scripts/audit_gate.py',
         '--package', package, '--report', records / 'audit-gate.json'],
        records / 'audit-gate-log.txt', cwd=package, env=env)
    if inventory(package) != before_gate:
        raise RuntimeError('Audit gate changed its interpreter package')
    gate = json.loads((records / 'audit-gate.json').read_bytes())
    if gate.get('passed') is not True or len(gate['cases']) != 8:
        raise RuntimeError('All eight ABI cases are required')
    verify_roots(input_maps)
    capture_build_state(work, records)
    assert_no_pth(output)
    assert_no_pth(package)
    export_recipe(ROOT, artifact / 'recipe', recipe)
    return artifact


def main():
    require_hosted()  # Before any writes, network, subprocess, or toolchain discovery.
    if (sys.version_info[:2] != (3, 11) or not sys.flags.isolated
            or not sys.flags.no_site or not sys.dont_write_bytecode):
        raise RuntimeError('Use preinstalled CPython 3.11 with -I -S -B')
    parser = argparse.ArgumentParser()
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--records', type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    runner_temp = Path(os.environ['RUNNER_TEMP']).resolve()
    if work.parent != runner_temp or work.exists():
        raise RuntimeError('Work must be a NEW direct child of RUNNER_TEMP')
    records = args.records.resolve()
    if (records.parent != runner_temp or records == work or not records.is_dir()
            or set(inventory(records)) != {'workflow-status.json'}):
        raise RuntimeError('Expected early records-only workflow directory')
    artifact = recorded_pipeline(records, lambda: perform_build(work, records))
    with Path(os.environ['GITHUB_OUTPUT']).open('a', encoding='utf-8') as output_file:
        output_file.write(f'artifact={artifact}\n')
    print('PASS: verified diagnostic package; upload is a separate Actions step')


if __name__ == '__main__':
    main()
