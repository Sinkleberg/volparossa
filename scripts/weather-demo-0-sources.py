#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare exact committed demo sources, never publish or build them.

Preview is read-only. Execution writes only a new directory inside this checkout.
External SDKs/dependencies remain pinned source recipes, not an offline vendor set.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
CHILD_TIMEOUT = 60
FORBIDDEN = {'.git', '.volparossa-dev', '.dart_tool', '.gradle', '.pub-cache',
             'node_modules', 'target', '__pycache__'}


class SourceError(Exception):
    pass


def git_environment():
    # Do not inherit alternate object databases, index/worktree overrides or config.
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
               GIT_NO_REPLACE_OBJECTS='1', GIT_TERMINAL_PROMPT='0', LC_ALL='C')
    return env


def git_command(repository, *args):
    return ['git', '-C', str(repository), '-c', 'core.attributesFile=' + os.devnull,
            '-c', 'tar.umask=0022', *args]


def git_read(repository, *args):
    result = subprocess.run(git_command(repository, *args), env=git_environment(),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=CHILD_TIMEOUT, check=False)
    if result.returncode:
        raise SourceError('git validation failed: ' + result.stderr.decode(errors='replace')[:4096])
    return result.stdout.decode().strip()


def checked_repository(path):
    if not path.is_absolute() or not path.is_dir():
        raise SourceError('repository must be an existing absolute directory')
    path = path.resolve()
    if Path(git_read(path, 'rev-parse', '--show-toplevel')).resolve() != path:
        raise SourceError('repository must name the checkout root')
    return path


def checked_revision(repository, revision):
    if not re.fullmatch('[0-9a-f]{40}', revision):
        raise SourceError('revision must be exactly 40 lowercase hexadecimal characters')
    if git_read(repository, 'cat-file', '-t', revision) != 'commit':
        raise SourceError('revision must identify a commit object, not a tree or tag')
    if git_read(repository, 'rev-parse', '--verify', revision) != revision:
        raise SourceError('commit identity mismatch')
    return revision


def checked_output(workspace, output):
    if not output.is_absolute() or output != output.resolve():
        raise SourceError('output must be absolute without symlinks or parent traversal')
    if not output.is_relative_to(workspace) or output == workspace:
        raise SourceError('output must be inside the current repository workspace')
    if FORBIDDEN.intersection(output.relative_to(workspace).parts):
        raise SourceError('output is inside a protected or cache directory')
    if output.exists() or output.is_symlink():
        raise SourceError('output already exists; overwriting is forbidden')
    if not output.parent.is_dir():
        raise SourceError('output parent must already exist')
    return output


def archive_tar(repository, revision, prefix, destination):
    """Stream bounded Git output and diagnostics, killing/reaping on every failure."""
    command = git_command(repository, 'archive', '--format=tar', '--prefix=' + prefix, revision)
    with subprocess.Popen(command, env=git_environment(), stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE) as child:
        try:
            with selectors.DefaultSelector() as selector, destination.open('xb') as target:
                selector.register(child.stdout, selectors.EVENT_READ, 'archive')
                selector.register(child.stderr, selectors.EVENT_READ, 'error')
                total = 0
                error = bytearray()
                deadline = time.monotonic() + CHILD_TIMEOUT
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise SourceError('git archive timeout')
                    for key, _ in selector.select(min(remaining, 0.25)):
                        data = os.read(key.fileobj.fileno(), 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                        elif key.data == 'archive':
                            total += len(data)
                            if total > MAX_ARCHIVE_BYTES:
                                raise SourceError('source archive exceeds size limit')
                            target.write(data)
                        else:
                            error.extend(data)
                            if len(error) > 65536:
                                raise SourceError('git archive diagnostic limit exceeded')
                child.wait(timeout=max(0.001, deadline - time.monotonic()))
                if child.returncode:
                    raise SourceError('git archive failed: ' + error.decode(errors='replace'))
        except BaseException:
            child.kill()
            child.wait()
            raise


def checked_tar(path, prefix):
    notices = []
    with tarfile.open(path, mode='r:') as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            if name.is_absolute() or '..' in name.parts or name.parts[0] != prefix.rstrip('/'):
                raise SourceError('unsafe source archive path')
            relative = PurePosixPath(*name.parts[1:])
            if FORBIDDEN.intersection(relative.parts):
                raise SourceError('committed cache or Git administration path in sources')
            if not (member.isdir() or member.isfile() or member.issym()):
                raise SourceError('unsupported source archive entry')
            if member.issym():
                link = PurePosixPath(member.linkname)
                if link.is_absolute() or '..' in link.parts:
                    raise SourceError('unsafe source symlink')
            if member.isfile() and (relative.name in {'LICENSE', 'LICENSE.txt', 'COPYING', 'NOTICE',
                                                       'THIRD_PARTY_LICENSES.md'}
                                    or str(relative).startswith('third_party/')):
                notices.append(str(relative))
    if 'LICENSE' not in notices:
        raise SourceError('source archive must retain its original root LICENSE')
    return sorted(notices)


def bundle(core, core_revision, weather, weather_revision, output):
    # mkdir is exclusive, so even an intervening creator cannot be overwritten.
    output.mkdir(mode=0o700)
    try:
        sources = {}
        with tempfile.TemporaryDirectory(prefix='.source-tar-', dir=output) as temporary:
            for component, repository, revision in [('core', core, core_revision),
                                                     ('weather', weather, weather_revision)]:
                prefix = 'weather-demo-0.1.0-' + component + '/'
                tar_path = Path(temporary) / (component + '.tar')
                archive_tar(repository, revision, prefix, tar_path)
                notices = checked_tar(tar_path, prefix)
                filename = component + '-source.tar.gz'
                compressed = output / filename
                with tar_path.open('rb') as source, compressed.open('xb') as target:
                    with gzip.GzipFile(filename='', mode='wb', fileobj=target, mtime=0,
                                       compresslevel=9) as zipped:
                        shutil.copyfileobj(source, zipped, length=65536)
                sources[component] = dict(commit=revision, archive=filename, prefix=prefix,
                    bytes=compressed.stat().st_size,
                    sha256=hashlib.sha256(compressed.read_bytes()).hexdigest(),
                    retained_notices_and_provenance=notices)
        manifest = dict(schema=1, proposed_prerelease='weather-demo-0.1.0',
            kind='committed-sources-only', sources=sources,
            upstream_pin_notices=[
                'Original licenses, provenance, lockfiles, patches and source recipes are retained as committed.',
                'External pinned SDKs and third-party dependencies referenced by those recipes are not fetched or vendored here.',
                'This is not a full offline vendor bundle, runtime acceptance, installable distribution or publication authorization.'])
        (output / 'source-manifest.json').write_text(
            json.dumps(manifest, sort_keys=True, indent=2) + '\n', encoding='utf-8')
        return manifest
    except BaseException:
        shutil.rmtree(output)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core-revision', required=True)
    parser.add_argument('--weather-repository', required=True, type=Path)
    parser.add_argument('--weather-revision', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--execute', action='store_true', help='write sources; default is read-only preview')
    args = parser.parse_args(argv)
    try:
        core = checked_repository(Path(__file__).resolve().parent.parent)
        weather = checked_repository(args.weather_repository)
        core_revision = checked_revision(core, args.core_revision)
        weather_revision = checked_revision(weather, args.weather_revision)
        output = checked_output(core, args.output)
        if args.execute:
            result = bundle(core, core_revision, weather, weather_revision, output)
        else:
            result = dict(mode='preview', core_revision=core_revision,
                          weather_revision=weather_revision,
                          files=['core-source.tar.gz', 'weather-source.tar.gz', 'source-manifest.json'],
                          action='No files written. Use --execute to prepare local source archives.')
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except (SourceError, OSError, subprocess.SubprocessError, tarfile.TarError) as error:
        print('source bundle failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
