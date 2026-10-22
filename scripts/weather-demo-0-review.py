#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Hosted-only contact sheets from retained accepted Weather demo media.

Default preview is read-only. No Android rerun, SDK, installation or publication.
Packaging identity remains distinct from the original accepted runtime identity.
"""
import argparse
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import runpy
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'VOLPAROSSA/volparossa'
WEATHER = '85e9eda9bb6105866db2510758e76c9930fdde91'
PREFIX = 'weather-demo-presentation/'  # upload-artifact removes the common .cache ancestor
MAX_ZIP = 128 * 1024**2
MAX_EXPANDED = 256 * 1024**2
FONT = Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf')
REPORTS = {'weather-android-hosted-acceptance.json', 'weather-android-owner-join.json',
           'weather-android-delivery-evidence.json', 'weather-android-vm-cleanup.json'}
STATE = {'stage': 'arguments'}


class ChildFailure(ValueError):
    def __init__(self, status):
        super().__init__('child failed with status ' + str(status))
        self.status = status


def require(condition, message):
    if not condition:
        raise ValueError(message)


def decode(raw, maximum=2 * 1024**2):
    require(0 < len(raw) <= maximum, 'JSON size rejected')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def tool(path):
    path = Path(path)
    info = path.stat()
    require(path.resolve(strict=True) == path and stat.S_ISREG(info.st_mode)
            and info.st_uid == 0 and not info.st_mode & 0o022, 'root-owned distro tool required')
    return str(path)


def command(args, *, maximum=2 * 1024**2, destination=None, seconds=30, budget=None):
    """Bound both pipes, elapsed time and optional generated PNG storage."""
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'GH_HOST': 'github.com'}
    if args[0] == '/usr/bin/gh' and 'GH_TOKEN' in os.environ:
        env['GH_TOKEN'] = os.environ['GH_TOKEN']
    output, errors, total = bytearray(), bytearray(), 0
    target = destination.open('xb') if destination is not None else None
    try:
        with subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=env) as child:
            try:
                deadline = time.monotonic() + seconds
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ, 'out')
                    selector.register(child.stderr, selectors.EVENT_READ, 'err')
                    while selector.get_map():
                        remaining = deadline - time.monotonic()
                        require(remaining > 0, 'child timeout')
                        if budget is not None:
                            require(sum(p.stat().st_size for p in budget.glob('*.png')) <= MAX_ZIP,
                                    'generated image budget exceeded')
                        for key, _ in selector.select(min(remaining, 0.25)):
                            chunk = os.read(key.fileobj.fileno(), 65536)
                            if not chunk:
                                selector.unregister(key.fileobj)
                            elif key.data == 'err':
                                errors.extend(chunk)
                                require(len(errors) <= 65536, 'child diagnostic limit exceeded')
                            else:
                                total += len(chunk)
                                require(total <= maximum, 'child output limit exceeded')
                                if target is not None:
                                    target.write(chunk)
                                else:
                                    output.extend(chunk)
                    child.wait(timeout=max(0.001, deadline - time.monotonic()))
                    if child.returncode:
                        raise ChildFailure(child.returncode)
            except BaseException:
                child.kill()
                child.wait()
                raise
    finally:
        if target is not None:
            target.close()
    return bytes(output)


def api(endpoint):
    # Every caller constructs this path from constants and strict numeric IDs.
    require(re.fullmatch(r'repos/VOLPAROSSA/volparossa/actions/[A-Za-z0-9_/?=&-]+', endpoint),
            'API endpoint rejected')
    return decode(command([tool('/usr/bin/gh'), 'api', '--method', 'GET', endpoint]))


def utc(value):
    require(type(value) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value),
            'API timestamp rejected')
    return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')


def selected_artifact(run_id, attempt, revision):
    STATE['stage'] = 'run-metadata'
    base = f'repos/{REPOSITORY}/actions/runs/{run_id}'
    latest = api(base)
    run = api(base + '/attempts/' + attempt)
    for value in [latest, run]:
        require(type(value.get('id')) is int and str(value['id']) == run_id
                and type(value.get('run_attempt')) is int and str(value['run_attempt']) == attempt
                and value.get('head_sha') == revision and value.get('status') == 'completed'
                and value.get('conclusion') == 'success'
                and value.get('repository', {}).get('full_name') == REPOSITORY
                and value.get('head_repository', {}).get('full_name') == REPOSITORY,
                'successful exact latest run attempt required')
    started, finished = utc(run['run_started_at']), utc(run['updated_at'])
    require(started <= finished, 'run time window rejected')
    STATE['stage'] = 'artifact-metadata'
    listing = api(base + '/artifacts?per_page=100')
    require(type(listing.get('total_count')) is int and 1 <= listing['total_count'] <= 100
            and type(listing.get('artifacts')) is list
            and len(listing['artifacts']) == listing['total_count'], 'artifact listing incomplete')
    matches = [item for item in listing['artifacts']
               if item.get('name') == 'weather-demo-review-' + revision]
    require(len(matches) == 1, 'exact review artifact missing or ambiguous')
    artifact = matches[0]
    require(type(artifact.get('id')) is int and artifact['id'] > 0
            and artifact.get('expired') is False
            and type(artifact.get('size_in_bytes')) is int and 0 < artifact['size_in_bytes'] <= MAX_ZIP
            and type(artifact.get('digest')) is str
            and re.fullmatch(r'sha256:[a-f0-9]{64}', artifact['digest'])
            and artifact.get('workflow_run', {}).get('id') == int(run_id)
            and artifact.get('workflow_run', {}).get('head_sha') == revision
            and started <= utc(artifact['created_at']) <= utc(artifact['updated_at']) <= finished,
            'artifact identity, lifetime or digest rejected')
    # The artifact API has no attempt field. Require latest attempt and its exact creation window.
    return {key: artifact[key] for key in ['id', 'name', 'size_in_bytes', 'digest', 'created_at', 'updated_at']}


def download(artifact, path):
    STATE['stage'] = 'artifact-download'
    endpoint = f'repos/{REPOSITORY}/actions/artifacts/{artifact["id"]}/zip'
    command([tool('/usr/bin/gh'), 'api', '--method', 'GET', endpoint],
            maximum=MAX_ZIP, destination=path, seconds=120)
    require(path.stat().st_size == artifact['size_in_bytes']
            and 'sha256:' + digest(path) == artifact['digest'], 'artifact bytes or SHA-256 mismatch')


def canonical_name(name):
    require(type(name) is str and re.fullmatch(r'[A-Za-z0-9_./-]+', name)
            and not name.startswith('/') and '\\' not in name, 'ZIP path rejected')
    parts = name.rstrip('/').split('/')
    require(all(p and p not in {'.', '..'} for p in parts)
            and '.git' not in parts, 'noncanonical ZIP path')
    require(parts[0] in {'weather-demo-presentation', 'weather-demo-sources'}, 'unexpected archive root')
    return name


def zip_entries(archive):
    entries, total = {}, 0
    require(len(archive.infolist()) <= 2048, 'ZIP entry limit exceeded')
    for info in archive.infolist():
        name = canonical_name(info.filename)
        require(name.rstrip('/') not in entries and not info.flag_bits & 1, 'duplicate or encrypted ZIP entry')
        mode = info.external_attr >> 16
        require(stat.S_IFMT(mode) in {0, stat.S_IFREG, stat.S_IFDIR}
                and not stat.S_ISLNK(mode), 'ZIP nonregular entry rejected')
        require(info.is_dir() == (name.endswith('/'))
                and (not stat.S_ISDIR(mode) or info.is_dir())
                and (not info.is_dir() or info.file_size == 0), 'ZIP file type mismatch')
        total += info.file_size
        require(0 <= info.file_size <= MAX_ZIP and total <= MAX_EXPANDED, 'ZIP expanded size limit')
        entries[name.rstrip('/')] = info
    return entries


def zip_hash(archive, info):
    hashed, count = hashlib.sha256(), 0
    with archive.open(info) as stream:
        while data := stream.read(65536):
            count += len(data)
            require(count <= info.file_size and count <= MAX_ZIP, 'ZIP member size mismatch')
            hashed.update(data)
    require(count == info.file_size, 'ZIP member truncated')
    return dict(bytes=count, sha256=hashed.hexdigest())


def evidence(archive_path, destination, identity):
    STATE['stage'] = 'archive-validation'
    with zipfile.ZipFile(archive_path) as archive:
        entries = zip_entries(archive)
        require(PREFIX + 'presentation.json' in entries, 'presentation manifest missing')
        info = entries[PREFIX + 'presentation.json']
        require(info.file_size <= 2 * 1024**2, 'presentation manifest too large')
        presentation = decode(archive.read(info))
        require(presentation.get('schema') == 1
                and presentation.get('kind') == 'weather-demo-unpublished-presentation'
                and presentation.get('identity') == identity
                and presentation.get('actual_app_pixels') is True
                and presentation.get('external_core') is True
                and all(presentation.get(k) is False for k in ['physical_device', 'production_authority',
                    'publication_authorized', 'includes_installable_binaries'])
                and presentation.get('visual_review_required') is True,
                'presentation identity or scope rejected')
        files = presentation['files']
        require(type(files) is dict and 1 <= len(files) <= 2048, 'presentation inventory rejected')
        actual = {name[len(PREFIX):] for name, info in entries.items()
                  if name.startswith(PREFIX) and not info.is_dir()}
        require(actual == set(files) | {'presentation.json', 'SHA256SUMS'}, 'presentation ZIP inventory mismatch')
        selected = REPORTS | {'demo-media/recording.json', 'demo-media/screen.mp4'}
        selected |= {name for name in files if re.fullmatch(r'demo-media/screen-[0-9]{3}\.png', name)}
        require(selected <= set(files), 'original evidence subset missing')
        # Hash every manifest member in place; never extract source tarballs, rendered video or documents.
        for name, expected in sorted(files.items()):
            canonical_name(PREFIX + name)
            require(type(expected) is dict and set(expected) == {'bytes', 'sha256'}
                    and type(expected['bytes']) is int and expected['bytes'] > 0
                    and type(expected['sha256']) is str and re.fullmatch('[a-f0-9]{64}', expected['sha256'])
                    and zip_hash(archive, entries[PREFIX + name]) == expected, 'presentation member hash mismatch')
        destination.mkdir(mode=0o700)
        (destination / 'demo-media').mkdir(mode=0o700)
        for name in sorted(selected | {'presentation.json'}):
            info = entries[PREFIX + name]
            maximum = MAX_ZIP if name.endswith('.mp4') else 4 * 1024**2 if name.endswith('.png') else 2 * 1024**2
            require(info.file_size <= maximum, 'selected evidence file too large')
            with archive.open(info) as source, (destination / name).open('xb') as target:
                shutil.copyfileobj(source, target, length=65536)
            (destination / name).chmod(0o600)
    STATE['stage'] = 'original-closed-verifier'
    # verify(), unlike export(), uses the original artifact identity. Do not fake GITHUB_SHA/run env.
    verifier_path = ROOT / 'tests/integration/weather-demo-media.py'
    verifier = runpy.run_path(str(verifier_path))
    saved_token = os.environ.pop('GH_TOKEN', None)
    try:
        media = verifier['verify'](destination)
    finally:
        if saved_token is not None:
            os.environ['GH_TOKEN'] = saved_token
    require(media['identity'] == identity and media['joined_core_acceptance'] is True
            and media['production_authority'] is False, 'original media identity rejected')
    acceptance = decode((destination / 'weather-android-hosted-acceptance.json').read_bytes(), 65536)
    require(acceptance['identity'] == identity and acceptance['passed'] is True
            and acceptance['joined_core_acceptance'] is True and acceptance['vm_cleanup_pending'] is False
            and acceptance['production_authority'] is False
            and presentation['acceptance_sha256'] == media['acceptance_sha256']
            and presentation['recording_sha256'] == media['files']['screen.mp4']['sha256']
            and presentation['original_video'] == media['video'], 'cross-artifact binding rejected')
    return presentation, media, digest(verifier_path)


def contact_sheets(evidence_root, output, media):
    STATE['stage'] = 'actual-video-sampling'
    ffmpeg = tool('/usr/bin/ffmpeg')
    tool('/usr/bin/ffprobe')
    # Font data is not an executable. Match the fixed-font check of the
    # already exercised presentation renderer; keep executable checks strict.
    require(FONT.is_file() and not FONT.is_symlink(), 'fixed distro font required')
    duration = media['video']['duration_seconds']
    require(type(duration) in {int, float} and math.isfinite(duration) and 0 < duration <= 180,
            'video duration rejected')
    samples = output / 'samples'
    samples.mkdir(mode=0o700)
    # Literal controlled filter; no paths or artifact text are interpolated as filter expressions.
    graph = ('fps=1:start_time=0,drawtext=fontfile=/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf:'
             "text='Nominal %{pts\\:hms}':fontsize=25:fontcolor=white:box=1:boxcolor=black@0.8:x=8:y=8")
    command([ffmpeg, '-nostdin', '-v', 'error', '-protocol_whitelist', 'file,pipe', '-i',
        str(evidence_root / 'demo-media/screen.mp4'), '-vf', graph, '-an', '-frames:v', '180',
        '-threads', '2', '-compression_level', '6', '-start_number', '0', str(samples / 'frame-%03d.png')],
        maximum=65536, seconds=180, budget=samples)
    frames = sorted(samples.glob('frame-*.png'))
    require(1 <= len(frames) <= 180 and sum(p.stat().st_size for p in frames) <= MAX_ZIP
            and [p.name for p in frames] == [f'frame-{i:03d}.png' for i in range(len(frames))],
            'sample inventory rejected')
    for frame in frames:
        require(0 < frame.stat().st_size <= 4 * 1024**2, 'sample PNG size rejected')
        frame.chmod(0o600)
    STATE['stage'] = 'contact-sheet-render'
    sheets = []
    for start in range(0, len(frames), 30):
        sheet = output / f'contact-{start // 30:02d}.png'
        command([ffmpeg, '-nostdin', '-v', 'error', '-framerate', '1', '-start_number', str(start),
            '-i', str(samples / 'frame-%03d.png'), '-vf',
            'scale=180:320,tile=6x5:padding=4:margin=4:color=0x101827',
            '-frames:v', '1', '-threads', '2', str(sheet)], maximum=65536, seconds=60)
        require(sheet.is_file() and 0 < sheet.stat().st_size <= 8 * 1024**2, 'contact sheet rejected')
        sheet.chmod(0o600)
        sheets.append(sheet.name)
    poster_frame = frames[len(frames) // 2]
    shutil.copyfile(poster_frame, output / 'poster.png')
    (output / 'poster.png').chmod(0o600)
    return dict(font_sha256=digest(FONT), sample_hz=1, sampling='FFmpeg fps=1 at normal clip timing; nominal times, no semantic stage labels',
                sampled_frames=len(frames), contact_sheets=sheets,
                poster_source='samples/' + poster_frame.name, synthesized_app_pixels=False,
                exact_action_timestamps_asserted=False)


def hosted():
    require(os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and os.environ.get('RUNNER_OS') == 'Linux'
            and os.environ.get('GITHUB_REPOSITORY') == REPOSITORY
            and os.getuid() == os.geteuid() != 0, 'unprivileged GitHub-hosted execution required')
    require(re.fullmatch('[a-f0-9]{40}', os.environ.get('GITHUB_SHA', ''))
            and all(re.fullmatch('[1-9][0-9]{0,19}', os.environ.get(k, ''))
                    for k in ['GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT']), 'review execution identity missing')


def prepare(run_id, attempt, revision, output, execute=False):
    STATE['stage'] = 'arguments'
    require(all(type(v) is str and re.fullmatch('[1-9][0-9]{0,19}', v) for v in [run_id, attempt])
            and type(revision) is str and re.fullmatch('[a-f0-9]{40}', revision), 'strict run/attempt/SHA required')
    output = Path(output)
    require(output.is_absolute() and output == output.resolve() and output.parent.is_dir()
            and output.is_relative_to(ROOT) and output != ROOT
            and '.git' not in output.relative_to(ROOT).parts
            and not output.exists() and not output.is_symlink(), 'new workspace output required')
    identity = dict(core_commit=revision, weather_commit=WEATHER, run_id=run_id, run_attempt=attempt)
    preview = dict(schema=1, kind='weather-demo-media-review-preview', identity=identity,
                   executed=False, publication_authorized=False, visual_review_required=True,
                   downloads='Only exact same-run weather-demo-review-' + revision)
    if not execute:
        return preview
    hosted()
    packaging = dict(core_commit=os.environ['GITHUB_SHA'], run_id=os.environ['GITHUB_RUN_ID'],
                     run_attempt=os.environ['GITHUB_RUN_ATTEMPT'])
    output.mkdir(mode=0o700)  # Exclusive: existing output is never repaired or overwritten.
    try:
        artifact = selected_artifact(run_id, attempt, revision)
        archive = output / 'review.zip'
        download(artifact, archive)
        original = output / 'original'
        presentation, media, verifier_sha = evidence(archive, original, identity)
        archive.unlink()
        rendered = contact_sheets(original, output, media)
        files = {p.relative_to(output).as_posix(): dict(bytes=p.stat().st_size, sha256=digest(p))
                 for p in sorted(output.rglob('*')) if p.is_file()}
        result = dict(schema=1, kind='weather-demo-retained-media-review', identity=identity,
            review_execution=packaging, executed=True, artifact=artifact,
            original_media_verifier_sha256=verifier_sha,
            original_acceptance_sha256=presentation['acceptance_sha256'],
            original_recording_sha256=presentation['recording_sha256'],
            joined_core_acceptance_rechecked=True, new_runtime_executed=False,
            publication_authorized=False, production_authority=False,
            visual_review_required=True, visual_acceptance_claimed=False, rendered=rendered, files=files)
        (output / 'review.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
        (output / 'review.json').chmod(0o600)
        return result
    except BaseException as error:
        # Keep a closed source/run-bound failure record after removing partial downloads/frames.
        for child in output.iterdir():
            shutil.rmtree(child) if child.is_dir() else child.unlink()
        category = ('process' if isinstance(error, (ChildFailure, subprocess.SubprocessError)) else
            'io' if isinstance(error, OSError) else 'value' if isinstance(error, ValueError) else
            'key' if isinstance(error, KeyError) else 'type' if isinstance(error, TypeError) else 'unknown')
        failure = dict(schema=1, kind='weather-demo-retained-media-review-failure', identity=identity,
            review_execution=packaging, stage=STATE['stage'], category=category,
            partial_output_removed=True, visual_acceptance_claimed=False, publication_authorized=False)
        if isinstance(error, ChildFailure):
            failure['child_status'] = error.status if type(error.status) is int and -255 <= error.status <= 255 else None
        (output / 'review-failure.json').write_text(json.dumps(failure, sort_keys=True, indent=2) + '\n')
        (output / 'review-failure.json').chmod(0o600)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--attempt', required=True)
    parser.add_argument('--core-revision', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args(argv)
    previous = signal.getsignal(signal.SIGTERM)
    def interrupted(*_):
        raise InterruptedError('retained media review interrupted')
    try:
        if args.execute:
            signal.signal(signal.SIGTERM, interrupted)
        value = prepare(args.run_id, args.attempt, args.core_revision, args.output, args.execute)
        print(json.dumps(value, sort_keys=True, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, zipfile.BadZipFile, KeyboardInterrupt):
        print('Retained-media review rejected; no new runtime or visual acceptance claimed.', file=sys.stderr)
        return 1
    finally:
        if args.execute:
            signal.signal(signal.SIGTERM, previous)


if __name__ == '__main__':
    sys.exit(main())
