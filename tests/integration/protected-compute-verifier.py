#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Public upstream crypto fixtures only; never authorize a worker or task secret."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
PINS = ROOT / 'tests/integration/protected-compute-verifier-pins.json'
MAX_LOG = 2 * 1024 * 1024
EXPECTED_TESTS = ('snp::milan_chain', 'snp::milan_chain_invalid',
    'snp::milan_report', 'snp::milan_report_invalid')
EXPECTED_FILES = {'Cargo.lock', 'Cargo.toml', 'LICENSE', 'tests/certs.rs',
    'src/certs/snp/builtin/milan/ark.pem', 'src/certs/snp/builtin/milan/ask.pem',
    'src/certs/snp/builtin/milan/mod.rs', 'tests/certs_data/report_milan.hex',
    'tests/certs_data/vcek_milan.der'}
SCOPE = dict(public_fixtures_only=True, live_hardware_attestation=False,
    trusted_worker_admission=False, private_task_release=False, protected_execution_proven=False)


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def bounded(path, maximum):
    require(not path.is_symlink() and path.is_file(), 'fixture_regular_file')
    with path.open('rb') as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum, 'fixture_size_bound')
    return raw


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pins():
    value = json.loads(bounded(PINS, 32768))
    require(set(value) == {'schema_version', 'kind', 'upstream', 'toolchain',
        'default_features', 'features', 'test_target', 'test_filter', 'expected_tests',
        'files', 'scope'} and type(value['schema_version']) is int
        and value['schema_version'] == 1 and value['kind'] == 'protected-compute-verifier-pins', 'pins_schema')
    require(set(value['upstream']) == {'repository', 'url', 'commit', 'tree'}, 'upstream_schema')
    require(value['upstream']['repository'] == 'virtee/sev'
        and value['upstream']['url'] == 'https://github.com/virtee/sev'
        and value['upstream']['commit'] == 'a966d06d9bf0e68afe2733e7bfbf278fd7fd65b5'
        and value['upstream']['tree'] == '636379a232b75ad3c0f2a079acc1788dc13a920f', 'upstream_pin')
    require(value['toolchain'] == {'rust': '1.85.0'} and value['default_features'] is False
        and value['features'] == ['snp', 'crypto_nossl'] and value['test_target'] == 'certs'
        and value['test_filter'] == 'snp::' and value['expected_tests'] == list(EXPECTED_TESTS), 'fixture_selection')
    require(value['scope'] == dict(public_fixtures_only=True, hardware_executed=False,
        private_task_release=False), 'fixture_scope')
    require(set(value['files']) == EXPECTED_FILES, 'fixture_files')
    for name, record in value['files'].items():
        require(name and not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/')), 'fixture_path')
        require(set(record) == {'bytes', 'sha256'} and type(record['bytes']) is int
            and 0 < record['bytes'] <= 1024 * 1024 and re.fullmatch('[0-9a-f]{64}', record['sha256']), 'fixture_pin')
    return value


def command(source, *args):
    return subprocess.check_output(['git', '-C', str(source), *args], timeout=15).decode('ascii').strip()


def verify_source(source):
    selected = pins()
    require(source.is_dir() and not source.is_symlink(), 'source_directory')
    require(command(source, 'rev-parse', 'HEAD') == selected['upstream']['commit'], 'source_commit')
    require(command(source, 'rev-parse', 'HEAD^{tree}') == selected['upstream']['tree'], 'source_tree')
    # Both source checks run before/after the native test. Build artifacts use a
    # separate target directory and may not silently become modified source.
    require(not command(source, 'status', '--porcelain', '--untracked-files=all'), 'source_changed')
    for name, record in selected['files'].items():
        path = source / name
        require(path.resolve().is_relative_to(source.resolve()), 'fixture_path_escape')
        raw = bounded(path, record['bytes'])
        require(len(raw) == record['bytes'] and sha(raw) == record['sha256'], 'fixture_digest')
    require(bounded(source / 'LICENSE', 32768)
        == bounded(ROOT / 'third_party/licenses/virtee-sev-8.0.0-Apache-2.0.txt', 32768), 'license_identity')
    return selected


def verify_results(raw, exit_status):
    require(type(exit_status) is int and exit_status == 0, 'cargo_failed')
    require(len(raw) <= MAX_LOG, 'test_log_bound')
    text = raw.decode('utf-8', errors='strict')
    observed = re.findall(r'^test (\S+) \.\.\. (\S+)[ \t]*$', text, re.M)
    require(len(observed) == 4 and set(observed) == {(name, 'ok') for name in EXPECTED_TESTS}, 'exact_fixture_tests')
    require(len(re.findall(r'^running 4 tests\s*$', text, re.M)) == 1, 'nonempty_test_execution')
    results = re.findall(r'^test result: (.+)$', text, re.M)
    require(len(results) == 1 and re.fullmatch(
        r'ok\. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in [0-9.]+s\s*', results[0]),
        'fixture_result_summary')
    return dict(tests=list(EXPECTED_TESTS), passed=4, failed=0, ignored=0, filtered=0)


def toolchain(rustc, cargo):
    for name, raw in (('rustc', rustc), ('cargo', cargo)):
        require(len(raw) <= 32768, 'toolchain_output_bound')
        value = raw.decode('ascii')
        require(value.startswith(name + ' 1.85.0 ') and '\nrelease: 1.85.0\n' in '\n' + value + '\n',
            'toolchain_version')
    return dict(rustc_sha256=sha(rustc), cargo_sha256=sha(cargo), rust='1.85.0')


def hosted():
    require(os.environ.get('GITHUB_ACTIONS') == 'true'
        and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
        and os.environ.get('GITHUB_REPOSITORY') == 'VOLPAROSSA/volparossa'
        and os.environ.get('GITHUB_WORKFLOW') == 'Protected compute verifier fixtures'
        and os.getuid() != 0, 'explicit_disposable_hosted_only')


def capture(stream, path):
    # Stop reading on overflow, so the pipeline fails and its producer receives
    # SIGPIPE. Never upload an unbounded compiler log or treat its prefix as a pass.
    total = 0
    with path.open('xb') as output:
        while chunk := stream.read(8192):
            allowed = min(len(chunk), MAX_LOG - total)
            output.write(chunk[:allowed])
            total += len(chunk)
            require(total <= MAX_LOG, 'test_log_bound')


def main(args):
    require(args and args[0] in ('source', 'receipt', 'capture'), 'fixed_verifier_command')
    hosted()
    if args[0] == 'source':
        require(len(args) == 2, 'source_arguments')
        verify_source(Path(args[1]))
        return
    if args[0] == 'capture':
        require(len(args) == 2, 'capture_arguments')
        capture(sys.stdin.buffer, Path(args[1]))
        return
    require(len(args) == 5, 'receipt_arguments')
    require(int(args[4]) == 0, 'capture_failed')
    source, output = Path(args[1]), Path(args[2])
    selected = verify_source(source)
    raw = bounded(output / 'tests.log', MAX_LOG)
    result = verify_results(raw, int(args[3]))
    tools = toolchain(bounded(output / 'rustc.txt', 32768), bounded(output / 'cargo.txt', 32768))
    record = dict(schema_version=1, kind='protected-compute-upstream-fixture-result',
        source_commit=selected['upstream']['commit'], source_tree=selected['upstream']['tree'],
        core_commit=os.environ['GITHUB_SHA'], pins_sha256=sha(bounded(PINS, 32768)),
        cargo_lock_sha256=selected['files']['Cargo.lock']['sha256'],
        features=selected['features'], default_features=False, toolchain=tools,
        evidence=dict(log_sha256=sha(raw), log_bytes=len(raw)), tests=result, scope=SCOPE)
    # A new result only; a stale success can never survive an unsuccessful rerun.
    with (output / 'report.json').open('x', encoding='utf-8') as stream:
        json.dump(record, stream, sort_keys=True, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    main(sys.argv[1:])
