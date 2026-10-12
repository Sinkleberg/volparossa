#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Real owner CLI/core maintenance over the existing disposable protected topology."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import signal
import stat
import subprocess
import sys
import threading
import time

F = runpy.run_path(str(Path(__file__).with_name('private-storage-fragments-smoke.py')))
SAMPLER = runpy.run_path(str(Path(__file__).with_name('private-storage-log-sampler.py')))
read, require = F['read'], F['require']
private_root, private_file, create, invoke, unlock = (F[key] for key in
    ('private_root', 'private_file', 'create', 'invoke', 'unlock'))
BYTES, CHUNK, LENGTHS, SHA = (F[key] for key in ('BYTES', 'CHUNK', 'LENGTHS', 'SHA'))
A_BYTES = F['PROVIDER_BYTES'][0]
FG = b'VOLPAROSSA independent foreground fixture'.ljust(64, b'.')
MAX_CHARGE = 2 * BYTES + A_BYTES
# This is the existing enclosing timeout, not a new per-stage allowance. The
# coordinator alone may spend 30s starting the daemon, 60s on inventory and
# 600s selecting its protected route before it publishes ready.json.
LIFECYCLE_SECONDS = 1800
# Closed parsing limits, not grants or a prediction of daemon tick timing.
# Keep the unchanged 256KiB owner-output bound while allowing ordinary turns
# during coordinator preparation. Later repair/retirement adds at most 12+4.
MAX_LIFECYCLE_CURSOR = 128
MAX_CURSOR = MAX_LIFECYCLE_CURSOR + 12 + 4
EXPORT_NAMES = tuple(name for name in F['EXPORT_NAMES'] if name not in
    ('private-storage-fragments-smoke.json', 'private-storage-fragments-evidence.json')) + (
    'private-storage-maintenance-smoke.json', 'private-storage-maintenance-evidence.json',
    'private-storage-maintenance-lifecycle.json',
    'private-storage-maintenance-lifecycle-failure.json',
    'private-storage-fragments-lifecycle-live-selection.json',
    'private-storage-fragments-lifecycle-gates.json',
    'content-provider-adaptive-private-storage-fragments-lifecycle-control.json',
    *(f'private-storage-fragments-lifecycle-privacy-{role}.json' for role in F['ROLES']))
SCOPE_FALSE = ('independent_failure_domains_proven', 'network_contribution_credit',
    'archive_encryption_proven', 'automatic_archive_discovery', 'automatic_grant_refresh',
    'contribution_resize_proven', 'full_alpha_acceptance_claimed')
STAGE = 'not_started'
TURN_DIAGNOSTIC = None
RETIREMENT_DIAGNOSTIC = None
RETIREMENT_TURNS = []
SAMPLER_DIAGNOSTIC = {}
LIFECYCLE_DIAGNOSTIC = None
LIFECYCLE_STAGES = ('checkpoint_before', 'spawn_owner', 'await_working', 'await_core_loss',
    'verify_retained', 'await_coordinator', 'validate_coordinator', 'start_sampler',
    'await_resumed_turn', 'stop_owner', 'verify_pause', 'fresh_owner_turn',
    'reconcile_progress', 'validate_flow_coverage', 'publish_result')
CHECKPOINT_STAGES = ('enrolled', 'owner_locked', 'waiting_for_core', 'working', 'paused',
    'enrollment_expired', 'core_unavailable', 'core_turn_revoked', 'turn_completed', 'retry_pending')
FAILURE_CODES = {
    'maintenance checkpoint scope': 'checkpoint_scope',
    'core turn not observed': 'turn_not_observed',
    'independent foreground operation not acknowledged': 'foreground_receipt',
    'bounded owner output': 'owner_output_bound',
    'owner process exit': 'owner_exit',
    'cursor did not resume exactly one turn': 'cursor_mismatch',
    'owner EOF was not during an admitted turn': 'owner_eof_stage',
    'foreground did not revoke the core turn': 'foreground_revoke_stage',
    'maintenance did not complete a core turn': 'turn_stage',
    'replacement set incomplete before retirement': 'retirement_initial_counts',
    'placement journal exceeds bound': 'placement_journal_bound',
    'unbounded retirement readbacks': 'retirement_readbacks',
    'duplicate replacement after restart': 'retirement_duplicate_placement',
    'signed replacement identities changed': 'retirement_identity',
    'source retirement unconfirmed': 'retirement_pending_or_charge',
    'private replica CLI operation failed': 'cli_exit',
    'replica diagnostics exceeded fixture bound': 'cli_output_bound',
    'owner lifecycle deadline': 'lifecycle_deadline',
    'lifecycle initial cursor': 'lifecycle_initial_cursor',
    'core loss changed charged custody': 'lifecycle_charge_changed',
    'core loss changed enrollment': 'lifecycle_enrollment_changed',
    'invalid fixture coordinator reply': 'lifecycle_coordinator_invalid',
    'SIGTERM did not persist pause': 'lifecycle_pause_missing',
    'enrollment changed across core restart': 'lifecycle_enrollment_changed',
    'resume cursor changed': 'lifecycle_cursor_changed',
    'restart charge reconciliation': 'lifecycle_reconciliation',
    'owner output not drained': 'owner_output_not_drained',
}
PRESELECTION_REASON_CODES = (
    'PRESELECTION_SAMPLE_NO_EXIT', 'PRESELECTION_SAMPLE_INSUFFICIENT_RELAYS',
    'PRESELECTION_SAMPLE_INVALID_POLICY', 'PRESELECTION_SAMPLE_INVALID_SNAPSHOT',
    'PRESELECTION_SAMPLE_ENTROPY',
)


def closed_diagnostic_text(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= maximum
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.geteuid(),
            'invalid private diagnostic file')
        data = stream.read(maximum + 1)
        require(len(data) <= maximum, 'private diagnostic size')
    return data.decode('ascii')


def closed_preselection_events(path, baseline_path, end_path):
    # Reuse the closed cooperative-browser event-ring grammar, but exclude all
    # records outside this selection's private start/end wall-clock bounds. These
    # are event counts in a selection window, not attribution to its final attempt.
    value = dict(version=1, state='unknown', observed_reason='unknown', uncertainty='absent_baseline',
        scope='selection_window_not_last_attempt_proof', limit=400, records=None,
        fresh_records=None, stale_records=None, later_records=None, counts=None, unrecognized_reason_records=None,
        window_covers_baseline=None)
    captured_at_ms = time.time_ns() // 1_000_000
    try:
        raw_baseline = closed_diagnostic_text(baseline_path, 32)
        require(re.fullmatch(r'[0-9]{1,20}\n', raw_baseline) is not None, 'invalid selection baseline')
        baseline = int(raw_baseline)
        require(0 < baseline <= captured_at_ms, 'invalid selection clock')
    except FileNotFoundError:
        return value
    except (OSError, ValueError, UnicodeError):
        value['uncertainty'] = 'invalid_baseline'
        return value
    value['uncertainty'] = 'absent_window_end'
    try:
        raw_end = closed_diagnostic_text(end_path, 32)
        require(re.fullmatch(r'[0-9]{1,20}\n', raw_end) is not None, 'invalid selection end')
        selection_end = int(raw_end)
        require(baseline <= selection_end <= captured_at_ms, 'invalid selection clock')
    except FileNotFoundError:
        return value
    except (OSError, ValueError, UnicodeError):
        value['uncertainty'] = 'invalid_window_end'
        return value
    value['uncertainty'] = 'absent'
    try:
        lines = closed_diagnostic_text(path, 131072).splitlines()
        require(len(lines) <= 400, 'preselection event ring exceeded')
        counts = dict.fromkeys(PRESELECTION_REASON_CODES, 0)
        fresh, stale, later, unrecognized, previous = 0, 0, 0, 0, 0
        first = None
        for line in lines:
            match = re.fullmatch(r'([0-9]{1,20})\tlevel=([0-9])\tevent=([A-Z0-9_]{1,96})'
                r'\tsession=[0-9a-f]{0,64}\tpath=(?:-|[0-9]{1,10})', line)
            require(match is not None, 'invalid bounded preselection event record')
            timestamp = int(match[1])
            require(timestamp > 0, 'invalid event clock')
            if timestamp < previous or timestamp > captured_at_ms:
                value['uncertainty'] = 'clock_regression'
                return value
            previous = timestamp
            if first is None:
                first = timestamp
            if timestamp <= baseline:
                stale += 1
                continue
            if timestamp > selection_end:
                later += 1
                continue
            fresh += 1
            if match[3] in counts:
                counts[match[3]] += 1
            elif match[3].startswith('PRESELECTION_SAMPLE_'):
                unrecognized += 1
        value.update(records=len(lines), fresh_records=fresh, stale_records=stale, later_records=later, counts=counts,
            unrecognized_reason_records=unrecognized,
            window_covers_baseline=first is not None and first <= baseline)
        observed = [code for code, count in counts.items() if count]
        if len(lines) == 400:
            value['uncertainty'] = 'ring_at_capacity'
        elif unrecognized:
            value['uncertainty'] = 'unrecognized'
        elif len(observed) > 1:
            value['uncertainty'] = 'ambiguous'
        elif not observed:
            value['uncertainty'] = 'no_fresh_signal'
        else:
            value.update(state='known', observed_reason=observed[0], uncertainty=None)
    except FileNotFoundError:
        pass
    except (OSError, ValueError, UnicodeError):
        value['uncertainty'] = 'invalid'
    return value


def failure_code(error):
    # Exact fixed messages only; never export arbitrary exception strings or CLI output.
    if isinstance(error, subprocess.TimeoutExpired):
        return 'cli_timeout'
    if isinstance(error, subprocess.SubprocessError):
        return 'cli_process'
    if isinstance(error, OSError):
        return 'local_io'
    return FAILURE_CODES.get(str(error), 'unclassified')


def bounded_count(value, maximum):
    return value if type(value) is int and 0 <= value <= maximum else None


def turn_checkpoint(value):
    value = value if isinstance(value, dict) else {}
    TURN_DIAGNOSTIC['cursor_after'] = bounded_count(value.get('turns'), MAX_CURSOR)
    stage = value.get('stage')
    TURN_DIAGNOSTIC['checkpoint_stage'] = stage if stage in (
        'enrolled', 'owner_locked', 'working', 'paused', 'enrollment_expired',
        'core_unavailable', 'core_turn_revoked', 'turn_completed', 'retry_pending') else None
    detail = value.get('detail')
    stage = detail.get('maintenance_stage') if isinstance(detail, dict) else None
    TURN_DIAGNOSTIC['maintenance_stage'] = stage if stage in (
        'observed', 'maintained', 'charge_limit', 'grant_refresh_required') else None


def retirement_counts(value, turn):
    global RETIREMENT_DIAGNOSTIC
    value = value if isinstance(value, dict) else {}
    RETIREMENT_DIAGNOSTIC = dict(turn=bounded_count(turn, 4),
        pending_retirements=bounded_count(value.get('pending_retirements'), 4),
        placement_authorizations=bounded_count(value.get('placement_authorizations'), 4),
        retained_copy_records=bounded_count(value.get('retained_copy_records'), 12))


def renewal_outcomes(value):
    """Only fixed engine outcomes; at most three retained copies in this fixture."""
    if not isinstance(value, list) or len(value) > 3:
        return None
    return [item if item in ('retiring_not_renewed', 'explicitly_deleted',
        'unavailable_or_grant_invalid', 'unknown_reservation_use_deposit_retry',
        'unconfirmed_retained', 'renewal_outside_original_grant',
        'existing_retention_sufficient', 'confirmed') else None for item in value]


def handoff_outcomes(value):
    """One admitted handoff per turn, without keys, archive IDs or free-form errors."""
    if not isinstance(value, list) or len(value) > 1:
        return None
    result = []
    for item in value:
        item = item if isinstance(item, dict) else {}
        stage = item.get('handoff_stage')
        result.append(dict(index=bounded_count(item.get('index'), len(LENGTHS) - 1),
            handoff_stage=stage if stage in ('complete', 'survivor_unavailable',
                'replacement_upload_pending', 'replacement_verification_pending',
                'replacement_retention_insufficient', 'source_delete_unconfirmed') else None,
            resumed_signed_intent=item.get('resumed_signed_intent')
                if type(item.get('resumed_signed_intent')) is bool else None,
            replacement_verified_this_pass=item.get('replacement_verified_this_pass')
                if type(item.get('replacement_verified_this_pass')) is bool else None,
            operation_complete=item.get('operation_complete')
                if type(item.get('operation_complete')) is bool else None))
    return result


def retirement_turn(value, turn):
    """Project existing owner checkpoint fields, never the private checkpoint itself."""
    if type(turn) is not int or not 1 <= turn <= 4 or len(RETIREMENT_TURNS) >= 4:
        return
    value = value if isinstance(value, dict) else {}
    detail = value.get('detail')
    detail = detail if isinstance(detail, dict) else {}
    refresh = detail.get('refresh')
    refresh = refresh if isinstance(refresh, dict) else {}
    stage = detail.get('repair_stage')
    maintenance = detail.get('maintenance_stage')
    RETIREMENT_TURNS.append(dict(turn=turn, cursor=bounded_count(value.get('turns'), MAX_CURSOR),
        maintenance_stage=maintenance if maintenance in (
            'observed', 'maintained', 'charge_limit', 'grant_refresh_required') else None,
        repair_stage=stage if stage in ('complete', 'repair_pending', 'pass_limit',
            'pending_grant_unavailable', 'no_eligible_candidate', 'pending_handoff',
            'retirement_pending') else None,
        attempted_handoffs=bounded_count(detail.get('attempted_handoffs'), 1),
        freshly_verified_replacements=bounded_count(detail.get('freshly_verified_replacements'), 1),
        pending_retirements=bounded_count(detail.get('pending_retirements'), 4),
        physical_payload_charge_upper_bound=bounded_count(
            detail.get('physical_payload_charge_upper_bound'), MAX_CHARGE),
        fragment_outcomes=handoff_outcomes(detail.get('fragment_outcomes')),
        refresh=dict(fragment_index=bounded_count(refresh.get('fragment_index'), len(LENGTHS) - 1),
            renewal=refresh.get('renewal') if type(refresh.get('renewal')) is bool else None,
            operation_complete=refresh.get('operation_complete')
                if type(refresh.get('operation_complete')) is bool else None,
            copy_outcomes=renewal_outcomes(refresh.get('copy_outcomes')))))


def failure_receipt(error):
    if LIFECYCLE_DIAGNOSTIC is not None:
        return dict(version=1, success=False, kind='private-storage-maintenance-lifecycle-failure',
            code='sampler_failure' if isinstance(error, SAMPLER['SamplerFailure']) else failure_code(error),
            **LIFECYCLE_DIAGNOSTIC, sampler=SAMPLER_DIAGNOSTIC or None)
    return dict(version=1, success=False, kind='private-storage-maintenance-failure', stage=STAGE,
        code='sampler_failure' if isinstance(error, SAMPLER['SamplerFailure']) else failure_code(error),
        turn=TURN_DIAGNOSTIC, retirement=RETIREMENT_DIAGNOSTIC,
        retirement_turns=RETIREMENT_TURNS,
        sampler=SAMPLER_DIAGNOSTIC or None)


def validate_lifecycle_failure(value):
    """Reject rather than copy unknown fields from even fixture-owned output."""
    require(isinstance(value, dict) and set(value) == {'version', 'success', 'kind', 'code', 'stage',
        'cursor_before', 'cursor_last', 'checkpoint_stage', 'owner_exit_status', 'owner_joined',
        'cleanup_error', 'sampler'}, 'invalid lifecycle failure')
    codes = set(FAILURE_CODES.values()) | {'cli_timeout', 'cli_process', 'local_io', 'unclassified', 'sampler_failure'}
    require(type(value['version']) is int and value['version'] == 1 and value['success'] is False
        and value['kind'] == 'private-storage-maintenance-lifecycle-failure'
        and value['stage'] in LIFECYCLE_STAGES and value['code'] in codes, 'invalid lifecycle failure')
    for key in ('cursor_before', 'cursor_last'):
        require(value[key] is None or type(value[key]) is int and 0 <= value[key] <= MAX_LIFECYCLE_CURSOR,
            'invalid lifecycle failure')
    require(value['checkpoint_stage'] is None or value['checkpoint_stage'] in CHECKPOINT_STAGES,
        'invalid lifecycle failure')
    require(value['owner_exit_status'] is None or type(value['owner_exit_status']) is int
        and -128 <= value['owner_exit_status'] <= 255, 'invalid lifecycle failure')
    require(type(value['owner_joined']) is bool and (value['cleanup_error'] is None
        or value['cleanup_error'] in codes), 'invalid lifecycle failure')
    sampler = value['sampler']
    if sampler is not None:
        fields = {'phase', 'operation', 'code', 'samples', 'completed', 'failed'}
        require(isinstance(sampler, dict) and fields <= set(sampler)
            and set(sampler) <= fields | {'route_mismatch', 'paths_process'}, 'invalid lifecycle sampler')
        require(sampler['phase'] in ('initial', 'sampling', 'final_drain')
            and sampler['operation'] in ('route_query', 'route_scope', 'exit_log_query', 'coverage', 'completion')
            and sampler['code'] in ('timeout', 'process', 'local_io', 'invalid', 'deadline'), 'invalid lifecycle sampler')
        for name, maximum in (('samples', SAMPLER['MAX_SAMPLES']),
                ('completed', SAMPLER['MAX_SAMPLES'] * SAMPLER['LIMIT']),
                ('failed', SAMPLER['MAX_SAMPLES'] * SAMPLER['LIMIT'])):
            require(type(sampler[name]) is int and 0 <= sampler[name] <= maximum, 'invalid lifecycle sampler')
        if 'route_mismatch' in sampler:
            require(sampler['route_mismatch'] in ('reply_bound', 'line_format', 'path_state', 'zero_context',
                'exit_changed', 'context_count', 'path_count', 'path_ids_changed', 'relays_changed'), 'invalid lifecycle sampler')
        if 'paths_process' in sampler:
            paths = sampler['paths_process']
            require(isinstance(paths, dict) and set(paths) == {'exit_status', 'diagnostic', 'stderr_state'}
                and (paths['exit_status'] is None or type(paths['exit_status']) is int and -128 <= paths['exit_status'] <= 255)
                and paths['diagnostic'] in ('UNRECOGNIZED', 'CLIENT_ROUTE_BUSY', 'MPQUIC_PATH_STATUS_UNAVAILABLE')
                and paths['stderr_state'] in ('unavailable', 'oversize', 'bounded'), 'invalid lifecycle sampler')
    return value


def lifecycle_failure_file(path):
    return validate_lifecycle_failure(json.loads(closed_diagnostic_text(path, 8192)))


OWNER_TEST_PREFIX = 'storage::peer::replicas::fragments::maintenance::tests::'
OWNER_REQUIRED_TESTS = {
    'enrollment_signature_private_mode_and_restart_cursor_are_retained',
    'owner_maintenance_renews_repairs_one_copy_and_retains_uncertain_charge_across_restart',
    'three_provider_maintenance_retires_all_originals_with_exact_candidate_grants',
    'service::owner_loop_reconnects_without_reenrollment_and_preserves_restart_cursor',
    'service::shutdown_during_reconnect_keeps_authority_and_retained_charge_for_restart',
    'service::expired_enrollment_never_reconnects_or_advances_work',
    'service::live_turn_loss_reconnects_and_reconciles_original_journals_without_new_leases',
    'service::finite_authority_expires_while_waiting_for_core_response_and_closes_connection',
    'expiry::expired_cap_cannot_plan_and_foreground_expiry_is_unchanged',
    'expiry::expired_during_challenge_does_not_sign_any_new_operation',
    'expiry::signing_does_not_rewrite_over_cap_retained_reserve_or_renew',
    'expiry::delayed_progress_renewal_keeps_original_signed_enrollment_expiry',
    'expiry::repair_after_delayed_refresh_keeps_original_signed_enrollment_expiry',
}


def owner_test_output(stream, diagnostic=None):
    """Bound actual libtest stdout; require executed named passes, not a --list."""
    data = stream.read(65537)
    if diagnostic is not None:
        # Preserve ordinary synthetic unit-test diagnostics, never owner runtime
        # output. This is bounded CI logging, not an artifact or passing receipt.
        suffix = b'\nOWNER_TEST_OUTPUT_LIMIT_EXCEEDED\n' if len(data) > 65536 else b''
        diagnostic.write(data[:65536 - len(suffix)] + suffix)
        diagnostic.flush()
    require(len(data) <= 65536, 'owner test output bound')
    text = data.decode('utf-8')
    rows = re.findall(r'^test ([a-zA-Z0-9_:]+) \.\.\. (ok|FAILED|ignored)$', text, re.M)
    require(0 < len(rows) <= 256 and len({name for name, _ in rows}) == len(rows)
        and all(name.startswith(OWNER_TEST_PREFIX) and result == 'ok' for name, result in rows)
        and {OWNER_TEST_PREFIX + name for name in OWNER_REQUIRED_TESTS} <= {name for name, _ in rows},
        'required owner tests did not execute')
    summaries = re.findall(r'^test result: ok\. ([0-9]+) passed; 0 failed; 0 ignored; 0 measured; '
        r'[0-9]+ filtered out; finished in [0-9.]+s$', text, re.M)
    require(summaries == [str(len(rows))], 'owner test result mismatch')
    return dict(version=1, kind='executed-owner-maintenance-tests', passed=len(rows),
        required_passed=len(OWNER_REQUIRED_TESTS), failed=0, ignored=0)


def private_json(path, maximum=32768):
    require(private_file(path).st_size <= maximum, 'private record bound')
    return json.loads(path.read_bytes())


def existing(root):
    return F['existing'](root)


def status(root, binary, client, *, budget=None):
    return invoke(binary, client, ['storage', 'fragments', 'status', '--state', root / 'fragment-set'],
        deadline=180 if budget is None else budget.remaining(180))


def checkpoint(root, binary, client, *, budget=None):
    value = invoke(binary, client, ['storage', 'fragments', 'maintenance', 'status',
        '--enrollment', root / 'maintenance'], deadline=180 if budget is None else budget.remaining(180))
    require(value['version'] == 1 and value['scope'] == 'owner-private-maintenance'
        and type(value['turns']) is int and 0 <= value['turns'] <= MAX_CURSOR
        and value['core_coordinated'] is True and value['new_network_node'] is False
        and value['automatic_grant_refresh'] is False and value['private_key_exported'] is False,
        'maintenance checkpoint scope')
    return value


def peer_args(root, key):
    return ['--state', root / 'foreground', '--provider-key', key, *unlock(root)]


def run_turn(root, binary, client, key_b, interrupt=None, *, budget=None):
    """One real daemon-issued turn; no owner-side scheduler or direct provider socket."""
    global TURN_DIAGNOSTIC
    TURN_DIAGNOSTIC = dict(substage='checkpoint_before', cursor_before=None, cursor_after=None,
        worker_exit_status=None, checkpoint_stage=None, maintenance_stage=None, cleanup_error=None)
    before = checkpoint(root, binary, client, budget=budget)['turns']
    TURN_DIAGNOSTIC.update(cursor_before=before, substage='spawn_owner')
    process = subprocess.Popen([binary, '--control-socket', client, 'storage', 'fragments',
        'maintenance', 'serve', '--enrollment', str(root / 'maintenance'), '--maximum-turns', '1',
        *map(str, unlock(root))], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    owner_failed = False
    try:
        if interrupt:
            TURN_DIAGNOSTIC['substage'] = 'await_working'
            deadline = time.monotonic() + 100
            while True:
                current = private_json(root / 'maintenance/checkpoint.json')
                turn_checkpoint(current)
                if current['turns'] == before + 1 and current['stage'] == 'working':
                    break
                require(process.poll() is None and time.monotonic() < deadline, 'core turn not observed')
                time.sleep(0.02)
            if interrupt == 'eof':
                # Kill only the exact fixture-owned CLI. Its live Unix connections close;
                # the subsequent fresh core turn proves release of the retained slot/lane.
                process.kill()
            else:
                require(interrupt == 'foreground', 'unknown interruption')
                TURN_DIAGNOSTIC['substage'] = 'foreground_operation'
                foreground = invoke(binary, client, ['storage', 'peer', 'progress', *peer_args(root, key_b)])
                require(foreground['committed'] is True and foreground['stored_bytes'] == len(FG),
                    'independent foreground operation not acknowledged')
        TURN_DIAGNOSTIC['substage'] = 'join_owner'
        stdout, stderr = process.communicate(timeout=650 if budget is None else budget.remaining(650))
        TURN_DIAGNOSTIC['worker_exit_status'] = process.returncode if -128 <= process.returncode <= 255 else None
        TURN_DIAGNOSTIC['substage'] = 'validate_owner_exit'
        require(len(stdout) <= 32768 and len(stderr) <= 16384, 'bounded owner output')
        require(process.returncode == (-signal.SIGKILL if interrupt == 'eof' else 0), 'owner process exit')
        TURN_DIAGNOSTIC['substage'] = 'checkpoint_after'
        result = checkpoint(root, binary, client, budget=budget)
        turn_checkpoint(result)
        TURN_DIAGNOSTIC['substage'] = 'validate_cursor_and_stage'
        require(result['turns'] == before + 1, 'cursor did not resume exactly one turn')
        if interrupt == 'eof':
            require(result['stage'] == 'working', 'owner EOF was not during an admitted turn')
        elif interrupt == 'foreground':
            require(result['stage'] == 'core_turn_revoked', 'foreground did not revoke the core turn')
        else:
            require(result['stage'] == 'turn_completed' and result['detail']['maintenance_stage'] in
                ('observed', 'maintained'), 'maintenance did not complete a core turn')
        return result
    except BaseException:
        owner_failed = True
        raise
    finally:
        try:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        except (OSError, subprocess.SubprocessError) as error:
            TURN_DIAGNOSTIC['cleanup_error'] = failure_code(error)
            if not owner_failed:
                raise


class OwnerProcess:
    """Own and drain the real finite-enrollment CLI; never export private output."""
    LIMIT = 262144

    def __init__(self, command):
        self.buffers = [bytearray(), bytearray()]
        self.overflow = [False, False]
        self.lock = threading.Lock()
        self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.threads = []
        try:
            for index, stream in enumerate((self.process.stdout, self.process.stderr)):
                thread = threading.Thread(target=self._drain, args=(index, stream))
                thread.start()
                self.threads.append(thread)
        except BaseException:
            self.close()
            raise

    def _drain(self, index, stream):
        try:
            with stream:
                while chunk := stream.read1(4096):
                    with self.lock:
                        available = self.LIMIT - len(self.buffers[index])
                        self.buffers[index].extend(chunk[:available])
                        self.overflow[index] |= len(chunk) > available
        except OSError:
            self.overflow[index] = True

    def reports(self):
        with self.lock:
            require(not any(self.overflow), 'bounded owner output')
            data = bytes(self.buffers[0])
        rows = data.split(b'\n')[:-1]
        require(len(rows) <= MAX_LIFECYCLE_CURSOR, 'bounded owner output')
        return [json.loads(row) for row in rows if row]

    def stop(self):
        self.process.send_signal(signal.SIGTERM)
        require(self.process.wait(timeout=10) == 0, 'owner process exit')
        self.join()

    def join(self):
        for thread in self.threads:
            thread.join(timeout=5)
            require(not thread.is_alive(), 'owner output not drained')
        require(not any(self.overflow), 'bounded owner output')

    def close(self):
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.join()


class LifecycleBudget:
    """One original signed expiry and monotonic fixture deadline, never renewed."""
    def __init__(self, expires):
        require(type(expires) is int and expires > 0, 'invalid lifecycle enrollment expiry')
        self.expires = expires
        self.deadline = time.monotonic() + min(LIFECYCLE_SECONDS, max(0, expires - time.time()))

    def remaining(self, maximum):
        # Recheck wall time as well: a forward clock change cannot enlarge the
        # original signed authorization; rollback cannot extend the monotonic cap.
        remaining = min(maximum, self.deadline - time.monotonic(), self.expires - time.time())
        require(remaining > 0, 'owner lifecycle deadline')
        return remaining


def wait_owner(owner, predicate, seconds=180, *, budget=None):
    deadline = time.monotonic() + (seconds if budget is None else budget.remaining(seconds))
    while time.monotonic() < deadline:
        if budget is not None:
            budget.remaining(seconds)
        require(owner.process.poll() is None, 'owner process exit')
        value = predicate()
        if value:
            if budget is not None:
                budget.remaining(seconds)
            return value
        time.sleep(.05)
    raise ValueError('owner lifecycle deadline')


def retained_during_core_loss(retained):
    # Original placements have the unchanged v1 report shape: v2-only repair
    # history fields do not exist until the first signed replacement is retained.
    require(retained['physical_payload_charge_upper_bound'] == 2 * BYTES
        and len(retained['fragments']) == 4
        and all(len(fragment['copies']) == 2 for fragment in retained['fragments'])
        and retained.get('placement_authorizations', 0) == 0,
        'core loss changed charged custody')


def lifecycle(root, binary, client, keys):
    """A fixed external VM supervisor alone controls the core service."""
    global LIFECYCLE_DIAGNOSTIC
    LIFECYCLE_DIAGNOSTIC = dict(stage='checkpoint_before', cursor_before=None, cursor_last=None,
        checkpoint_stage=None, owner_exit_status=None, owner_joined=False, cleanup_error=None)
    enrollment = (root / 'maintenance/enrollment.json').read_bytes()
    budget = LifecycleBudget(json.loads(enrollment)['enrollment']['expires'])

    def observed_checkpoint():
        value = checkpoint(root, binary, client, budget=budget)
        LIFECYCLE_DIAGNOSTIC['cursor_last'] = bounded_count(value.get('turns'), MAX_LIFECYCLE_CURSOR)
        stage = value.get('stage')
        LIFECYCLE_DIAGNOSTIC['checkpoint_stage'] = stage if stage in CHECKPOINT_STAGES else None
        return value

    before = observed_checkpoint()['turns']
    LIFECYCLE_DIAGNOSTIC['cursor_before'] = before
    require(before == 3, 'lifecycle initial cursor')
    LIFECYCLE_DIAGNOSTIC['stage'] = 'spawn_owner'
    # Normal serve remains bounded by the same signed expiry and outer 1800s
    # fixture. An eight-turn trial cap could expire before supervisor readiness.
    owner = OwnerProcess([binary, '--control-socket', client, 'storage', 'fragments',
        'maintenance', 'serve', '--enrollment', str(root / 'maintenance'),
        *map(str, unlock(root))])
    owner_failed = False
    try:
        LIFECYCLE_DIAGNOSTIC['stage'] = 'await_working'
        working = wait_owner(owner, lambda: (v if (v := observed_checkpoint())['stage'] == 'working'
            and v['turns'] > before else None), budget=budget)
        create(root / 'lifecycle-working.json', b'{"ready":true}')
        LIFECYCLE_DIAGNOSTIC['stage'] = 'await_core_loss'
        lost = wait_owner(owner, lambda: (v if (v := observed_checkpoint())['stage'] == 'core_unavailable'
            and v['turns'] >= working['turns'] else None), budget=budget)
        LIFECYCLE_DIAGNOSTIC['stage'] = 'verify_retained'
        retained = status(root, binary, client, budget=budget)
        retained_during_core_loss(retained)
        F['check_identity'](root)
        require((root / 'maintenance/enrollment.json').read_bytes() == enrollment,
            'core loss changed enrollment')
        create(root / 'lifecycle-unavailable.json', b'{"ready":true}')
        # This is read-only coordination, not execution authority. The immutable
        # root-owned reply binds only the actual new fixture route and baseline.
        coordinator = Path(client).parents[2] / 'maintenance-coordinator'
        ready = coordinator / 'ready.json'
        LIFECYCLE_DIAGNOSTIC['stage'] = 'await_coordinator'
        wait_owner(owner, ready.exists, LIFECYCLE_SECONDS, budget=budget)
        LIFECYCLE_DIAGNOSTIC['stage'] = 'validate_coordinator'
        info = ready.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0
            and stat.S_IMODE(info.st_mode) == 0o640 and info.st_size <= 8192,
            'invalid fixture coordinator reply')
        control = read(ready)
        require(set(control) == {'baseline', 'scope'}, 'invalid fixture coordinator reply')
        SAMPLER['validate_route_scope'](control['scope'])
        exit_socket = Path(client).parents[2] / 'runtime-exit/control/agent.sock'
        after_ready = observed_checkpoint()['turns']
        LIFECYCLE_DIAGNOSTIC['stage'] = 'start_sampler'
        with SAMPLER['capture'](binary, exit_socket, control['baseline'], 1,
                client=Path(client), scope=control['scope'], diagnostic=SAMPLER_DIAGNOSTIC) as coverage:
            LIFECYCLE_DIAGNOSTIC['stage'] = 'await_resumed_turn'
            resumed = wait_owner(owner, lambda: next((v for v in owner.reports()
                if v['stage'] == 'turn_completed' and v['turns'] > after_ready), None), 650, budget=budget)
            LIFECYCLE_DIAGNOSTIC['stage'] = 'stop_owner'
            owner.stop()
            LIFECYCLE_DIAGNOSTIC['stage'] = 'verify_pause'
            paused = observed_checkpoint()
            require(paused['stage'] == 'paused' and paused['turns'] >= resumed['turns'],
                'SIGTERM did not persist pause')
            require((root / 'maintenance/enrollment.json').read_bytes() == enrollment,
                'enrollment changed across core restart')
            # Fresh process reconciles the original journals; no new enrollment.
            LIFECYCLE_DIAGNOSTIC['stage'] = 'fresh_owner_turn'
            restarted = run_turn(root, binary, client, keys[1], budget=budget)
            require(restarted['turns'] == paused['turns'] + 1, 'resume cursor changed')
            LIFECYCLE_DIAGNOSTIC['stage'] = 'reconcile_progress'
            current = invoke(binary, client, ['storage', 'fragments', 'progress', *existing(root)],
                deadline=budget.remaining(180))
            require(current['physical_payload_charge_upper_bound'] == 2 * BYTES
                and current['uncertain_payload_bytes'] == 0, 'restart charge reconciliation')
            F['check_identity'](root)
            LIFECYCLE_DIAGNOSTIC['stage'] = 'validate_flow_coverage'
        gates = coverage.report(joined=coverage.joined)
        SAMPLER['validate_summary'](gates, control['baseline'], 1)
        create(root / 'flow-lifecycle.json', json.dumps(gates, sort_keys=True).encode())
        result = dict(cursor_before=before, cursor_at_core_loss=lost['turns'],
            cursor_after_reconnect=resumed['turns'], cursor_at_pause=paused['turns'],
            cursor_after_resume=restarted['turns'], same_owner_survived_core_loss=True,
            charge_retained_during_core_loss=True, journal_identity_retained_during_core_loss=True,
            core_unavailable_observed=True, fresh_core_turn_completed=True,
            sigterm_exit_zero=True, paused_checkpoint_retained=True,
            new_owner_process_resumed=True, enrollment_unchanged=True,
            original_identities_retained=True, physical_payload_charge=2 * BYTES,
            uncertainty_reconciled=True, owner_process_joined=True)
        # Sampler finalization can consume time after the last owner operation;
        # it must not turn an expired trial into a successful lifecycle receipt.
        budget.remaining(LIFECYCLE_SECONDS)
        LIFECYCLE_DIAGNOSTIC['stage'] = 'publish_result'
        create(root / 'lifecycle-result.json', json.dumps(result, sort_keys=True).encode())
        return result
    except BaseException:
        owner_failed = True
        raise
    finally:
        try:
            owner.close()
            LIFECYCLE_DIAGNOSTIC['owner_joined'] = owner.process.poll() is not None
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            LIFECYCLE_DIAGNOSTIC['cleanup_error'] = failure_code(error)
            if not owner_failed:
                raise
        finally:
            code = owner.process.poll()
            LIFECYCLE_DIAGNOSTIC['owner_exit_status'] = code if type(code) is int and -128 <= code <= 255 else None


def prepare(root, binary, client, provider_a, provider_b, provider_c, key_a, key_b, key_c):
    global STAGE
    STAGE = 'prepare'
    keys = (key_a, key_b, key_c)
    require(not list(root.iterdir()) and len(set(keys)) == 3, 'fresh owner and providers required')
    create(root / 'input.bin', F['FIXTURE'])
    create(root / 'foreground.bin', FG)
    create(root / 'passphrase', base64.b64encode(os.urandom(48)) + b'\n')
    invoke(binary, client, ['init', *unlock(root)], raw=True)
    owner = invoke(binary, client, ['content', 'recipient-key', *unlock(root)])['identity_public_key_hex']
    require(re.fullmatch('[0-9a-f]{64}', owner) and owner not in keys, 'distinct owner required')
    for label, control, key in zip('abc', (provider_a, provider_b, provider_c), keys):
        grant = invoke(binary, control, ['storage', 'peer', 'grant', '--provider-key', key,
            '--owner-key', owner, '--max-payload-bytes', BYTES, '--max-leases', 4,
            '--max-retention-seconds', 7200, '--lifetime-seconds', 7200,
            '--output', root / f'grant-{label}.bin'])
        require(grant['grant_written'] is True and grant['max_payload_bytes'] == BYTES
            and grant['max_leases'] == 4 and grant['reserved_bytes'] == 0
            and grant['network_contribution_credit'] is False, 'bounded provider grant')
    grant = invoke(binary, provider_b, ['storage', 'peer', 'grant', '--provider-key', key_b,
        '--owner-key', owner, '--max-payload-bytes', len(FG), '--max-leases', 1,
        '--max-retention-seconds', 7200, '--lifetime-seconds', 7200,
        '--output', root / 'foreground-grant.bin'])
    require(grant['grant_written'] is True and grant['max_payload_bytes'] == len(FG)
        and grant['max_leases'] == 1, 'independent foreground grant')
    return dict(synthetic_opaque_bytes=True, ciphertext_bytes=BYTES, fragment_lengths=list(LENGTHS),
        providers=3, copies_per_fragment=2, grant_payload_bytes=[BYTES] * 3, grant_max_leases=[4] * 3,
        independent_foreground_bytes=len(FG), owner_distinct_from_all_providers=True, owner_secrets_exported=False)


def upload(root, binary, client, keys):
    global STAGE
    STAGE = 'upload'
    # Existing real foreground deposit/retry/renew/progress, immutable identity checks,
    # and deletion of the original local bytes. Grants reserve no extra physical bytes.
    uploaded = F['upload'](root, binary, client, keys)
    foreground = invoke(binary, client, ['storage', 'peer', 'deposit', *peer_args(root, keys[1]),
        '--grant', root / 'foreground-grant.bin', '--input', root / 'foreground.bin',
        '--sha256', hashlib.sha256(FG).hexdigest(), '--already-encrypted', '--lifetime-seconds', 5400])
    require(foreground['committed'] is True and foreground['stored_bytes'] == len(FG), 'foreground seed')
    (root / 'foreground.bin').unlink()
    STAGE = 'enroll'
    arguments = ['storage', 'fragments', 'maintenance', 'enroll', '--enrollment', root / 'maintenance',
        '--state', root / 'fragment-set', '--from-provider-key', keys[0], '--authorization-seconds', 6000,
        '--lifetime-seconds', 5400, '--renew-before-seconds', 7200,
        '--maximum-charged-bytes', MAX_CHARGE, '--maximum-turn-bytes', 8 * 1024 * 1024, *unlock(root)]
    for label, key in zip('bc', keys[1:]):
        arguments += ['--provider-key', key, '--grant', root / f'grant-{label}.bin']
    enrolled = invoke(binary, client, arguments)
    require(enrolled['stage'] == 'enrolled' and enrolled['turns'] == 0, 'enrollment failed')
    before = status(root, binary, client)
    STAGE = 'renew'
    renewal = run_turn(root, binary, client, keys[1])
    refresh = renewal['detail']['refresh']
    require(refresh == dict(fragment_index=0, renewal=True, operation_complete=True,
            copy_outcomes=['confirmed', 'confirmed'])
        and type(refresh['fragment_index']) is int
        and refresh['renewal'] is True and refresh['operation_complete'] is True,
        'real rotating renewal not observed')
    after = status(root, binary, client)
    for old, new in zip(before['fragments'][0]['copies'], after['fragments'][0]['copies']):
        require(new['last_confirmed_expiry'] > old['last_confirmed_expiry'] + 1000,
            'provider did not extend the actual lease')
    STAGE = 'owner_eof'
    eof = run_turn(root, binary, client, keys[1], 'eof')
    STAGE = 'foreground'
    revoked = run_turn(root, binary, client, keys[1], 'foreground')
    require((renewal['turns'], eof['turns'], revoked['turns']) == (1, 2, 3), 'restart cursor reset')
    STAGE = 'reconcile_cancelled_turns'
    # Interruption can leave an honest uncertain renewal/progress journal even
    # when the provider kept its committed copy. Reconcile actual receipts; never
    # infer a confirmed owner state merely from killing the requesting process.
    F['validate_cli'](invoke(binary, client, ['storage', 'fragments', 'progress', *existing(root)], deadline=900),
        'progress', keys, 'committed')
    F['check_identity'](root)
    return dict(uploaded, core_renewal_confirmed=True, renewal_fragment_index=0,
        owner_eof_during_admitted_turn=True, subsequent_core_turn_proves_lane_released=True,
        independent_foreground_progress_confirmed=True, foreground_turn_revoked=True,
        cursor_before_restart=2, cursor_after_restart=3, cancelled_turns_reconciled=True, enrollment_owner_private=True)


def validate_repaired(value, keys):
    require(value['owner_signature_verified'] is True and value['report_version'] == 2
        and value['logical_ciphertext_bytes'] == BYTES and value['fragment_count'] == 4
        and value['copies_per_fragment'] == value['desired_copies_per_fragment'] == 2
        and value['placement_authorizations'] == 3 and value['retained_copy_records'] == 11
        and value['pending_retirements'] == 3 and value['replacement_overhead_included'] is True
        and value['uncertain_payload_bytes'] == A_BYTES and value['committed_payload_bytes'] == 2 * BYTES
        and value['reserved_payload_bytes'] == 0 and value['physical_payload_charge_upper_bound'] == MAX_CHARGE
        and value['fully_redundant_from_retained_receipts'] is True
        and value['fragments_with_confirmed_unexpired_copy'] == 4
        and value['providers'] == [dict(provider_key=key, physical_payload_charge_upper_bound=size)
            for key, size in zip(keys, (A_BYTES, BYTES, BYTES))], 'replacement custody or accounting incomplete')
    require(all(value[key] is False for key in ('read_consumes_archive', 'metadata_overhead_measured',
        'current_remote_availability_proven', 'independent_failure_domains_proven',
        'network_contribution_credit', 'erasure_coding')), 'replacement scope changed')
    for index, fragment in enumerate(value['fragments']):
        require(fragment['index'] == index and fragment['offset'] == sum(LENGTHS[:index])
            and fragment['ciphertext_bytes'] == LENGTHS[index] and fragment['confirmed_unexpired_copies'] == 2,
            'fragment reconstruction geometry changed')
        committed = [copy for copy in fragment['copies'] if copy['charge'] == 'committed']
        uncertain = [copy for copy in fragment['copies'] if copy['charge'] == 'uncertain']
        require(len(committed) == 2 and {copy['provider_key'] for copy in committed} == set(keys[1:])
            and len(uncertain) == (0 if index == 1 else 1)
            and all(copy['provider_key'] == keys[0] for copy in uncertain)
            and len(fragment['copies']) == len(committed) + len(uncertain), 'effective replacement placement')


def repaired(value, keys):
    # Retained healthy receipts alone do not prove every withdrawn A copy has a
    # replacement. Three explicit signed intents must reach verified retirement.
    if not (value.get('placement_authorizations') == 3 and value.get('pending_retirements') == 3
            and value.get('retained_copy_records') == 11 and value['fully_redundant_from_retained_receipts']):
        return False
    validate_repaired(value, keys)
    return True


def staged_files_absent(root):
    F['staged_files_absent'](root)
    require(not any(path.name.startswith(('.handoff-', '.replicas-', '.fragments-'))
        for path in (root / 'fragment-set').rglob('*')), 'handoff staging remains')


def restore(root, binary, client, keys):
    global STAGE
    STAGE = 'repair'
    require(not (root / 'input.bin').exists(), 'original bytes still present')
    begin = checkpoint(root, binary, client)['turns']
    require(begin == read(root / 'lifecycle-result.json')['cursor_after_resume'],
        'cursor lost before provider withdrawal')
    fresh, turns = 0, 0
    for _ in range(12):
        previous = status(root, binary, client)
        previous_charge = previous['physical_payload_charge_upper_bound']
        turn = run_turn(root, binary, client, keys[1])
        turns += 1
        detail = turn['detail']
        require(detail['refresh']['fragment_index'] == (turn['turns'] - 1) % 4,
            'durable scan cursor did not rotate')
        replacement = detail.get('freshly_verified_replacements', 0)
        require(type(replacement) is int and 0 <= replacement <= 1, 'unbounded replacements per turn')
        fresh += replacement
        value = status(root, binary, client)
        require(previous_charge <= value['physical_payload_charge_upper_bound'] <= MAX_CHARGE,
            'offline original charge lost or enrollment exceeded')
        F['check_identity'](root)
        if repaired(value, keys):
            break
    else:
        raise ValueError('bounded repair turns incomplete')
    require(fresh == 3, 'three fresh replacement readbacks not observed')
    # A fresh CLI process reloads the same journals before each restore: no parent
    # holds an archive or a hidden in-memory replacement map on behalf of these reads.
    STAGE = 'restore'
    for number in (1, 2):
        path = root / f'restore-{number}.bin'
        value = invoke(binary, client, ['storage', 'fragments', 'restore', *existing(root), '--output', path], deadline=900)
        validate_repaired(value, keys)
        require(value['restored'] is True and value['whole_archive_sha256_verified'] is True
            and all(entry['restored'] is True and entry['provider_key'] in keys[1:]
                for entry in value['fragment_outcomes']), 'replacement-only reconstruction failed')
        require(private_file(path).st_size == BYTES and hashlib.sha256(path.read_bytes()).hexdigest() == SHA,
            'restored bytes differ')
        F['check_identity'](root)
    invoke(binary, client, ['storage', 'fragments', 'restore', *existing(root), '--output', root / 'restore-1.bin'], expected=1)
    require(hashlib.sha256((root / 'restore-1.bin').read_bytes()).hexdigest() == SHA, 'restore clobbered output')
    staged_files_absent(root)
    return dict(restores=2, source_absent=True, owner_worker_starts=turns, scan_cursor_before=begin,
        scan_cursor_after=checkpoint(root, binary, client)['turns'], fresh_verified_replacements=fresh,
        retained_copy_records=11, pending_retirements=3, physical_payload_charge=MAX_CHARGE,
        uncertain_payload_charge=A_BYTES, survivor_provider_indexes=[1, 2], uniform_target_copies=2,
        whole_archive_sha256_verified=True, reads_nonconsuming=True, existing_output_preserved=True,
        original_identities_retained=True, staging_removed=True)


def validate_retirement_progress(before, value, detail):
    # A completed retirement freshly reads back its existing replacement. That is
    # not a new placement; compare actual retained identities/counts instead.
    fresh = detail.get('freshly_verified_replacements', 0)
    require(type(fresh) is int and 0 <= fresh <= 1, 'unbounded retirement readbacks')
    require(value['placement_authorizations'] == before['placement_authorizations']
        and value['retained_copy_records'] == before['retained_copy_records'],
        'duplicate replacement after restart')


def finish(root, binary, client, keys):
    global STAGE, RETIREMENT_TURNS
    STAGE = 'retirement'
    RETIREMENT_TURNS = []
    turns = 0
    before = status(root, binary, client)
    retirement_counts(before, 0)
    require(before['placement_authorizations'] == 3 and before['retained_copy_records'] == 11,
        'replacement set incomplete before retirement')
    placements = root / 'fragment-set' / 'placement-authorizations.json'
    require(private_file(placements).st_size <= 1048576, 'placement journal exceeds bound')
    original_placements = placements.read_bytes()
    for _ in range(4):
        turn = run_turn(root, binary, client, keys[1])
        turns += 1
        retirement_turn(turn, turns)
        value = status(root, binary, client)
        retirement_counts(value, turns)
        validate_retirement_progress(before, value, turn['detail'])
        require(placements.read_bytes() == original_placements, 'signed replacement identities changed')
        if value['pending_retirements'] == 0:
            break
    require(value['pending_retirements'] == 0 and value['placement_authorizations'] == 3
        and value['physical_payload_charge_upper_bound'] == 2 * BYTES
        and value['uncertain_payload_bytes'] == 0, 'source retirement unconfirmed')
    STAGE = 'delete'
    for _ in range(2):
        deleted = invoke(binary, client, ['storage', 'fragments', 'delete', *existing(root)], deadline=900)
        require(deleted['operation_complete'] is True and deleted['physical_payload_charge_upper_bound'] == 0
            and all(copy['charge'] == 'deleted' for fragment in deleted['fragments'] for copy in fragment['copies']),
            'all retained copies must be explicitly deleted')
        F['check_identity'](root)
    foreground = invoke(binary, client, ['storage', 'peer', 'delete', *peer_args(root, keys[1])])
    require(foreground['state'] == 'Deleted', 'foreground copy not deleted')
    staged_files_absent(root)
    return dict(owner_worker_starts=turns, pending_retirements=0, duplicate_replacements=0,
        acknowledged_source_retirement=True, all_eleven_copies_deleted=True, foreground_copy_deleted=True,
        delete_retry_idempotent=True, original_identities_retained=True, final_payload_charge=0, staging_removed=True)


def cleanup(path):
    root = private_root(path, missing=True)
    files, directories = [], []
    if root.exists():
        def visit(directory, depth):
            require(depth <= 4, 'cleanup depth')
            entries = list(directory.iterdir())
            require(len(entries) <= 24, 'cleanup entries')
            for child in entries:
                info = child.lstat()
                if stat.S_ISDIR(info.st_mode):
                    allowed = ((depth == 0 and (child.name in ('fragment-set', 'maintenance', 'foreground')
                            or re.fullmatch(r'\.fragments-[A-Za-z0-9]+', child.name)))
                        or (depth == 1 and (re.fullmatch('fragment-000[0-3]', child.name)
                            or re.fullmatch(r'\.(?:replicas|fragment-transfer)-[A-Za-z0-9]+', child.name)))
                        or (depth == 2 and (child.name in ('copy-0', 'copy-1', 'copy-2')
                            or re.fullmatch(r'\.handoff-(?:journal|transfer)-[A-Za-z0-9]+', child.name)))
                        or (depth == 3 and directory.name.startswith('.handoff-journal-') and child.name == 'copy'))
                    require(allowed and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.geteuid(),
                        'unexpected cleanup directory')
                    visit(child, depth + 1)
                    directories.append(child)
                else:
                    allowed = ((depth == 0 and child.name in F['FILES'] | {'foreground.bin', 'foreground-grant.bin',
                            'flow-upload.json', 'flow-restore.json', 'flow-finish.json', 'flow-lifecycle.json',
                            'lifecycle-working.json', 'lifecycle-unavailable.json', 'lifecycle-result.json'})
                        or (depth == 1 and child.name in ('fragments.json', 'placement-authorizations.json',
                            'enrollment.json', 'checkpoint.json', 'archive.json'))
                        or (depth == 2 and child.name in ('replicas.json', 'restored-fragment'))
                        or (depth == 3 and (child.name == 'archive.json'
                            or (directory.name.startswith('.handoff-transfer-')
                                and re.fullmatch('survivor-[0-2]', child.name))))
                        or (depth == 4 and directory.name == 'copy' and child.name == 'archive.json')
                        or re.fullmatch(r'\.tmp[A-Za-z0-9]+', child.name))
                    require(allowed, 'unexpected cleanup file')
                    private_file(child)
                    files.append(child)
        visit(root, 0)
        require(len(files) <= 96 and len(directories) <= 32, 'cleanup total bound')
        for entry in files:
            entry.unlink()
        for entry in directories:
            entry.rmdir()
        root.rmdir()
    return dict(owner_identity_removed=True, passphrase_removed=True, grants_removed=True,
        fragment_metadata_removed=True, input_and_outputs_removed=True, fragment_staging_removed=True,
        enrollment_checkpoint_removed=True, foreground_journal_removed=True, user_directory_removed=True)


def validate_lifecycle(value):
    cursor_keys = ('cursor_before', 'cursor_at_core_loss', 'cursor_after_reconnect',
        'cursor_at_pause', 'cursor_after_resume')
    flags = ('same_owner_survived_core_loss', 'core_unavailable_observed', 'fresh_core_turn_completed',
        'charge_retained_during_core_loss', 'journal_identity_retained_during_core_loss',
        'sigterm_exit_zero', 'paused_checkpoint_retained', 'new_owner_process_resumed',
        'enrollment_unchanged', 'original_identities_retained', 'uncertainty_reconciled',
        'owner_process_joined', 'guest_core_pid_changed', 'guest_core_namespace_preserved')
    require(set(value) == {*cursor_keys, *flags, 'physical_payload_charge'},
        'lifecycle receipt fields')
    require(all(type(value[key]) is int for key in cursor_keys)
        and value['cursor_before'] == 3
        and 3 < value['cursor_at_core_loss'] < value['cursor_after_reconnect']
        <= value['cursor_at_pause'] < value['cursor_after_resume'] <= MAX_LIFECYCLE_CURSOR
        and value['cursor_after_resume'] == value['cursor_at_pause'] + 1
        and all(value[key] is True for key in flags)
        and type(value['physical_payload_charge']) is int
        and value['physical_payload_charge'] == 2 * BYTES, 'lifecycle evidence incomplete')


def validate_evidence(value):
    require(value['success'] is True and all(value[key] is False for key in SCOPE_FALSE), 'scope overstated')
    require(value['prepare'] == dict(synthetic_opaque_bytes=True, ciphertext_bytes=BYTES, fragment_lengths=list(LENGTHS),
        providers=3, copies_per_fragment=2, grant_payload_bytes=[BYTES] * 3, grant_max_leases=[4] * 3,
        independent_foreground_bytes=len(FG), owner_distinct_from_all_providers=True, owner_secrets_exported=False),
        'provider grant proof missing')
    expected_upload = dict(fragment_count=4, copies_per_fragment=2, committed_fragment_copies=8,
        logical_ciphertext_bytes=BYTES, physical_payload_charge=2 * BYTES, owner_signature_verified=True,
        fresh_process_progress=True, committed_retry_same_identities=True, renewal_confirmed_by_progress=True,
        source_removed_before_restore=True, staging_removed=True, core_renewal_confirmed=True,
        renewal_fragment_index=0, owner_eof_during_admitted_turn=True,
        subsequent_core_turn_proves_lane_released=True, independent_foreground_progress_confirmed=True,
        foreground_turn_revoked=True, cursor_before_restart=2, cursor_after_restart=3,
        cancelled_turns_reconciled=True, enrollment_owner_private=True)
    require(value['upload'] == expected_upload, 'core renewal/revocation/restart proof missing')
    validate_lifecycle(value['lifecycle'])
    resume_cursor = value['lifecycle']['cursor_after_resume']
    restored = value['restore']
    require(type(restored['owner_worker_starts']) is int and 1 <= restored['owner_worker_starts'] <= 12
        and restored == dict(restores=2, source_absent=True, owner_worker_starts=restored['owner_worker_starts'],
            scan_cursor_before=resume_cursor, scan_cursor_after=resume_cursor + restored['owner_worker_starts'], fresh_verified_replacements=3,
            retained_copy_records=11, pending_retirements=3, physical_payload_charge=MAX_CHARGE,
            uncertain_payload_charge=A_BYTES, survivor_provider_indexes=[1, 2], uniform_target_copies=2,
            whole_archive_sha256_verified=True, reads_nonconsuming=True, existing_output_preserved=True,
            original_identities_retained=True, staging_removed=True), 'actual repair and restored custody missing')
    finished = value['finish']
    require(type(finished['owner_worker_starts']) is int and 1 <= finished['owner_worker_starts'] <= 4
        and finished == dict(owner_worker_starts=finished['owner_worker_starts'], pending_retirements=0,
            duplicate_replacements=0, acknowledged_source_retirement=True, all_eleven_copies_deleted=True,
            foreground_copy_deleted=True, delete_retry_idempotent=True, original_identities_retained=True,
            final_payload_charge=0, staging_removed=True), 'retirement/deletion missing')
    require(value['withdrawal'] == dict(first_provider_stopped_before_restore=True, first_store_retained=True,
        other_two_providers_serving=True, same_three_stores_reopened=True, all_usage_snapshots_with_services_stopped=True,
        all_three_store_inodes_preserved=True, agent_restart_claimed=False), 'provider withdrawal not observed')
    require(value['uploaded_usage'] == [dict(reserved_bytes=0, committed_bytes=size, leases=count)
        for size, count in zip((A_BYTES, F['PROVIDER_BYTES'][1] + len(FG), F['PROVIDER_BYTES'][2]), (3, 4, 2))]
        and value['restored_usage'] == [dict(reserved_bytes=0, committed_bytes=size, leases=count)
        for size, count in zip((A_BYTES, BYTES + len(FG), BYTES), (3, 5, 4))]
        and value['deleted_usage'] == [dict(reserved_bytes=0, committed_bytes=0, leases=0)] * 3,
        'actual provider store accounting differs')
    require(value['private_cleanup'] == dict(owner_identity_removed=True, passphrase_removed=True, grants_removed=True,
        fragment_metadata_removed=True, input_and_outputs_removed=True, fragment_staging_removed=True,
        enrollment_checkpoint_removed=True, foreground_journal_removed=True, user_directory_removed=True),
        'private cleanup incomplete')
    isolation = value['isolation']
    require(isolation['user_uid'] > 0 and isolation['user_uid'] != isolation['agent_uid']
        and isolation['control_gid'] != isolation['agent_gid']
        and all(isolation[key] is True for key in ('agent_cannot_read_user_state',
            'client_cannot_read_any_provider_store', 'agent_mount_positive_control',
            'all_provider_keys_match_independent_fixture_peers', 'three_provider_namespaces_distinct')),
        'private owner/provider isolation missing')
    require(set(value['network']) == {*F['PHASES'], 'lifecycle'}, 'network phase missing')
    for name, phase in value['network'].items():
        layout = dict(value['layout'])
        if name != 'upload':
            layout['route_scope'] = phase['gates']['exit_route_scope']
        F['validate_network'](phase, value['expected_peers'], layout, name,
            maintenance_contexts=True, minimum=1 if name == 'lifecycle' else None)


def evidence(work):
    usage_names = ('uploaded_usage', 'restored_usage', 'deleted_usage')
    value = {name: read(work / f'private-storage-fragments-{name}.json')
        for name in F['SUMMARY_NAMES'] if name not in ('smoke', 'evidence', *usage_names)}
    for name in usage_names:
        value[name] = F['read_usage'](work / f'private-storage-fragments-{name}.json')
    value.update(success=True, expected_peers=read(work / 'a01-expected-peers.json'), **dict.fromkeys(SCOPE_FALSE, False))
    value['lifecycle'] = read(work / 'private-storage-maintenance-lifecycle.json')
    value['network'] = {name: dict(selected_route=read(work / f'private-storage-fragments-{name}-live-selection.json'),
        privacy={role: read(work / f'private-storage-fragments-{name}-privacy-{role}.json') for role in F['ROLES']},
        control_privacy=read(work / f'content-provider-adaptive-private-storage-fragments-{name}-control.json'),
        gates=read(work / f'private-storage-fragments-{name}-gates.json')) for name in (*F['PHASES'], 'lifecycle')}
    validate_evidence(value)
    return value


def validate_report(report, revision):
    require(re.fullmatch('[0-9a-f]{40}', revision) and report['source_revision'] == revision
        and report['schema_version'] == 2 and report['report_kind'] == 'volparossa-private-storage-maintenance'
        and report['success'] is True and report['runner_exit_status'] == 0
        and report['phase'] == 'private-storage-maintenance-complete' and report['observed_blocker'] is None
        and report['cleanup'] == dict(complete=True, remaining_owned_objects=0)
        and report['host_state']['unchanged'] is True, 'source-bound cleanup missing')
    validate_evidence(report['maintenance'])


def main(args):
    if args == ['owner-test-output']:
        print(json.dumps(owner_test_output(sys.stdin.buffer, sys.stderr.buffer), sort_keys=True))
        return
    if len(args) == 2 and args[0] == 'lifecycle-failure':
        print(json.dumps(lifecycle_failure_file(Path(args[1])), sort_keys=True))
        return
    if len(args) == 3 and args[0] == 'lifecycle-check':
        require(args[2] in ('working', 'unavailable'), 'unknown lifecycle marker')
        marker = private_root(args[1]) / f'lifecycle-{args[2]}.json'
        require(private_file(marker).st_size <= 64 and read(marker) == {'ready': True},
            'lifecycle marker missing')
        return
    if args == ['export-names']:
        print('\n'.join(EXPORT_NAMES)); return
    if len(args) == 2 and args[0] == 'preselection-diagnostic':
        work = Path(args[1])
        print(json.dumps(closed_preselection_events(work / 'logs-client.txt',
            work / 'private-storage-maintenance-selection-start.private',
            work / 'private-storage-maintenance-selection-end.private'), sort_keys=True))
        return
    if len(args) == 3 and args[0] == 'report':
        validate_report(read(Path(args[1])), args[2]); return
    if len(args) == 3 and args[0] == 'evidence':
        result = evidence(Path(args[1]))
        Path(args[2]).write_text(json.dumps(result, sort_keys=True) + '\n')
        return
    if len(args) == 10 and args[0] == 'prepare':
        result = prepare(private_root(args[1]), *args[2:])
    elif len(args) == 7 and args[0] == 'lifecycle':
        result = lifecycle(private_root(args[1]), args[2], args[3], args[4:])
    elif len(args) == 7 and args[0] in ('upload', 'restore', 'finish'):
        root = private_root(args[1])
        socket = Path(args[3])
        require(socket.parts[-3:] == ('runtime-client', 'control', 'agent.sock'), 'fixture client socket differs')
        exit_socket = socket.parents[2] / 'runtime-exit/control/agent.sock'
        baseline = int(os.environ['STORAGE_PROOF_BASELINE_MS'])
        scope = json.loads(os.environ['STORAGE_PROOF_ROUTE_SCOPE'])
        SAMPLER['validate_route_scope'](scope)
        with SAMPLER['capture'](args[2], exit_socket, baseline, F['PHASES'][args[0]],
                client=socket, scope=scope, diagnostic=SAMPLER_DIAGNOSTIC) as coverage:
            result = {'upload': upload, 'restore': restore, 'finish': finish}[args[0]](
                root, args[2], args[3], args[4:])
        summary = coverage.report(joined=coverage.joined)
        SAMPLER['validate_summary'](summary, baseline, F['PHASES'][args[0]])
        create(root / f'flow-{args[0]}.json', json.dumps(summary, sort_keys=True).encode())
    elif len(args) == 2 and args[0] == 'cleanup':
        result = cleanup(args[1])
    else:
        raise ValueError('fixture invocation')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    def interrupted(_signal, _frame):
        raise InterruptedError('fixture interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps(failure_receipt(error)))
        sys.exit(1)
