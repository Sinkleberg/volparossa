#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Join actual consumer receipts, store usage and independently drained captures.

This new profile does not reinterpret historical fragment/maintenance evidence.
Its application inputs are synthetic; it proves neither an Immich installation
nor an OpenCloud account server. The outer VM report owns host/guest cleanup.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys

HERE = Path(__file__).resolve().parent
APP = runpy.run_path(str(HERE / 'storage-consumer-maintenance-smoke.py'))
F, SAMPLER, PROVISIONER = APP['BASE'], APP['SAMPLER'], APP['PROVISIONER']
NET, ROLES, NODES = F['NET'], F['ROLES'], F['NODES']
PHASES = dict(publish=56, exercise=16, finish=22)
APPS = ('image', 'cloud')
MAX_JSON = 1024 * 1024
SCOPE = dict(synthetic_inputs=True, automatic_grant_refresh=False, private_keys_exported=False,
    immich_running_proven=False, opencloud_account_server_proven=False,
    node_report_hash_independently_reconstructed=False, host_cleanup_proven=False)
EXPORT_NAMES = (
    'a01-expected-peers.json', 'private-storage-fragments-layout.json',
    'private-storage-fragments-isolation.json', 'private-storage-fragments-deleted_usage.json',
    *(f'storage-consumer-{name}.json' for name in
        ('provision', 'prepare', *PHASES, 'withdrawal', 'private-cleanup', 'isolation', 'evidence')),
    *(f'private-storage-fragments-consumer_{name}_usage.json' for name in ('uploaded', 'restored', 'deleted')),
    *(filename for phase in PHASES for filename in (
        f'private-storage-fragments-consumer-{phase}-layout.json',
        f'private-storage-fragments-consumer-{phase}-live-selection.json',
        f'private-storage-fragments-consumer-{phase}-gates.json',
        f'content-provider-adaptive-private-storage-fragments-consumer-{phase}-control.json',
        *(f'private-storage-fragments-consumer-{phase}-privacy-{role}.json' for role in ROLES))))


def require(condition, code):
    if not condition:
        raise ValueError(code)


def keys(value, expected):
    require(type(value) is dict and set(value) == set(expected), 'consumer_closed_fields')


def count(value, low=0, high=2**64 - 1):
    return type(value) is int and low <= value <= high


def sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def encoded(value):
    # This is the provisioner's exact original on-disk representation, not the
    # Node report representation (whose original hash is observed by wrapper).
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'consumer_duplicate_json_key')
        value[key] = item
    return value


def read(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid in (0, os.geteuid())
            and not before.st_mode & 0o022 and 0 < before.st_size <= MAX_JSON, 'consumer_input_boundary')
        raw = stream.read(MAX_JSON + 1)
        after, named = os.fstat(stream.fileno()), Path(path).lstat()
        fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(len(raw) == before.st_size and all(getattr(before, k) == getattr(after, k) == getattr(named, k)
            for k in fields), 'consumer_input_changed')
    value = json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: require(False, 'consumer_nonfinite_json'))
    return value, raw


def validate_provision(value):
    true = ('guest_only', 'source_files_verified', 'runtime_files_verified', 'shared_adapter_verified',
        'original_licenses_retained')
    false = ('storage_enrollment_created', 'peer_storage_proven', 'application_restore_proven',
        'sdk_or_browser_provisioned', 'immich_or_opencloud_server_started')
    keys(value, ('version', 'kind', 'success', 'pins', 'pins_sha256', 'tools', *true, *false))
    require(type(value['version']) is int and value['version'] == 1
        and value['kind'] == 'storage-consumer-maintenance-runtime-provision' and value['success'] is True
        and encoded(value['pins']) == encoded(PROVISIONER['load_pins']())
        and value['pins_sha256'] == hashlib.sha256(PROVISIONER['PINS'].read_bytes()).hexdigest()
        and all(value[k] is True for k in true) and all(value[k] is False for k in false), 'consumer_provision')
    keys(value['tools'], ('gpg', 'gpg-agent', 'gpgconf', 'tar'))
    for name, tool in value['tools'].items():
        keys(tool, ('package', 'package_version', 'bytes', 'sha256'))
        require(tool['package'] == name and type(tool['package_version']) is str
            and re.fullmatch('[0-9A-Za-z.+:~_-]{1,100}', tool['package_version'])
            and count(tool['bytes'], 1, 16 * 1024**2) and sha(tool['sha256']), 'consumer_tool_provenance')


def validate_orchestration(value, phase, provision_sha, prepared):
    extra = ('authority',) if phase == 'prepare' else (
        'minimum_protected_completions', 'sampler_joined', 'remote_cleanup_independently_proven')
    keys(value, ('version', 'kind', 'phase', 'passed', 'node', 'node_report_sha256',
        'provision_sha256', 'node_joined', 'protected_flow_proven', *extra))
    require(type(value['version']) is int and value['version'] == 1
        and value['kind'] == 'storage-consumer-maintenance-orchestration'
        and value['phase'] == phase and value['passed'] is True and value['node_joined'] is True
        and value['provision_sha256'] == provision_sha and sha(value['node_report_sha256'])
        and value['node'].get('passed') is True, 'consumer_orchestration')
    APP['validate_node_report'](value['node'], phase, provision_sha, prepared)
    if phase == 'prepare':
        require(value['protected_flow_proven'] is False, 'consumer_prepare_not_flow_proof')
        keys(value['authority'], APPS)
        for app in APPS:
            size = value['node'][app]['cipher_bytes']
            expected = dict(fresh_owner_created=True, owner_distinct_from_providers=True,
                grant_payload_bytes=[size] * 3, grant_max_leases=[4] * 3,
                grant_retention_seconds=7200, grant_lifetime_seconds=7200, reserved_credit=0,
                enrollment_created=False, policy_authorization_seconds=6000,
                policy_lifetime_seconds=3600, policy_maximum_charge=3 * size, automatic_grant_refresh=False)
            # JSON equality alone accepts bool as int; authority types are fixed.
            require(encoded(value['authority'][app]) == encoded(expected), 'consumer_authority')
    else:
        require(value['protected_flow_proven'] is True and value['sampler_joined'] is True
            and type(value['minimum_protected_completions']) is int
            and value['minimum_protected_completions'] == PHASES[phase]
            and value['remote_cleanup_independently_proven'] is False, 'consumer_flow_scope')


def geometry(prepared):
    sizes, provider_bytes, repair_reads = [], [0, 0, 0], 0
    for app in APPS:
        size = prepared[app]['cipher_bytes']
        _, lengths, withdrawn = APP['geometry'](size)
        sizes.append(size)
        repair_reads += withdrawn
        for i, length in enumerate(lengths):
            for copy in range(2):
                provider_bytes[(i + copy) % 3] += length
    return sum(sizes), provider_bytes, repair_reads


def usage(value, sizes, leases):
    require(type(value) is list and len(value) == 3, 'consumer_usage_count')
    for item, size, number in zip(value, sizes, leases):
        keys(item, ('reserved_bytes', 'committed_bytes', 'leases'))
        require(all(count(n) for n in item.values()) and item == dict(reserved_bytes=0,
            committed_bytes=size, leases=number), 'consumer_exact_provider_usage')


def validate_network(phase, peers, layout, name, total, repair_reads):
    """Same protected-route/privacy conditions, with this profile's own phases.

    Repair of A's fragments 0/2/3 requires the sole original B/C survivor as
    source and the other survivor's verified readback. Thus each must return at
    least L0+L2+L3 per app, independent of later restore fallback selection.
    The two application reads additionally require the whole two ciphertexts.
    Packet payload includes framing: these are lower bounds, not GET attribution.
    """
    keys(phase, ('layout', 'selected_route', 'privacy', 'control_privacy', 'gates'))
    keys(phase['layout'], ('route_scope',))
    selected, privacy, gates = phase['selected_route'], phase['privacy'], phase['gates']
    SAMPLER['validate_summary'](gates, gates['event_baseline_unix_ms'], PHASES[name])
    SAMPLER['validate_phase_route'](phase['layout']['route_scope'], selected, gates)
    paths, slots = selected['paths'], selected['benchmark_slots']
    require(layout['provider_nodes'] == list(NODES) and len({peers[n] for n in NODES}) == 3
        and layout['control_relay_peer_id'] in {peers[n] for n in ROLES[1:4]}, 'consumer_provider_roles')
    require(selected['transport'] == 'mptcp' and len(paths) == len(slots) == 2
        and len({p['relay_peer_id'] for p in paths}) == 2
        and {p['exit_peer_id'] for p in paths} == {peers['exit']}
        and all(p['route_context_id'] == selected['route_context_id'] for p in paths)
        and [p['relay_peer_id'] for p in paths] == [s['relay_peer_id'] for s in slots], 'consumer_protected_mptcp')
    forbidden = {peers['client'], peers['exit'], layout['control_relay_peer_id']} | {p['relay_peer_id'] for p in paths}
    require(all(peers[n] not in forbidden for n in NODES), 'consumer_provider_path_overlap')
    relays = [s['relay_node'] for s in slots]
    require(len(set(relays)) == 2 and all(r in ROLES[1:4] for r in relays)
        and all(peers[s['relay_node']] == s['relay_peer_id'] for s in slots), 'consumer_physical_relays')
    keys(privacy, ROLES)
    for role, capture in privacy.items():
        require(capture['capture_role'] == role and capture['content_provider_mode'] is True
            and capture['unexpected_outer_packets'] == capture['unexpected_provider_application_packets'] == 0
            and capture['expected_link_down_notifications'] == 0, 'consumer_unexpected_egress')
        provider_counters(capture)
        NET['validate_drained'](capture, allow_empty=role in ROLES[1:4] and role not in relays)
        if role != 'exit':
            require(all(n == 0 for counters in capture['provider_application'].values() for n in counters.values()),
                'consumer_provider_bypass')
    require(privacy['client']['direct_client_exit_packets'] == privacy['client']['internet_destination_outer_packets'] == 0
        and privacy['exit']['direct_client_exit_packets'] == privacy['exit']['client_public_packets'] == 0
        and privacy['exit']['outbound_client_discovery_attempt_packets'] == 0
        and all(privacy[r]['internet_destination_outer_packets'] == 0 for r in ROLES[1:4]), 'consumer_privacy')
    for relay in relays:
        require(privacy[relay]['client_leg_wireguard_data_datagrams'] > 16
            and privacy[relay]['exit_leg_wireguard_data_datagrams'] > 16, 'consumer_two_leg_traffic')
    application = privacy['exit']['provider_application']
    for node in NODES[1:] if name == 'exercise' else NODES:
        require(application[node]['request_packets'] > 0 and application[node]['response_packets'] > 0,
            'consumer_active_provider_traffic')
    if name == 'exercise':
        require(application[NODES[0]]['response_payload_bytes'] == 0, 'consumer_withdrawn_provider_responded')
        actual = [application[node]['response_payload_bytes'] for node in NODES[1:]]
        require(all(n >= repair_reads for n in actual) and sum(actual) >= 2 * repair_reads + total,
            'consumer_survivor_payload')
    control = phase['control_privacy']
    control_node = next(n for n in ROLES[1:4] if peers[n] == layout['control_relay_peer_id'])
    pairs = {f'ac{i}': [NET['PUBLIC_IPS'][control_node], NET['PUBLIC_IPS'][node]]
        for i, node in enumerate(('relay3', 'relay4', 'relay5'))}
    require(control['capture_role'] == 'content-control' and control['content_provider_mode'] is True
        and control['content_control_pairs'] == pairs and set(control['interfaces']) == set(pairs)
        and set(control['content_control_packets']) == set(pairs)
        and control['unexpected_provider_control_packets'] == control['unexpected_provider_application_packets'] == 0,
        'consumer_control_boundary')
    provider_counters(control)
    require(all(n == 0 for values in control['provider_application'].values() for n in values.values()),
        'consumer_control_payload')
    NET['validate_drained'](control, allow_empty=True)


def provider_counters(capture):
    keys(capture['provider_application'], NODES)
    for counters in capture['provider_application'].values():
        keys(counters, ('request_packets', 'response_packets', 'response_payload_bytes'))
        require(all(count(n) for n in counters.values()), 'consumer_packet_counter')


def validate_evidence(value):
    keys(value, ('schema_version', 'kind', 'success', 'scope', 'provision', 'provision_sha256',
        'prepare', *PHASES, 'withdrawal', 'private_cleanup', 'initial_usage', 'uploaded_usage',
        'restored_usage', 'deleted_usage', 'expected_peers', 'layout', 'isolation', 'consumer_isolation', 'network'))
    require(type(value['schema_version']) is int and value['schema_version'] == 1
        and value['kind'] == 'storage-consumer-maintenance-evidence' and value['success'] is True,
        'consumer_evidence_identity')
    require(encoded(value['scope']) == encoded(SCOPE), 'consumer_evidence_scope')
    validate_provision(value['provision'])
    provision_sha = hashlib.sha256(encoded(value['provision'])).hexdigest()
    require(value['provision_sha256'] == provision_sha, 'consumer_provision_hash')
    prepared = value['prepare']['node']
    for phase in ('prepare', *PHASES):
        validate_orchestration(value[phase], phase, provision_sha, prepared)
    total, initial_bytes, repair_reads = geometry(prepared)
    usage(value['initial_usage'], [0] * 3, [0] * 3)
    usage(value['uploaded_usage'], initial_bytes, [6, 6, 4])
    usage(value['restored_usage'], [initial_bytes[0], total, total], [6, 8, 8])
    usage(value['deleted_usage'], [0] * 3, [0] * 3)
    require(encoded(value['withdrawal']) == encoded(dict(first_provider_stopped_before_repair_and_read=True,
        first_store_retained=True, other_two_providers_serving=True, same_three_stores_reopened=True,
        all_usage_snapshots_with_services_stopped=True, all_three_store_inodes_preserved=True)),
        'consumer_store_withdrawal')
    cleanup = value['private_cleanup']
    keys(cleanup, ('version', 'kind', 'passed', 'local_fixture_removed', 'no_owned_fixture_process_observed',
        'removed_files', 'removed_directories', 'remote_cleanup_confirmed', 'provider_usage_proven'))
    require(type(cleanup['version']) is int and cleanup['version'] == 1
        and cleanup['kind'] == 'storage-consumer-maintenance-cleanup' and cleanup['passed'] is True
        and cleanup['local_fixture_removed'] is True and cleanup['no_owned_fixture_process_observed'] is True
        and count(cleanup['removed_files'], 1, 512) and count(cleanup['removed_directories'], 1, 512)
        # The walk permits 512 children; the receipt also counts the root.
        and cleanup['removed_files'] + cleanup['removed_directories'] <= 513
        and cleanup['remote_cleanup_confirmed'] is False and cleanup['provider_usage_proven'] is False,
        'consumer_private_cleanup')
    peers = value['expected_peers']
    keys(peers, (*ROLES, *NODES))
    require(all(type(p) is str and re.fullmatch('[A-Za-z0-9_-]{1,128}', p) for p in peers.values())
        and len(set(peers.values())) == len(peers), 'consumer_peer_identity')
    layout = value['layout']
    keys(layout, ('provider_nodes', 'control_relay_peer_id', 'route_context_id', 'route_scope'))
    SAMPLER['context_id'](layout['route_context_id'])
    SAMPLER['validate_route_scope'](layout['route_scope'])
    isolation = value['isolation']
    ids = ('user_uid', 'agent_uid', 'control_gid', 'agent_gid')
    flags = ('agent_cannot_read_user_state', 'client_cannot_read_any_provider_store',
        'agent_mount_positive_control', 'all_provider_keys_match_independent_fixture_peers', 'three_provider_namespaces_distinct')
    keys(isolation, (*ids, *flags))
    require(all(count(isolation[k], 1, 2**32 - 1) for k in ids)
        and isolation['user_uid'] != isolation['agent_uid'] and isolation['control_gid'] != isolation['agent_gid']
        and all(isolation[k] is True for k in flags), 'consumer_shared_isolation')
    require(encoded(value['consumer_isolation']) == encoded(dict(user_uid=isolation['user_uid'],
        agent_uid=isolation['agent_uid'], agent_mount_positive_control=True,
        client_cannot_read_new_owner_root=True, client_cannot_read_any_provider_store=True)),
        'consumer_new_owner_isolation')
    keys(value['network'], PHASES)
    for name, phase in value['network'].items():
        validate_network(phase, peers, layout, name, total, repair_reads)
    return value


def build_evidence(work):
    work = Path(work)
    def get(name):
        return read(work / name)[0]
    provision, raw = read(work / 'storage-consumer-provision.json')
    require(raw == encoded(provision), 'consumer_provision_encoding')
    value = dict(schema_version=1, kind='storage-consumer-maintenance-evidence', success=True,
        scope=dict(SCOPE), provision=provision, provision_sha256=hashlib.sha256(raw).hexdigest(),
        **{name: get(f'storage-consumer-{name}.json') for name in ('prepare', *PHASES, 'withdrawal')},
        private_cleanup=get('storage-consumer-private-cleanup.json'),
        initial_usage=get('private-storage-fragments-deleted_usage.json'),
        **{name + '_usage': get(f'private-storage-fragments-consumer_{name}_usage.json')
            for name in ('uploaded', 'restored', 'deleted')},
        expected_peers=get('a01-expected-peers.json'), layout=get('private-storage-fragments-layout.json'),
        isolation=get('private-storage-fragments-isolation.json'),
        consumer_isolation=get('storage-consumer-isolation.json'))
    value['network'] = {name: dict(layout=get(f'private-storage-fragments-consumer-{name}-layout.json'),
        selected_route=get(f'private-storage-fragments-consumer-{name}-live-selection.json'),
        gates=get(f'private-storage-fragments-consumer-{name}-gates.json'),
        control_privacy=get(f'content-provider-adaptive-private-storage-fragments-consumer-{name}-control.json'),
        privacy={role: get(f'private-storage-fragments-consumer-{name}-privacy-{role}.json') for role in ROLES})
        for name in PHASES}
    return validate_evidence(value)


def main(arguments):
    if len(arguments) == 1 and arguments[0] == 'export-names':
        print('\n'.join(EXPORT_NAMES))
    elif len(arguments) == 2 and arguments[0] == 'check':
        validate_evidence(read(Path(arguments[1]))[0])
    elif len(arguments) == 3 and arguments[0] == 'evidence':
        raw = encoded(build_evidence(Path(arguments[1])))
        require(len(raw) <= MAX_JSON, 'consumer_evidence_bound')
        F['create'](Path(arguments[2]), raw)
    else:
        raise ValueError('consumer_evidence_arguments')


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except (ValueError, KeyError, TypeError, OSError, StopIteration, RecursionError):
        sys.exit('storage consumer evidence rejected')
