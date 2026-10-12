#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the explicit disposable KVM topology; no host operation.
# shellcheck disable=SC2154,SC2034
MAINTENANCE_OWNER_PID=

private_storage_maintenance_join() {
    if [ -n "$MAINTENANCE_OWNER_PID" ]; then
        kill -TERM "$MAINTENANCE_OWNER_PID" 2>/dev/null || true
        maintenance_join_status=0
        wait "$MAINTENANCE_OWNER_PID" || maintenance_join_status=$?
        MAINTENANCE_OWNER_PID=
        # timeout forwards TERM and has its own KILL deadline; failures never
        # become successful lifecycle evidence.
        [ "$maintenance_join_status" -eq 0 ] || [ "$maintenance_join_status" -eq 143 ] || return 1
    fi
    if [ -d "$WORK/maintenance-coordinator" ] && [ ! -L "$WORK/maintenance-coordinator" ]; then
        rm -f -- "$WORK/maintenance-coordinator/ready.json" "$WORK/maintenance-coordinator/ready.part"
        rmdir -- "$WORK/maintenance-coordinator" || return 1
    fi
}

private_storage_maintenance_publish_ready() {
    # The fresh coordinator directory is root-owned and not worker-writable.
    # Publish only after install has completed both bytes and final metadata.
    install -o root -g "$WORKER_GID" -m 0640 "$WORK/maintenance-coordinator-ready.private" \
        "$WORK/maintenance-coordinator/ready.part" || return 1
    mv -- "$WORK/maintenance-coordinator/ready.part" "$WORK/maintenance-coordinator/ready.json"
}

private_storage_maintenance_wait_marker() {
    maintenance_poll=0
    while [ "$maintenance_poll" -lt 900 ]; do
        kill -0 "$MAINTENANCE_OWNER_PID" 2>/dev/null || return 1
        if private_storage_fragments_private lifecycle-check "$storage_user" "$1" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
        maintenance_poll=$((maintenance_poll + 1))
    done
    return 1
}

private_storage_maintenance_supervisor_record() {
    # Fixed metadata only, written before owner cleanup can emit a secondary
    # cancellation. Diagnostic failure never changes the operation's outcome.
    if (umask 077
        python3 -B "$WORK/bin/private-storage-maintenance-smoke.py" supervisor-record \
            "$maintenance_supervisor_stage" "$1" "$2" "$maintenance_control_relation" \
            >"$WORK/maintenance-supervisor.part") \
        && mv -- "$WORK/maintenance-supervisor.part" "$WORK/private-storage-maintenance-supervisor.json"; then
        return 0
    fi
    rm -f -- "$WORK/maintenance-supervisor.part" || true
    return 0
}

private_storage_maintenance_supervisor_stage() {
    maintenance_supervisor_stage=$1
    private_storage_maintenance_supervisor_record pending null
}

private_storage_maintenance_post_reconnect() {
    maintenance_control_relation=unobserved
    private_storage_maintenance_supervisor_stage bind_slots
    benchmark_bind_slots "$WORK/private-storage-maintenance-reconnect-selection.json" || {
        private_storage_maintenance_supervisor_record failed "$?"; return 1;
    }
    # The existing restricted broker links are not silently widened by this trial.
    private_storage_maintenance_supervisor_stage control_query
    maintenance_control_peer=$(content_custody_cli client content status | jq -er '.control_relay_peer_id') || {
        # This is the original pipeline's status, not a claimed CLI-only status.
        private_storage_maintenance_supervisor_record failed "$?"; return 1;
    }
    if [ -z "$maintenance_control_peer" ]; then maintenance_control_relation=empty
    elif [ "$maintenance_control_peer" = "$provider_control_peer" ]; then maintenance_control_relation=same
    else maintenance_control_relation=different; fi
    private_storage_maintenance_supervisor_stage control_match
    [ "$maintenance_control_peer" = "$provider_control_peer" ] || {
        private_storage_maintenance_supervisor_record failed "$?"; return 1;
    }
    private_storage_maintenance_supervisor_stage route_scope
    storage_route_scope=$(jq -ce '{exit_peer_id:.exact_selected_exit,paths:[.paths[]|{path_id,relay_peer_id}]}' \
        "$WORK/private-storage-maintenance-reconnect-selection.json") || {
        private_storage_maintenance_supervisor_record failed "$?"; return 1;
    }
    private_storage_maintenance_supervisor_stage start_observers
    private_storage_fragments_phase_start lifecycle || {
        private_storage_maintenance_supervisor_record failed "$?"; return 1;
    }
    private_storage_maintenance_supervisor_stage ready_payload
    jq -cn --argjson baseline "$provider_baseline_ms" --argjson scope "$storage_route_scope" \
        '{baseline:$baseline,scope:$scope}' >"$WORK/maintenance-coordinator-ready.private" || {
        private_storage_maintenance_supervisor_record failed "$?"; return 1;
    }
    private_storage_maintenance_supervisor_stage publish_ready
    private_storage_maintenance_publish_ready || {
        private_storage_maintenance_supervisor_record failed "$?"; return 1;
    }
    private_storage_maintenance_supervisor_stage join_owner
    maintenance_status=0
    wait "$MAINTENANCE_OWNER_PID" || maintenance_status=$?
    MAINTENANCE_OWNER_PID=
    if [ "$maintenance_status" -ne 0 ]; then
        private_storage_maintenance_supervisor_record failed "$maintenance_status"; return 1
    fi
    private_storage_maintenance_supervisor_stage lifecycle_receipt
    jq -ce '. + {guest_core_pid_changed:true,guest_core_namespace_preserved:true}' \
        "$WORK/maintenance-owner-lifecycle.private" >"$WORK/private-storage-maintenance-lifecycle.json" || {
        private_storage_maintenance_supervisor_record failed "$?"; return 1;
    }
    private_storage_maintenance_supervisor_stage finish_observers
    private_storage_fragments_phase_finish 1 || {
        private_storage_maintenance_supervisor_record failed "$?"; return 1;
    }
    private_storage_maintenance_supervisor_stage coordinator_cleanup
    private_storage_maintenance_join || {
        private_storage_maintenance_supervisor_record failed "$?"; return 1;
    }
    private_storage_maintenance_supervisor_record complete 0
}

private_storage_maintenance_lifecycle() {
    PHASE=private-storage-maintenance-core-restart
    [ ! -e "$WORK/maintenance-coordinator" ] && [ ! -L "$WORK/maintenance-coordinator" ] || return 1
    install -d -o root -g "$WORKER_GID" -m 0750 "$WORK/maintenance-coordinator"
    timeout --signal=TERM --kill-after=15s 1800s setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$custody_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/private-storage-maintenance-smoke.py" lifecycle "$storage_user" \
        "$binary_directory/volparossa" "$WORK/runtime-client/control/agent.sock" \
        "$storage_key_a" "$storage_key_b" "$storage_key_c" >"$WORK/maintenance-owner-lifecycle.private" &
    MAINTENANCE_OWNER_PID=$!
    private_storage_maintenance_wait_marker working || return 1
    maintenance_old_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $maintenance_old_pid in ''|0|*[!0-9]*) return 1 ;; esac
    maintenance_namespace=$(stat -Lc '%d:%i' "/run/netns/$CLIENT") || return 1
    [ "$(stat -Lc '%d:%i' "/proc/$maintenance_old_pid/ns/net")" = "$maintenance_namespace" ] || return 1
    [ "$(readlink -f "/proc/$maintenance_old_pid/exe")" = "$binary_directory/volparossa-agent" ] || return 1
    # Only this already-owned disposable unit is stopped, never a caller-selected service.
    retire_unit volparossa-alpha-agent@client.service || return 1
    private_storage_maintenance_wait_marker unavailable || return 1
    maintenance_poll=0
    while [ "$(unit_load_state volparossa-alpha-agent@client.service)" != not-found ]; do
        [ "$maintenance_poll" -lt 100 ] || return 1
        sleep 0.1
        maintenance_poll=$((maintenance_poll + 1))
    done
    launch_agent client "$CLIENT"
    maintenance_poll=0
    while [ "$maintenance_poll" -lt 300 ]; do
        maintenance_new_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
        case $maintenance_new_pid in ''|0|*[!0-9]*) ;;
            *) [ -S "$WORK/runtime-client/control/agent.sock" ] && break ;;
        esac
        sleep 0.1
        maintenance_poll=$((maintenance_poll + 1))
    done
    [ "$maintenance_poll" -lt 300 ] && [ "$maintenance_new_pid" != "$maintenance_old_pid" ] || return 1
    [ "$(stat -Lc '%d:%i' "/proc/$maintenance_new_pid/ns/net")" = "$maintenance_namespace" ] || return 1
    [ "$(readlink -f "/proc/$maintenance_new_pid/exe")" = "$binary_directory/volparossa-agent" ] || return 1
    # Reuse current read-only inventory and ordinary protected selection barriers.
    python3 -I -B "$WORK/bin/content-provider-readiness.py" "$WORK" \
        >"$WORK/maintenance-inventory.private" || return 1
    benchmark_select_route private-storage-maintenance-reconnect mptcp || return 1
    private_storage_maintenance_post_reconnect
}

private_storage_maintenance_initial_inventory() {
    PHASE=private-storage-maintenance-inventory
    maintenance_inventory_status=0
    # This content-custody shortcut skips A01. Its Client deliberately cannot
    # see custody peers relay3/4/5; reuse the same relay0/1/2 + primary Exit
    # barrier as reconnect, not the six-relay discovered-compute fixture.
    (umask 077
     python3 -I -B "$WORK/bin/content-provider-readiness.py" "$WORK" \
        >"$WORK/maintenance-initial-inventory.part") || maintenance_inventory_status=$?
    if python3 -B "$WORK/bin/private-storage-maintenance-smoke.py" inventory-check \
        "$WORK/maintenance-initial-inventory.part" "$maintenance_inventory_status"; then
        mv -- "$WORK/maintenance-initial-inventory.part" \
            "$WORK/private-storage-maintenance-inventory.json" || fail MAINTENANCE_INVENTORY_INVALID
    else
        rm -f -- "$WORK/maintenance-initial-inventory.part"
        fail MAINTENANCE_INVENTORY_INVALID
    fi
    [ "$maintenance_inventory_status" -eq 0 ] || fail MAINTENANCE_INVENTORY_UNAVAILABLE
}

private_storage_maintenance_run() {
    storage_fixture_driver=private-storage-maintenance-smoke.py
    # Preserve all core exchange/turn deadlines. The fixture includes real daemon
    # ticks, quiet-link cooldown and bounded attempts against stopped provider A.
    storage_phase_timeout_seconds=2400
    ip -n "$CLIENT" -j -d link show cr0 | jq -e 'length == 1 and .[0].linkinfo.info_kind == "veth"
        and (.[0].flags | index("UP")) != null' >/dev/null || fail MAINTENANCE_GUEST_LINK_MISSING
    private_storage_maintenance_initial_inventory
    private_storage_fragments_run
}

private_storage_maintenance_finalize_report() {
    maintenance_status=$1
    # Already published at the original supervisor gate, before TERM/cleanup.
    # Reject malformed private metadata rather than exporting it as evidence.
    if [ -e "$WORK/private-storage-maintenance-supervisor.json" ] \
        || [ -L "$WORK/private-storage-maintenance-supervisor.json" ]; then
        if ! python3 -B "$source_directory/tests/integration/private-storage-maintenance-smoke.py" supervisor-check \
            "$WORK/private-storage-maintenance-supervisor.json" >/dev/null 2>&1; then
            rm -f -- "$WORK/private-storage-maintenance-supervisor.json" || return 1
        fi
    fi
    # Cleanup has already captured the bounded client event ring before stopping
    # agents. Export only closed categories/counts; diagnostic failure is not a
    # replacement for the original outcome and never changes acceptance.
    if python3 -B "$source_directory/tests/integration/private-storage-maintenance-smoke.py" route-diagnostic \
        "$WORK" >"$WORK/maintenance-route-diagnostic.part" 2>/dev/null; then
        mv -- "$WORK/maintenance-route-diagnostic.part" "$WORK/private-storage-maintenance-route-diagnostic.json" || true
    else
        rm -f -- "$WORK/maintenance-route-diagnostic.part" || true
    fi
    # The owner emits a closed failure receipt, not raw stderr. Preserve it only
    # after strict bounded schema validation, including on lifecycle failure.
    if [ "$maintenance_status" -ne 0 ] && [ -f "$WORK/maintenance-owner-lifecycle.private" ]; then
        if python3 -B "$source_directory/tests/integration/private-storage-maintenance-smoke.py" lifecycle-failure \
            "$WORK/maintenance-owner-lifecycle.private" >"$WORK/maintenance-lifecycle-failure.part" 2>/dev/null; then
            mv -- "$WORK/maintenance-lifecycle-failure.part" "$WORK/private-storage-maintenance-lifecycle-failure.json"
        else
            rm -f -- "$WORK/maintenance-lifecycle-failure.part"
        fi
    fi
    optional_json_evidence "$WORK/private-storage-maintenance-evidence.json" >"$WORK/handoff-report-evidence.part"
    optional_json_evidence "$WORK/storage-consumer-evidence.json" >"$WORK/handoff-report-consumers.part"
    optional_json_evidence "$WORK/a15-evidence.json" >"$WORK/handoff-report-host.part"
    jq -cn --arg revision "$expected_commit" --arg run "$RUN_ID" --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$maintenance_status" --slurpfile evidence "$WORK/handoff-report-evidence.part" \
        --slurpfile consumers "$WORK/handoff-report-consumers.part" \
        --slurpfile host "$WORK/handoff-report-host.part" --argjson complete "$CLEANUP_COMPLETE" \
        --argjson remaining "$REMAINING_OWNED_OBJECTS" '
      {schema_version:3,report_kind:"volparossa-private-storage-maintenance",source_revision:$revision,run_id:$run,
       phase:$phase,runner_exit_status:$status,maintenance:$evidence[0],consumers:$consumers[0],
       success:($status == 0 and $evidence[0].success == true and $consumers[0].success == true and $complete and $remaining == 0 and $host[0].unchanged == true),
       observed_blocker:(if $blocker == "NONE" then null else $blocker end),
       cleanup:{complete:$complete,remaining_owned_objects:$remaining},host_state:($host[0] | del(.acceptance_id)),
       scope:"Finite owner enrollment and protected renewal/repair across core restart, SIGTERM/resume and foreground revocation. Separate pinned Image encrypted snapshot and Cloud authenticated DAV-body restoration after A withdrawal, with retained original authority, actual replacement custody and independent zero provider usage. Synthetic inputs only; no running Immich/OpenCloud account server, independent-device availability, reciprocal credit, contribution resizing or full-alpha proof."}' \
        >"$WORK/private-storage-maintenance-smoke.json" || return 1
    maintenance_exports=$(python3 -B "$source_directory/tests/integration/private-storage-maintenance-smoke.py" export-names) || return 1
    for maintenance_name in $maintenance_exports; do
        maintenance_artifact=$WORK/$maintenance_name
        if [ -f "$maintenance_artifact" ] && [ ! -L "$maintenance_artifact" ]; then
            [ "$(wc -c <"$maintenance_artifact")" -le 1048576 ] || return 1
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$maintenance_artifact" "$output_directory/$maintenance_name"
        fi
    done
    python3 -B "$source_directory/tests/integration/private-storage-maintenance-smoke.py" report \
        "$WORK/private-storage-maintenance-smoke.json" "$expected_commit"
}
