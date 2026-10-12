#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Additional explicit profile only; never replaces the original consumer run.
# shellcheck disable=SC2154,SC2034

private_cloud_upload_private() {
    STORAGE_PROOF_BASELINE_MS=${provider_baseline_ms:-0} \
      STORAGE_PROOF_ROUTE_SCOPE=${storage_route_scope:-} \
      timeout --signal=TERM --kill-after=30s 2400s setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$custody_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/cloud-upload-maintenance-smoke.py" "$@"
}

private_cloud_upload_phase() {
    case $1 in upload|exercise|finish) ;; *) fail CLOUD_UPLOAD_PHASE_INVALID ;; esac
    upload_phase=$1
    upload_minimum=$(private_cloud_upload_private flow-minimum "$upload_phase" "$upload_user") \
        || fail CLOUD_UPLOAD_FLOW_MINIMUM_INVALID
    case $upload_minimum in ''|*[!0-9]*) fail CLOUD_UPLOAD_FLOW_MINIMUM_INVALID ;; esac
    PHASE=cloud-upload-$upload_phase
    private_storage_fragments_phase_start "cloud-upload-$upload_phase"
    private_cloud_upload_private "$upload_phase" "$upload_user" \
        "$WORK/runtime-exit/control/agent.sock" "$storage_user" \
        >"$WORK/cloud-upload-$upload_phase.json" || fail CLOUD_UPLOAD_APPLICATION_FAILED
    private_storage_fragments_phase_finish "$upload_minimum"
}

private_cloud_upload_cleanup() {
    [ "${upload_private_cleanup_complete:-no}" != yes ] || return 0
    [ -n "${upload_user:-}" ] || return 0
    private_cloud_upload_private cleanup "$upload_user" \
        >"$WORK/cloud-upload-private-cleanup.json" || return 1
    rmdir "$WORK/u" || return 1
    upload_private_cleanup_complete=yes
}

private_cloud_upload_run() {
    [ "${private_storage_maintenance:-no}" = yes ] && [ "${cloud_upload_maintenance:-no}" = yes ] \
        || fail CLOUD_UPLOAD_PROFILE_INVALID
    [ "${consumer_private_cleanup_complete:-no}" = yes ] || fail CLOUD_UPLOAD_PRIOR_CONSUMER_NOT_JOINED
    # Validate the unchanged mandatory prior profile first. The final joined
    # evidence builder additionally reconstructs it from all original raw files.
    python3 -B "$source_directory/tests/integration/storage-consumer-maintenance-evidence.py" \
        check "$WORK/storage-consumer-evidence.json" || fail CLOUD_UPLOAD_PRIOR_CONSUMER_INVALID
    jq -e 'length == 3 and all(.[]; . == {reserved_bytes:0,committed_bytes:0,leases:0})' \
        "$WORK/private-storage-fragments-consumer_deleted_usage.json" >/dev/null \
        || fail CLOUD_UPLOAD_INITIAL_STORE_NOT_EMPTY
    if [ -e "$WORK/u" ] || [ -L "$WORK/u" ]; then fail CLOUD_UPLOAD_OWNER_PARENT_NOT_NEW; fi
    upload_user=$WORK/u/a
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$WORK/u" "$upload_user"
    upload_client_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $upload_client_pid in ''|0|*[!0-9]*) fail CLOUD_UPLOAD_CLIENT_PID_INVALID ;; esac
    nsenter --target "$upload_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$WORK/state-client/identity.key" || fail CLOUD_UPLOAD_POSITIVE_ISOLATION_FAILED
    for upload_private in "$upload_user" "$WORK/state-relay4/private-store" \
        "$WORK/state-relay5/private-store" "$WORK/state-relay3/private-store"; do
        if nsenter --target "$upload_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
            --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$upload_private"; then fail CLOUD_UPLOAD_LOCAL_SHORTCUT; fi
    done
    jq -n --argjson user "$WORKER_UID" --argjson agent "$AGENT_UID" \
        '{user_uid:$user,agent_uid:$agent,agent_mount_positive_control:true,
        client_cannot_read_new_owner_root:true,client_cannot_read_any_provider_store:true}' \
        >"$WORK/cloud-upload-isolation.json"
    [ -f /opt/volparossa-cloud-upload-proof/provision.json ] \
        && [ ! -L /opt/volparossa-cloud-upload-proof/provision.json ] || fail CLOUD_UPLOAD_PROVISION_MISSING
    install -o root -g root -m 0600 /opt/volparossa-cloud-upload-proof/provision.json \
        "$WORK/cloud-upload-provision.json"

    private_storage_fragments_reopen relay4 relay5 relay3
    PHASE=cloud-upload-prepare
    private_cloud_upload_private prepare "$upload_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$WORK/runtime-relay4/control/agent.sock" \
        "$WORK/runtime-relay5/control/agent.sock" "$WORK/runtime-relay3/control/agent.sock" \
        "$storage_key_a" "$storage_key_b" "$storage_key_c" \
        >"$WORK/cloud-upload-prepare.json" || fail CLOUD_UPLOAD_PREPARE_FAILED
    private_cloud_upload_phase upload
    private_storage_fragments_usage cloud_upload_uploaded_usage

    # The joined upload receipt measures completed early A migrations. Only
    # remaining original A copies count as new repair after this withdrawal.
    private_storage_fragments_reopen relay5 relay3
    content_custody_cli relay4 content status | jq -e '.serving == false' >/dev/null \
        || fail CLOUD_UPLOAD_SOURCE_STILL_SERVING
    for upload_node in relay5 relay3; do
        content_custody_cli "$upload_node" content status | jq -e '.serving == true' >/dev/null \
            || fail CLOUD_UPLOAD_SURVIVOR_NOT_SERVING
    done
    private_cloud_upload_phase exercise
    private_storage_fragments_usage cloud_upload_restored_usage

    private_storage_fragments_reopen relay4 relay5 relay3
    private_cloud_upload_phase finish
    private_storage_fragments_usage cloud_upload_deleted_usage
    jq -e 'length == 3 and all(.[]; . == {reserved_bytes:0,committed_bytes:0,leases:0})' \
        "$WORK/private-storage-fragments-cloud_upload_deleted_usage.json" >/dev/null \
        || fail CLOUD_UPLOAD_PROVIDER_CLEANUP_INCOMPLETE
    jq -n '{first_provider_stopped_after_measured_upload_baseline:true,
        first_provider_stopped_before_new_repair_and_reads:true,first_store_retained:true,
        other_two_providers_serving:true,same_three_stores_reopened:true,
        all_usage_snapshots_with_services_stopped:true,all_three_store_inodes_preserved:true}' \
        >"$WORK/cloud-upload-withdrawal.json"
    private_cloud_upload_cleanup || fail CLOUD_UPLOAD_PRIVATE_CLEANUP_FAILED
    python3 -B "$source_directory/tests/integration/cloud-upload-maintenance-evidence.py" \
        evidence "$WORK" "$WORK/cloud-upload-evidence.json" || fail CLOUD_UPLOAD_EVIDENCE_INVALID
}

private_cloud_upload_finalize_report() {
    upload_final_status=$1
    python3 -B "$source_directory/tests/integration/cloud-upload-maintenance-evidence.py" finalize-report \
        "$WORK" "$expected_commit" "$RUN_ID" "$PHASE" "$upload_final_status" "$CLEANUP_COMPLETE" \
        "$REMAINING_OWNED_OBJECTS" "$OBSERVED_BLOCKER" "$WORK/cloud-upload-maintenance-smoke.json" || return 1
    upload_exports=$(python3 -B "$source_directory/tests/integration/cloud-upload-maintenance-evidence.py" export-names) || return 1
    for upload_name in $upload_exports; do
        upload_artifact=$WORK/$upload_name
        if [ -f "$upload_artifact" ] && [ ! -L "$upload_artifact" ]; then
            [ "$(wc -c <"$upload_artifact")" -le 1048576 ] || return 1
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$upload_artifact" "$output_directory/$upload_name"
        fi
    done
    python3 -B "$source_directory/tests/integration/cloud-upload-maintenance-evidence.py" check-report \
        "$WORK/cloud-upload-maintenance-smoke.json" "$expected_commit"
}
