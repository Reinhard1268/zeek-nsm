#lateral-movement.zeek

@load base/frameworks/notice
@load base/protocols/smb
@load base/protocols/conn

module LateralMovement;

export {
    redef enum Notice::Type += {
        LM_SMB_Multi_Host_Scan,
        LM_Auth_Spray,
        LM_PsExec_Detected,
        LM_WMI_Remote_Exec,
        LM_RDP_Multi_Hop,
        LM_Admin_Share_Access
    };

    const smb_scan_threshold:   count    = 5    &redef;
    const smb_scan_window:      interval = 3min &redef;
    const auth_spray_threshold: count    = 5    &redef;
    const auth_spray_window:    interval = 3min &redef;
}

redef enum Log::ID += { LOG };

type Info: record {
    ts:           time   &log;
    src:          addr   &log;
    dst:          addr   &log;
    proto:        string &log;
    technique:    string &log;
    host_count:   count  &log &optional;
    detail:       string &log;
    mitre_tactic: string &log;
    mitre_id:     string &log;
};

global smb_targets:   table[addr] of set[addr] &create_expire=3min;
global auth_attempts: table[addr] of count     &create_expire=3min;
global alerted_smb:   set[addr]                &create_expire=10min;
global alerted_auth:  set[addr]                &create_expire=10min;

function is_local(a: addr): bool {
    return addr_matches_cidr(a, [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]);
}

event zeek_init() {
    Log::create_stream(LateralMovement::LOG, [$columns=Info, $path="lateral-movement"]);
}

event connection_established(c: connection) {
    local src   = c$id$orig_h;
    local dst   = c$id$resp_h;
    local dport = c$id$resp_p;

    if (!is_local(src) || !is_local(dst)) return;

    if (dport == 445/tcp || dport == 139/tcp) {
        if (src !in smb_targets) smb_targets[src] = set();
        add smb_targets[src][dst];

        if (|smb_targets[src]| >= smb_scan_threshold && src !in alerted_smb) {
            add alerted_smb[src];
            Log::write(LateralMovement::LOG, Info(
                $ts=network_time(), $src=src, $dst=dst,
                $proto="smb", $technique="SMB_MULTI_HOST_SCAN",
                $host_count=|smb_targets[src]|,
                $detail=fmt("%s scanned %d SMB hosts", src, |smb_targets[src]|),
                $mitre_tactic="Lateral Movement",
                $mitre_id="T1021.002"));
            NOTICE([$note=LM_SMB_Multi_Host_Scan,
                    $msg=fmt("SMB multi-host scan from %s: %d hosts",
                             src, |smb_targets[src]|),
                    $src=src,
                    $identifier=fmt("lm-smb-scan-%s", src)]);
        }
    }

    if (dport == 3389/tcp) {
        Log::write(LateralMovement::LOG, Info(
            $ts=network_time(), $src=src, $dst=dst,
            $proto="rdp", $technique="RDP_INTERNAL_CONNECTION",
            $detail=fmt("Internal RDP from %s to %s", src, dst),
            $mitre_tactic="Lateral Movement",
            $mitre_id="T1021.001"));
        NOTICE([$note=LM_RDP_Multi_Hop,
                $msg=fmt("Internal RDP: %s -> %s", src, dst),
                $src=src, $dst=dst,
                $identifier=fmt("lm-rdp-%s-%s", src, dst)]);
    }

    if (dport == 135/tcp) {
        if (src !in auth_attempts) auth_attempts[src] = 0;
        auth_attempts[src] += 1;
        if (auth_attempts[src] >= 3) {
            Log::write(LateralMovement::LOG, Info(
                $ts=network_time(), $src=src, $dst=dst,
                $proto="dcom", $technique="WMI_REMOTE_EXEC",
                $detail=fmt("WMI/DCOM from %s to %s", src, dst),
                $mitre_tactic="Lateral Movement",
                $mitre_id="T1047"));
            NOTICE([$note=LM_WMI_Remote_Exec,
                    $msg=fmt("WMI/DCOM lateral movement from %s to %s", src, dst),
                    $src=src, $dst=dst,
                    $identifier=fmt("lm-wmi-%s-%s", src, dst)]);
            auth_attempts[src] = 0;
        }
    }
}

event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool) {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    if (!is_local(src)) return;
    if (!c$smb_state?$current_file) return;
    if (!c$smb_state$current_file?$name) return;
    local fname = c$smb_state$current_file$name;

    if (/ADMIN\$/ in fname || /C\$\\/ in fname || /IPC\$/ in fname) {
        Log::write(LateralMovement::LOG, Info(
            $ts=network_time(), $src=src, $dst=dst,
            $proto="smb", $technique="ADMIN_SHARE_ACCESS",
            $detail=fmt("Admin share from %s to %s: %s", src, dst, fname),
            $mitre_tactic="Lateral Movement",
            $mitre_id="T1021.002"));
        NOTICE([$note=LM_Admin_Share_Access,
                $msg=fmt("Admin share from %s to %s: %s", src, dst, fname),
                $src=src, $dst=dst,
                $identifier=fmt("lm-share-%s-%s-%s", src, dst, fname)]);
    }

    if (/PSEXESVC/ in fname || /psexec/ in fname) {
        Log::write(LateralMovement::LOG, Info(
            $ts=network_time(), $src=src, $dst=dst,
            $proto="smb", $technique="PSEXEC_LATERAL_MOVEMENT",
            $detail=fmt("PsExec detected: %s from %s to %s", fname, src, dst),
            $mitre_tactic="Lateral Movement",
            $mitre_id="T1569.002"));
        NOTICE([$note=LM_PsExec_Detected,
                $msg=fmt("PsExec from %s to %s: %s", src, dst, fname),
                $src=src, $dst=dst,
                $identifier=fmt("lm-psexec-%s-%s", src, dst)]);
    }
}
