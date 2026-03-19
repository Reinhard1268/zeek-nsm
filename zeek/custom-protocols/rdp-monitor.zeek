# File: rdp-monitor.zeek

@load base/frameworks/notice
@load base/protocols/rdp
@load base/protocols/conn

module RDPMonitor;

export {
    redef enum Notice::Type += {
        RDP_External_Connection,
        RDP_Brute_Force,
        RDP_Internal_Lateral,
        RDP_NLA_Disabled,
        RDP_Non_Standard_Port
    };

    const rdp_brute_threshold: count    = 10   &redef;
    const rdp_brute_window:    interval = 5min &redef;
    const rdp_ports: set[port] = { 3389/tcp }  &redef;
}

redef enum Log::ID += { LOG };

type Info: record {
    ts:            time   &log;
    src:           addr   &log;
    dst:           addr   &log;
    dport:         port   &log;
    cookie:        string &log &optional;
    security:      string &log &optional;
    auth_attempts: count  &log &optional;
    action:        string &log;
    detail:        string &log;
    mitre_id:      string &log;
};

global rdp_fail_counts: table[addr, addr] of count &create_expire=5min;
global alerted_brute:   set[addr]                  &create_expire=10min;

function is_local(a: addr): bool {
    return addr_matches_cidr(a, [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]);
}

event zeek_init() {
    Log::create_stream(RDPMonitor::LOG, [$columns=Info, $path="rdp-monitor"]);
}

event rdp_connect_request(c: connection, cookie: string) {
    local src   = c$id$orig_h;
    local dst   = c$id$resp_h;
    local dport = c$id$resp_p;

    if (!is_local(src) && is_local(dst)) {
        Log::write(RDPMonitor::LOG, Info(
            $ts=network_time(), $src=src, $dst=dst, $dport=dport,
            $cookie=cookie, $action="EXTERNAL_RDP",
            $detail=fmt("External RDP from %s to %s (cookie=%s)", src, dst, cookie),
            $mitre_id="T1021.001"));
        NOTICE([$note=RDP_External_Connection,
                $msg=fmt("External RDP from %s to %s", src, dst),
                $src=src, $dst=dst,
                $identifier=fmt("rdp-ext-%s-%s", src, dst)]);
    }

    if (is_local(src) && is_local(dst)) {
        Log::write(RDPMonitor::LOG, Info(
            $ts=network_time(), $src=src, $dst=dst, $dport=dport,
            $cookie=cookie, $action="INTERNAL_LATERAL_RDP",
            $detail=fmt("Internal RDP lateral movement from %s to %s", src, dst),
            $mitre_id="T1021.001"));
        NOTICE([$note=RDP_Internal_Lateral,
                $msg=fmt("Internal RDP from %s to %s", src, dst),
                $src=src, $dst=dst,
                $identifier=fmt("rdp-lateral-%s-%s", src, dst)]);
    }

    if (dport !in rdp_ports) {
        Log::write(RDPMonitor::LOG, Info(
            $ts=network_time(), $src=src, $dst=dst, $dport=dport,
            $action="NON_STANDARD_PORT",
            $detail=fmt("RDP on non-standard port %s from %s to %s", dport, src, dst),
            $mitre_id="T1021.001"));
        NOTICE([$note=RDP_Non_Standard_Port,
                $msg=fmt("RDP on non-standard port %s from %s", dport, src),
                $src=src,
                $identifier=fmt("rdp-port-%s-%s", src, dport)]);
    }
}

event rdp_negotiation_response(c: connection, security_protocol: count) {
    local src   = c$id$orig_h;
    local dst   = c$id$resp_h;
    local dport = c$id$resp_p;

    if (security_protocol == 0) {
        Log::write(RDPMonitor::LOG, Info(
            $ts=network_time(), $src=src, $dst=dst, $dport=dport,
            $security="Classic RDP (no NLA)", $action="NLA_DISABLED",
            $detail=fmt("RDP without NLA from %s to %s", src, dst),
            $mitre_id="T1557"));
        NOTICE([$note=RDP_NLA_Disabled,
                $msg=fmt("RDP without NLA from %s to %s", src, dst),
                $src=src, $dst=dst,
                $identifier=fmt("rdp-nla-%s-%s", src, dst)]);
    }
}

event connection_state_remove(c: connection) {
    local src   = c$id$orig_h;
    local dst   = c$id$resp_h;
    local dport = c$id$resp_p;

    if (dport != 3389/tcp) return;
    if (!is_local(dst)) return;

    if (c$conn$duration < 5secs && c$conn$orig_bytes < 1024) {
        if ([src, dst] !in rdp_fail_counts) rdp_fail_counts[src, dst] = 0;
        rdp_fail_counts[src, dst] += 1;

        if (rdp_fail_counts[src, dst] >= rdp_brute_threshold && src !in alerted_brute) {
            add alerted_brute[src];
            Log::write(RDPMonitor::LOG, Info(
                $ts=network_time(), $src=src, $dst=dst, $dport=dport,
                $auth_attempts=rdp_fail_counts[src, dst],
                $action="BRUTE_FORCE",
                $detail=fmt("RDP brute force from %s to %s: %d attempts",
                            src, dst, rdp_fail_counts[src, dst]),
                $mitre_id="T1110.001"));
            NOTICE([$note=RDP_Brute_Force,
                    $msg=fmt("RDP brute force from %s to %s: %d attempts",
                             src, dst, rdp_fail_counts[src, dst]),
                    $src=src, $dst=dst,
                    $identifier=fmt("rdp-brute-%s-%s", src, dst)]);
        }
    }
}
