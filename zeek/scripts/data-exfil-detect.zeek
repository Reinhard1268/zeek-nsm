# File: data-exfil-detect.zeek

@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/http

module DataExfil;

export {
    redef enum Notice::Type += {
        Exfil_High_Volume_Outbound,
        Exfil_HTTP_Large_POST,
        Exfil_DNS_Tunneling,
        Exfil_Long_DNS_Query
    };

    const volume_threshold_bytes: count  = 104857600 &redef;  # 100 MB
    const post_threshold_bytes:   count  = 5242880   &redef;  # 5 MB
    const dns_label_threshold:    count  = 50        &redef;
}

redef enum Log::ID += { LOG };

type Info: record {
    ts:          time   &log;
    src:         addr   &log;
    dst:         addr   &log;
    proto:       string &log;
    bytes_out:   count  &log;
    threshold:   count  &log;
    detail:      string &log;
    notice_type: string &log;
};

global outbound_bytes: table[addr, addr] of count &create_expire=1hr;
global last_alert:     table[addr, addr] of time  &create_expire=1hr;

function is_local(a: addr): bool {
    return addr_matches_cidr(a, [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]);
}

event zeek_init() {
    Log::create_stream(DataExfil::LOG, [$columns=Info, $path="data-exfil"]);
}

event connection_state_remove(c: connection) {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    if (!is_local(src) || is_local(dst)) return;
    if (!c$conn?$orig_bytes) return;

    local bytes = c$conn$orig_bytes;
    if ([src, dst] !in outbound_bytes) outbound_bytes[src, dst] = 0;
    outbound_bytes[src, dst] += bytes;

    if (outbound_bytes[src, dst] >= volume_threshold_bytes) {
        local mb = outbound_bytes[src, dst] / 1048576.0;
        if ([src, dst] !in last_alert || network_time() - last_alert[src, dst] > 1hr) {
            last_alert[src, dst] = network_time();
            Log::write(DataExfil::LOG, Info(
                $ts=network_time(), $src=src, $dst=dst,
                $proto="tcp", $bytes_out=outbound_bytes[src, dst],
                $threshold=volume_threshold_bytes,
                $detail=fmt("%.1f MB outbound from %s to %s in last hour", mb, src, dst),
                $notice_type="VOLUME_EXFIL"));
            NOTICE([$note=Exfil_High_Volume_Outbound,
                    $msg=fmt("High outbound volume: %.1f MB from %s -> %s", mb, src, dst),
                    $src=src, $dst=dst,
                    $identifier=fmt("exfil-vol-%s-%s", src, dst)]);
        }
        outbound_bytes[src, dst] = 0;
    }
}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) {
    if (!is_orig) return;

    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    if (!is_local(src) || is_local(dst)) return;
    if (!c$http?$method) return;
    if (c$http$method != "POST" && c$http$method != "PUT") return;

    local body_len = stat$body_length;
    if (body_len < post_threshold_bytes) return;

    local mb = body_len / 1048576.0;
    Log::write(DataExfil::LOG, Info(
        $ts=network_time(), $src=src, $dst=dst,
        $proto="http", $bytes_out=body_len,
        $threshold=post_threshold_bytes,
        $detail=fmt("HTTP %s %.1f MB to %s%s",
                    c$http$method, mb, dst,
                    c$http?$uri ? c$http$uri : ""),
        $notice_type="HTTP_POST_EXFIL"));
    NOTICE([$note=Exfil_HTTP_Large_POST,
            $msg=fmt("Large HTTP %s %.1f MB from %s to %s",
                     c$http$method, mb, src, dst),
            $src=src, $dst=dst,
            $identifier=fmt("exfil-post-%s-%s", src, dst)]);
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    local parts    = split_string(query, /\./);
    if (|parts| < 2) return;
    local subdomain = parts[0];
    local sub_len   = |subdomain|;
    if (sub_len < dns_label_threshold) return;

    local src = c$id$orig_h;
    Log::write(DataExfil::LOG, Info(
        $ts=network_time(), $src=src, $dst=c$id$resp_h,
        $proto="dns", $bytes_out=sub_len,
        $threshold=dns_label_threshold,
        $detail=fmt("DNS exfil suspected: label length %d in query %s", sub_len, query),
        $notice_type="DNS_TUNNEL_EXFIL"));
    NOTICE([$note=Exfil_DNS_Tunneling,
            $msg=fmt("DNS tunneling from %s: label %d chars in %s", src, sub_len, query),
            $src=src,
            $identifier=fmt("exfil-dns-%s-%s", src, query)]);
}
