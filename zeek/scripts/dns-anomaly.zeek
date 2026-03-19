#dns-anomaly.zeek

@load base/frameworks/notice
@load base/protocols/dns

module DNSAnomaly;

export {
    redef enum Notice::Type += {
        DNS_High_Query_Volume,
        DNS_Long_Subdomain,
        DNS_High_Entropy_Domain,
        DNS_Non_Standard_Port,
        DNS_High_NXDOMAIN_Ratio
    };

    const query_rate_threshold:     count  = 100  &redef;
    const subdomain_len_threshold:  count  = 50   &redef;
    const entropy_threshold:        double = 3.5  &redef;
    const nxdomain_ratio_threshold: double = 0.70 &redef;
}

redef enum Log::ID += { LOG };

type Info: record {
    ts:            time   &log;
    src:           addr   &log;
    query:         string &log;
    qtype:         string &log;
    rcode:         string &log;
    subdomain_len: count  &log;
    entropy:       double &log;
    anomaly_type:  string &log;
    detail:        string &log;
};

global query_counts:    table[addr] of count &create_expire=1min;
global nxdomain_counts: table[addr] of count &create_expire=5min;
global total_counts:    table[addr] of count &create_expire=5min;

event zeek_init() {
    Log::create_stream(DNSAnomaly::LOG, [$columns=Info, $path="dns-anomaly"]);
}

function shannon_entropy(s: string): double {
    local freq: table[string] of count;
    local n = |s|;
    if (n == 0) return 0.0;
    for (i in s) {
        local ch = s[i];
        if (ch !in freq) freq[ch] = 0;
        freq[ch] += 1;
    }
    local entropy = 0.0;
    for (ch in freq) {
        local p = freq[ch] / (n * 1.0);
        entropy -= p * log(p) / log(2.0);
    }
    return entropy;
}

function get_subdomain(query: string): string {
    local parts = split_string(query, /\./);
    if (|parts| <= 2) return "";
    local sub = "";
    for (i in parts) {
        if (i < |parts| - 2) {
            if (sub != "") sub += ".";
            sub += parts[i];
        }
    }
    return sub;
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    local src   = c$id$orig_h;
    local dport = c$id$resp_p;

    if (src !in query_counts) query_counts[src] = 0;
    if (src !in total_counts) total_counts[src] = 0;
    query_counts[src] += 1;
    total_counts[src] += 1;

    if (query_counts[src] > query_rate_threshold) {
        Log::write(DNSAnomaly::LOG, Info(
            $ts=network_time(), $src=src, $query=query,
            $qtype=fmt("%d", qtype), $rcode="N/A",
            $subdomain_len=0, $entropy=0.0,
            $anomaly_type="HIGH_QUERY_VOLUME",
            $detail=fmt("%d queries/min from %s", query_counts[src], src)));
        NOTICE([$note=DNS_High_Query_Volume,
                $msg=fmt("High DNS query volume from %s: %d/min", src, query_counts[src]),
                $src=src, $identifier=fmt("dns-vol-%s", src)]);
        query_counts[src] = 0;
    }

    local subdomain = get_subdomain(query);
    local sub_len   = |subdomain|;
    if (sub_len > subdomain_len_threshold) {
        Log::write(DNSAnomaly::LOG, Info(
            $ts=network_time(), $src=src, $query=query,
            $qtype=fmt("%d", qtype), $rcode="N/A",
            $subdomain_len=sub_len, $entropy=0.0,
            $anomaly_type="LONG_SUBDOMAIN",
            $detail=fmt("Subdomain length %d exceeds threshold %d", sub_len, subdomain_len_threshold)));
        NOTICE([$note=DNS_Long_Subdomain,
                $msg=fmt("Long subdomain from %s: %s (%d chars)", src, query, sub_len),
                $src=src, $identifier=fmt("dns-long-%s-%s", src, query)]);
    }

    local label = split_string(query, /\./)[0];
    local ent   = shannon_entropy(label);
    if (ent > entropy_threshold) {
        Log::write(DNSAnomaly::LOG, Info(
            $ts=network_time(), $src=src, $query=query,
            $qtype=fmt("%d", qtype), $rcode="N/A",
            $subdomain_len=sub_len, $entropy=ent,
            $anomaly_type="HIGH_ENTROPY_DOMAIN",
            $detail=fmt("Entropy %.2f > %.2f for %s", ent, entropy_threshold, query)));
        NOTICE([$note=DNS_High_Entropy_Domain,
                $msg=fmt("High entropy domain from %s: %s (%.2f)", src, query, ent),
                $src=src, $identifier=fmt("dns-ent-%s-%s", src, query)]);
    }

    if (dport != 53/udp && dport != 53/tcp) {
        Log::write(DNSAnomaly::LOG, Info(
            $ts=network_time(), $src=src, $query=query,
            $qtype=fmt("%d", qtype), $rcode="N/A",
            $subdomain_len=0, $entropy=0.0,
            $anomaly_type="NON_STANDARD_PORT",
            $detail=fmt("DNS on port %s", dport)));
        NOTICE([$note=DNS_Non_Standard_Port,
                $msg=fmt("DNS on non-standard port from %s: %s", src, dport),
                $src=src, $identifier=fmt("dns-port-%s-%s", src, dport)]);
    }
}

event dns_end(c: connection, msg: dns_msg) {
    local src = c$id$orig_h;
    if (msg$rcode == 3) {
        if (src !in nxdomain_counts) nxdomain_counts[src] = 0;
        nxdomain_counts[src] += 1;
    }
    if (src in nxdomain_counts && src in total_counts && total_counts[src] > 20) {
        local ratio = nxdomain_counts[src] / (total_counts[src] * 1.0);
        if (ratio > nxdomain_ratio_threshold) {
            Log::write(DNSAnomaly::LOG, Info(
                $ts=network_time(), $src=src, $query="(multiple)",
                $qtype="N/A", $rcode="NXDOMAIN",
                $subdomain_len=0, $entropy=0.0,
                $anomaly_type="HIGH_NXDOMAIN_RATIO",
                $detail=fmt("NXDOMAIN ratio %.1f%% (%d/%d)",
                            ratio*100, nxdomain_counts[src], total_counts[src])));
            NOTICE([$note=DNS_High_NXDOMAIN_Ratio,
                    $msg=fmt("High NXDOMAIN ratio from %s: %.1f%%", src, ratio*100),
                    $src=src, $identifier=fmt("dns-nx-%s", src)]);
            nxdomain_counts[src] = 0;
            total_counts[src]    = 0;
        }
    }
}
