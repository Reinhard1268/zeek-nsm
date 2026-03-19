#beaconing-detect.zeek

@load base/frameworks/notice
@load base/protocols/conn

module BeaconingDetect;

export {
    redef enum Notice::Type += {
        C2_Beaconing_Detected,
        C2_Beaconing_High_Confidence
    };

    const min_connections:  count  = 10  &redef;
    const cv_threshold:     double = 0.3 &redef;
    const beacon_min_secs:  double = 5.0 &redef;
    const beacon_max_secs:  double = 3600.0 &redef;
}

redef enum Log::ID += { LOG };

type Info: record {
    ts:               time   &log;
    src:              addr   &log;
    dst:              addr   &log;
    dport:            port   &log;
    interval_mean:    double &log;
    interval_std:     double &log;
    interval_cv:      double &log;
    connection_count: count  &log;
    confidence_score: double &log;
    verdict:          string &log;
    detail:           string &log;
};

# Stores per src->dst connection timestamps
global conn_timestamps: table[addr, addr, port] of vector of double
    &create_expire=2hrs;

global alerted_pairs: table[addr, addr, port] of time
    &create_expire=1hr;

function is_local(a: addr): bool {
    return addr_matches_cidr(a, [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]);
}

function vector_mean(v: vector of double): double {
    if (|v| == 0) return 0.0;
    local total = 0.0;
    for (i in v) total += v[i];
    return total / |v|;
}

function vector_std(v: vector of double, mean: double): double {
    if (|v| < 2) return 0.0;
    local sum_sq = 0.0;
    for (i in v) {
        local diff = v[i] - mean;
        sum_sq += diff * diff;
    }
    return sqrt(sum_sq / |v|);
}

function compute_cv(intervals: vector of double): double {
    if (|intervals| < 2) return 9999.0;
    local mean = vector_mean(intervals);
    if (mean == 0.0) return 9999.0;
    local std = vector_std(intervals, mean);
    return std / mean;
}

function confidence_score(cv: double, conn_count: count): double {
    local cv_score    = 0.0;
    local count_score = 0.0;
    if (cv < cv_threshold)
        cv_score = (cv_threshold - cv) / cv_threshold * 50.0;
    count_score = conn_count > 100 ? 50.0 : (conn_count / 100.0) * 50.0;
    return cv_score + count_score;
}

event zeek_init() {
    Log::create_stream(BeaconingDetect::LOG, [$columns=Info, $path="beaconing"]);
}

event connection_established(c: connection) {
    local src   = c$id$orig_h;
    local dst   = c$id$resp_h;
    local dport = c$id$resp_p;

    # Only monitor local -> external
    if (!is_local(src) || is_local(dst)) return;

    # Only TCP/UDP (skip ICMP etc)
    if (c$id$proto != tcp && c$id$proto != udp) return;

    local key = [src, dst, dport];
    if (key !in conn_timestamps)
        conn_timestamps[key] = vector();

    conn_timestamps[key] += double_to_time(time_to_double(network_time()));

    local ts_vec = conn_timestamps[key];
    if (|ts_vec| < min_connections) return;

    # Compute intervals between consecutive connections
    local intervals: vector of double = vector();
    for (i in ts_vec) {
        if (i == 0) next;
        local gap = ts_vec[i] - ts_vec[i-1];
        if (gap >= beacon_min_secs && gap <= beacon_max_secs)
            intervals += gap;
    }

    if (|intervals| < min_connections - 1) return;

    local mean = vector_mean(intervals);
    local std  = vector_std(intervals, mean);
    local cv   = mean > 0.0 ? std / mean : 9999.0;

    if (cv > cv_threshold) return;

    # Throttle alerts per pair
    if (key in alerted_pairs &&
        network_time() - alerted_pairs[key] < 30min) return;

    alerted_pairs[key] = network_time();

    local score   = confidence_score(cv, |ts_vec|);
    local verdict = score > 70.0 ? "BEACON_HIGH" : "BEACON_MEDIUM";

    Log::write(BeaconingDetect::LOG, Info(
        $ts=network_time(),
        $src=src,
        $dst=dst,
        $dport=dport,
        $interval_mean=mean,
        $interval_std=std,
        $interval_cv=cv,
        $connection_count=|ts_vec|,
        $confidence_score=score,
        $verdict=verdict,
        $detail=fmt("Beacon: %s->%s:%s interval=%.1fs CV=%.3f count=%d score=%.1f",
                    src, dst, dport, mean, cv, |ts_vec|, score)));

    local note = score > 70.0 ? C2_Beaconing_High_Confidence : C2_Beaconing_Detected;
    NOTICE([$note=note,
            $msg=fmt("[%s] Beaconing from %s to %s:%s — interval=%.1fs CV=%.3f score=%.1f",
                     verdict, src, dst, dport, mean, cv, score),
            $src=src,
            $dst=dst,
            $identifier=fmt("beacon-%s-%s-%s", src, dst, dport)]);
}
