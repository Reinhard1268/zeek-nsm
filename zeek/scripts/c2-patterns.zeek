#c2-patterns.zeek

@load base/frameworks/notice
@load base/protocols/ssl
@load base/protocols/http

module C2Patterns;

export {
    redef enum Notice::Type += {
        C2_JA3_Suspicious,
        C2_SSL_SelfSigned,
        C2_SSL_Expired,
        C2_No_PTR_Record,
        C2_HTTP_Suspicious_UA,
        C2_Non_Standard_Port_TLS
    };

    const malicious_ja3: set[string] = {
        "a0e9f5d64349fb13191bc781f81f42e1",  # Cobalt Strike default
        "72a589da586844d7f0818ce684948eea",  # Metasploit Meterpreter
        "de9f2c7fd25e1b3afad3e85a0bd17d9b",  # AsyncRAT
        "4d7a28d6f2263ed61de88ca66eb011e3",  # Sliver C2
        "b386946a5a44d1ddcc843bc75336dfce",  # Havoc C2
        "d0ec3b5f84b63bb40fa5e8e2b3e9e7f5",  # Brute Ratel
    } &redef;

    const suspicious_cert_cn: set[string] = {
        "AsyncRAT Server",
        "Metasploit",
        "localhost",
        "test",
    } &redef;

    const c2_tls_ports: set[port] = {
        4443/tcp, 8443/tcp, 6606/tcp, 7707/tcp, 9001/tcp, 1337/tcp
    } &redef;

    const suspicious_ua_patterns: vector of pattern = {
        /python-requests/,
        /Go-http-client/,
        /curl\//,
        /Wget\//,
        /libwww-perl/,
        /Mozilla\/4\.0 \(compatible\)$/,
    };
}

redef enum Log::ID += { LOG };

type Info: record {
    ts:          time   &log;
    src:         addr   &log;
    dst:         addr   &log;
    sport:       port   &log;
    dport:       port   &log;
    indicator:   string &log;
    detail:      string &log;
    notice_type: string &log;
};

event zeek_init() {
    Log::create_stream(C2Patterns::LOG, [$columns=Info, $path="c2-patterns"]);
}

event ssl_established(c: connection) {
    if (!c?$ssl) return;

    local src   = c$id$orig_h;
    local dst   = c$id$resp_h;
    local dport = c$id$resp_p;
    local ssl   = c$ssl;

    if (ssl?$ja3 && ssl$ja3 in malicious_ja3) {
        Log::write(C2Patterns::LOG, Info(
            $ts=network_time(), $src=src, $dst=dst,
            $sport=c$id$orig_p, $dport=dport,
            $indicator=ssl$ja3,
            $detail=fmt("Malicious JA3 matched: %s -> %s", src, dst),
            $notice_type="JA3_MATCH"));
        NOTICE([$note=C2_JA3_Suspicious,
                $msg=fmt("Malicious JA3 from %s to %s: %s", src, dst, ssl$ja3),
                $src=src, $dst=dst,
                $identifier=fmt("c2-ja3-%s-%s", src, ssl$ja3)]);
    }

    if (ssl?$subject && ssl?$issuer && ssl$subject == ssl$issuer) {
        local cn = ssl$subject;
        Log::write(C2Patterns::LOG, Info(
            $ts=network_time(), $src=src, $dst=dst,
            $sport=c$id$orig_p, $dport=dport,
            $indicator=cn,
            $detail=fmt("Self-signed cert: %s -> %s CN=%s", src, dst, cn),
            $notice_type="SELF_SIGNED"));
        local short_cn = split_string(cn, /CN=/);
        if (|short_cn| > 1 && short_cn[1] in suspicious_cert_cn) {
            NOTICE([$note=C2_SSL_SelfSigned,
                    $msg=fmt("Known malware cert from %s to %s: CN=%s", src, dst, cn),
                    $src=src, $dst=dst,
                    $identifier=fmt("c2-cert-%s-%s", src, dst)]);
        } else {
            NOTICE([$note=C2_SSL_SelfSigned,
                    $msg=fmt("Self-signed cert from %s to %s: CN=%s", src, dst, cn),
                    $src=src, $dst=dst,
                    $identifier=fmt("c2-selfsign-%s-%s", src, dst)]);
        }
    }

    if (dport in c2_tls_ports) {
        Log::write(C2Patterns::LOG, Info(
            $ts=network_time(), $src=src, $dst=dst,
            $sport=c$id$orig_p, $dport=dport,
            $indicator=fmt("%s", dport),
            $detail=fmt("TLS on suspicious port %s: %s -> %s", dport, src, dst),
            $notice_type="NONSTANDARD_TLS_PORT"));
        NOTICE([$note=C2_Non_Standard_Port_TLS,
                $msg=fmt("TLS C2 on port %s from %s to %s", dport, src, dst),
                $src=src, $dst=dst,
                $identifier=fmt("c2-port-%s-%s-%s", src, dst, dport)]);
    }

    if (ssl?$not_valid_after && ssl$not_valid_after < network_time()) {
        Log::write(C2Patterns::LOG, Info(
            $ts=network_time(), $src=src, $dst=dst,
            $sport=c$id$orig_p, $dport=dport,
            $indicator=fmt("expired:%s", ssl$not_valid_after),
            $detail=fmt("Expired cert from %s to %s", src, dst),
            $notice_type="EXPIRED_CERT"));
        NOTICE([$note=C2_SSL_Expired,
                $msg=fmt("Expired TLS cert from %s to %s", src, dst),
                $src=src, $dst=dst,
                $identifier=fmt("c2-exp-%s-%s", src, dst)]);
    }
}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) {
    if (!c$http?$user_agent) return;
    local ua  = c$http$user_agent;
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    for (i in suspicious_ua_patterns) {
        if (suspicious_ua_patterns[i] in ua) {
            Log::write(C2Patterns::LOG, Info(
                $ts=network_time(), $src=src, $dst=dst,
                $sport=c$id$orig_p, $dport=c$id$resp_p,
                $indicator=ua,
                $detail=fmt("Suspicious UA from %s: %s", src, ua),
                $notice_type="SUSPICIOUS_UA"));
            NOTICE([$note=C2_HTTP_Suspicious_UA,
                    $msg=fmt("Suspicious HTTP UA from %s: %s", src, ua),
                    $src=src,
                    $identifier=fmt("c2-ua-%s-%s", src, ua)]);
            break;
        }
    }
}
