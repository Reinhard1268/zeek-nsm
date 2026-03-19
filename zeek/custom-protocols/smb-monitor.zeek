# File: smb-monitor.zeek

@load base/frameworks/notice
@load base/protocols/smb

module SMBMonitor;

export {
    redef enum Notice::Type += {
        SMB_PsExec_Pattern,
        SMB_Admin_Share_Access,
        SMB_Ransomware_Extension,
        SMB_High_Write_Rate,
        SMB_Suspicious_File
    };

    const suspicious_extensions: set[string] = {
        "exe", "dll", "ps1", "bat", "vbs", "scr",
        "hta", "pif", "com", "lnk", "jar", "wsf"
    } &redef;

    const ransomware_extensions: set[string] = {
        "locky", "zepto", "cerber", "crypt", "encrypted",
        "locked", "wncry", "wnry", "wcry", "onion"
    } &redef;

    const high_write_threshold: count    = 100  &redef;
    const high_write_window:    interval = 1min &redef;
}

redef enum Log::ID += { LOG };

type Info: record {
    ts:       time   &log;
    src:      addr   &log;
    dst:      addr   &log;
    action:   string &log;
    filename: string &log &optional;
    share:    string &log &optional;
    size:     count  &log &optional;
    detail:   string &log;
    mitre_id: string &log;
};

global write_counts:  table[addr, addr] of count &create_expire=1min;
global ransom_writes: table[addr] of count       &create_expire=5min;

function get_extension(fname: string): string {
    local parts = split_string(fname, /\./);
    if (|parts| < 2) return "";
    return to_lower(parts[|parts| - 1]);
}

event zeek_init() {
    Log::create_stream(SMBMonitor::LOG, [$columns=Info, $path="smb-monitor"]);
}

event smb2_write_request(c: connection, hdr: SMB2::Header, file_id: SMB2::FileId,
                          offset: count, data_len: count) {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    if ([src, dst] !in write_counts) write_counts[src, dst] = 0;
    write_counts[src, dst] += 1;

    if (write_counts[src, dst] >= high_write_threshold) {
        Log::write(SMBMonitor::LOG, Info(
            $ts=network_time(), $src=src, $dst=dst,
            $action="HIGH_WRITE_RATE",
            $detail=fmt("High SMB write rate: %d writes/min from %s to %s",
                        write_counts[src, dst], src, dst),
            $mitre_id="T1486"));
        NOTICE([$note=SMB_High_Write_Rate,
                $msg=fmt("High SMB write rate from %s to %s (%d/min)",
                         src, dst, write_counts[src, dst]),
                $src=src, $dst=dst,
                $identifier=fmt("smb-writes-%s-%s", src, dst)]);
        write_counts[src, dst] = 0;
    }
}

event smb2_create_request(c: connection, hdr: SMB2::Header, name: string) {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local ext = get_extension(name);

    if (/PSEXESVC/ in name || /psexec/i in name) {
        Log::write(SMBMonitor::LOG, Info(
            $ts=network_time(), $src=src, $dst=dst,
            $action="PSEXEC_BINARY", $filename=name,
            $detail=fmt("PsExec binary via SMB: %s -> %s file=%s", src, dst, name),
            $mitre_id="T1569.002"));
        NOTICE([$note=SMB_PsExec_Pattern,
                $msg=fmt("PsExec via SMB from %s to %s: %s", src, dst, name),
                $src=src, $dst=dst,
                $identifier=fmt("smb-psexec-%s-%s", src, dst)]);
    }

    if (/\\\\[^\\]+\\ADMIN\$/ in name || /\\\\[^\\]+\\C\$/ in name) {
        Log::write(SMBMonitor::LOG, Info(
            $ts=network_time(), $src=src, $dst=dst,
            $action="ADMIN_SHARE_WRITE", $filename=name,
            $detail=fmt("Write to admin share: %s -> %s: %s", src, dst, name),
            $mitre_id="T1021.002"));
        NOTICE([$note=SMB_Admin_Share_Access,
                $msg=fmt("Admin share write from %s to %s: %s", src, dst, name),
                $src=src, $dst=dst,
                $identifier=fmt("smb-admin-%s-%s-%s", src, dst, name)]);
    }

    if (ext in suspicious_extensions) {
        Log::write(SMBMonitor::LOG, Info(
            $ts=network_time(), $src=src, $dst=dst,
            $action="SUSPICIOUS_FILE_WRITE", $filename=name,
            $detail=fmt("Suspicious file extension via SMB: %s -> %s file=%s", src, dst, name),
            $mitre_id="T1105"));
        NOTICE([$note=SMB_Suspicious_File,
                $msg=fmt("Suspicious file over SMB from %s to %s: %s", src, dst, name),
                $src=src, $dst=dst,
                $identifier=fmt("smb-sus-%s-%s-%s", src, dst, ext)]);
    }

    if (ext in ransomware_extensions) {
        if (src !in ransom_writes) ransom_writes[src] = 0;
        ransom_writes[src] += 1;
        Log::write(SMBMonitor::LOG, Info(
            $ts=network_time(), $src=src, $dst=dst,
            $action="RANSOMWARE_EXTENSION", $filename=name,
            $detail=fmt("Ransomware extension from %s to %s: %s", src, dst, name),
            $mitre_id="T1486"));
        NOTICE([$note=SMB_Ransomware_Extension,
                $msg=fmt("Ransomware extension from %s to %s: .%s", src, dst, ext),
                $src=src, $dst=dst,
                $identifier=fmt("smb-ransom-%s-%s", src, dst)]);
    }
}
