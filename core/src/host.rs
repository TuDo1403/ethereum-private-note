//! What this process does about the machine it runs on. Software here cannot beat a keylogger, a screen
//! recorder or a kernel-level endpoint agent (CrowdStrike and the like): whoever owns the kernel sees every
//! keystroke, the screen and process memory. So there are two modest things, both heuristic:
//!
//! - `harden`: no core dumps, no debugger or `/proc/pid/mem` access by other processes of the same user,
//!   and (Linux) memory locked out of swap. Stops crash-dump collectors and same-user malware, not root.
//! - `require_trusted_host`: refuse to start while a network interface is up or a known monitoring agent
//!   is installed, unless the caller passes the explicit override. Turns the README's "run it offline on a
//!   machine you trust" from advice into a check. Absence of a finding proves nothing: the agent list is
//!   short and a determined agent is not found by its install path.
//!
//! Unix only, like the FIDO2 tools. This is the only module with `unsafe`: a few libc calls.
#![allow(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

/// Install paths of common endpoint monitoring agents, with the name to show. Heuristic: a path that exists
/// means the agent is installed, not that it is running or can see this process.
const AGENTS: &[(&str, &str)] = &[
    ("/Applications/Falcon.app", "CrowdStrike Falcon"),
    ("/opt/CrowdStrike", "CrowdStrike Falcon"),
    ("/Library/Sentinel", "SentinelOne"),
    ("/opt/sentinelone", "SentinelOne"),
    ("/Applications/VMware Carbon Black Cloud", "Carbon Black"),
    ("/opt/carbonblack", "Carbon Black"),
    (
        "/Library/Application Support/Microsoft/Defender",
        "Microsoft Defender for Endpoint",
    ),
    ("/opt/microsoft/mdatp", "Microsoft Defender for Endpoint"),
    ("/Library/Elastic/Endpoint", "Elastic Endpoint"),
    ("/opt/Elastic/Endpoint", "Elastic Endpoint"),
    (
        "/Library/Application Support/PaloAltoNetworks/Traps",
        "Cortex XDR",
    ),
    ("/opt/traps", "Cortex XDR"),
];

/// Locking everything needs room for Argon2's 1 GiB plus the rest of the process.
#[cfg(target_os = "linux")]
const MEMLOCK_NEEDED: libc::rlim_t = 3 << 30;

/// True for an address that means a real network: not loopback, unspecified or link-local (macOS keeps
/// fe80:: addresses on AirDrop and tunnel interfaces that go nowhere).
fn is_external(a: IpAddr) -> bool {
    match a {
        IpAddr::V4(a) => !(a.is_loopback() || a.is_unspecified() || a.is_link_local()),
        IpAddr::V6(a) => {
            !(a.is_loopback() || a.is_unspecified() || (a.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// Addresses of interfaces that are up and running (with carrier), as `name address`.
fn network_addresses() -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `list` is a valid out pointer; on success it is a list we free below with `freeifaddrs`.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        // Cannot tell. Reporting "no network" would be a silent pass, so report it as a finding.
        return vec!["? (could not list network interfaces)".into()];
    }
    let up = (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_uint;
    let mut p = list;
    while !p.is_null() {
        // SAFETY: `p` is a non-null node of the list `getifaddrs` returned; it stays valid until freed.
        let ifa = unsafe { &*p };
        p = ifa.ifa_next;
        if ifa.ifa_flags & up != up || ifa.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: `ifa_addr` is non-null and points to a sockaddr whose family says its real type, so the
        // casts below read a `sockaddr_in` or `sockaddr_in6` exactly when it is one.
        let addr = unsafe {
            match libc::c_int::from((*ifa.ifa_addr).sa_family) {
                libc::AF_INET => {
                    let s = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    IpAddr::V4(Ipv4Addr::from(u32::from_be(s.sin_addr.s_addr)))
                }
                libc::AF_INET6 => {
                    let s = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    IpAddr::V6(Ipv6Addr::from(s.sin6_addr.s6_addr))
                }
                _ => continue,
            }
        };
        if is_external(addr) {
            // SAFETY: `ifa_name` is a NUL-terminated string owned by the list.
            let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_string_lossy();
            // One line per interface: a typical host has an IPv4 and several IPv6 addresses on each.
            if !found.iter().any(|f| f.starts_with(&format!("{name} "))) {
                found.push(format!("{name} {addr}"));
            }
        }
    }
    // SAFETY: `list` came from a successful `getifaddrs` and nothing points into it any more.
    unsafe { libc::freeifaddrs(list) };
    found
}

/// Reasons this host should not see a seed. `exists` is injected so tests need no real agent.
fn problems(addresses: &[String], exists: impl Fn(&Path) -> bool) -> Vec<String> {
    let mut out: Vec<String> = addresses
        .iter()
        .map(|a| format!("network interface is up ({a})"))
        .collect();
    let mut seen: Vec<&str> = Vec::new();
    for (path, name) in AGENTS {
        if exists(Path::new(path)) && !seen.contains(name) {
            seen.push(name);
            out.push(format!("{name} is installed ({path})"));
        }
    }
    out
}

/// Refuses to continue on a networked host or one with a monitoring agent installed, unless `allow` (the
/// `--allow-unsafe-host` flag). With `allow` the findings are still printed, as a warning.
pub fn require_trusted_host(allow: bool) -> Result<(), String> {
    let found = problems(&network_addresses(), |p| p.exists());
    if found.is_empty() {
        return Ok(());
    }
    let list = found
        .iter()
        .map(|f| format!("  - {f}"))
        .collect::<Vec<_>>()
        .join("\n");
    if allow {
        eprintln!("warning: this host is not trusted for secrets:\n{list}");
        return Ok(());
    }
    Err(format!(
        "this host is not trusted for secrets:\n{list}\nA keylogger or endpoint agent here sees everything you type and print. \
         Use an offline machine (see README), or pass --allow-unsafe-host to continue anyway"
    ))
}

/// Turns on the process protections that exist on this OS and returns a warning for each one that failed.
/// Call it first thing in `main`, before any secret exists.
pub fn harden() -> Vec<String> {
    let mut warn = Vec::new();
    if !disable_core_dumps() {
        warn.push("could not disable core dumps".into());
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_SET_DUMPABLE takes one integer argument; the rest are ignored.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong, 0, 0, 0) } != 0 {
            warn.push("could not block other processes from reading this one".into());
        }
        if !lock_memory() {
            warn.push(
                "memory is not locked: secrets may reach swap (use swapoff or encrypted swap)"
                    .into(),
            );
        }
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: PT_DENY_ATTACH ignores pid, addr and data; it only marks this process as not debuggable.
        if unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) } != 0 {
            warn.push("could not block debuggers from attaching".into());
        }
    }
    warn
}

/// Sets the core file size limit to zero, so a crash writes no memory image to disk.
fn disable_core_dumps() -> bool {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `zero` is a valid rlimit that outlives the call.
    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) == 0 }
}

/// Locks all current and future pages (Linux). Only when the limit leaves room for Argon2's 1 GiB: with
/// `MCL_FUTURE` under a smaller limit that allocation would fail after the seed was already typed in.
#[cfg(target_os = "linux")]
fn lock_memory() -> bool {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid out pointer for the call.
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) } != 0 {
        return false;
    }
    if lim.rlim_cur != lim.rlim_max {
        lim.rlim_cur = lim.rlim_max; // raising the soft limit to the hard one is always allowed
        // SAFETY: `lim` is a valid rlimit that outlives the call.
        if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &lim) } != 0 {
            return false;
        }
    }
    if lim.rlim_cur != libc::RLIM_INFINITY && lim.rlim_cur < MEMLOCK_NEEDED {
        return false;
    }
    // SAFETY: mlockall takes only flags.
    unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_addresses() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        for a in [
            "192.168.1.5",
            "10.0.0.2",
            "8.8.8.8",
            "2001:db8::1",
            "fd00::1",
        ] {
            assert!(is_external(ip(a)), "{a}");
        }
        // Loopback, unspecified and link-local do not mean a network.
        for a in [
            "127.0.0.1",
            "0.0.0.0",
            "169.254.3.4",
            "::1",
            "::",
            "fe80::1",
            "febf::1",
        ] {
            assert!(!is_external(ip(a)), "{a}");
        }
        assert!(is_external(ip("fec0::1"))); // site-local is outside fe80::/10
    }

    #[test]
    fn problems_name_each_finding_once() {
        assert!(problems(&[], |_| false).is_empty());
        let p = problems(&["en0 192.168.1.5".into()], |_| false);
        assert_eq!(p, ["network interface is up (en0 192.168.1.5)"]);
        // Both CrowdStrike paths exist: still one line. A second vendor adds its own.
        let p = problems(&[], |path| {
            path.starts_with("/opt/CrowdStrike")
                || path.starts_with("/Applications/Falcon.app")
                || path.starts_with("/opt/traps")
        });
        assert_eq!(p.len(), 2, "{p:?}");
        assert!(p[0].starts_with("CrowdStrike Falcon is installed"));
        assert!(p[1].starts_with("Cortex XDR is installed"));
    }

    #[test]
    fn override_allows_a_flagged_host() {
        // Whatever this machine is, the override never refuses; without it a clean host passes too.
        assert!(require_trusted_host(true).is_ok());
    }

    #[test]
    fn core_dumps_are_disabled() {
        // Not `harden` itself: locking memory or denying debuggers inside the shared test process would
        // affect every other test. Those need a real process and are checked by running the binaries.
        assert!(disable_core_dumps());
        let mut lim = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: `lim` is a valid out pointer for the call.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) }, 0);
        assert_eq!(lim.rlim_cur, 0);
    }
}
