# Port Scan Results

Two scans were run for this assignment: one against Nmap's own public test
target, to safely demonstrate the tool without exposing personal system
details, and the required scan against my own machine (`localhost`).

## Scan 1 — Tool demonstration (Nmap's public test server)

`scanme.nmap.org` is a server Nmap's own project maintains specifically so
people can practice scanning without needing permission from a third party.
It's included here to show the tool working against a host with a more
varied set of open ports than a typical personal laptop.

**Command used:**

```bash
nmap scanme.nmap.org
```

**Actual Nmap output:**

```text
Starting Nmap 7.98 ( https://nmap.org ) at 2026-09-14 04:37 +0500
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.28s latency).
Other addresses for scanme.nmap.org (not scanned): 2600:3c01::f03c:91ff:fe18:bb2f
Not shown: 996 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
9929/tcp  open  nping-echo
31337/tcp open  Elite

Nmap done: 1 IP address (1 host up) scanned in 5.97 seconds
```

| Port | State | Service reported by Nmap | Likely purpose | Is it expected? |
|---|---|---|---|---|
| 22/tcp | open | ssh | Secure Shell — encrypted remote command-line access | Yes — Nmap's team runs this so people can test SSH-related tools |
| 80/tcp | open | http | Web server (unencrypted) | Yes — hosts a basic test page |
| 9929/tcp | open | nping-echo | Echo service for Nmap's own `nping` tool | Yes — intentionally exposed for testing Nmap's suite |
| 31337/tcp | open | Elite | Registered IANA name for this port | Ambiguous by design — 31337 ("eleet") is the same port number historically associated with old backdoor trojans like Back Orifice. On scanme.nmap.org it's a benign, intentional test port. This is a good illustration that a port *number* alone never tells you if something is safe — you have to know what's actually running behind it. |

## Scan 2 — Required scan (my own machine, localhost)

**Command used:**

```bash
nmap localhost
```

**Actual Nmap output:**

```text
Starting Nmap 7.98 ( https://nmap.org ) at 2026-09-14 04:39 +0500
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00091s latency).
Other addresses for localhost (not scanned): ::1
Not shown: 995 closed tcp ports (reset)
PORT      STATE SERVICE
135/tcp   open  msrpc
445/tcp   open  microsoft-ds
902/tcp   open  iss-realsecure
912/tcp   open  apex-mesh
49400/tcp open  compaqdiag

Nmap done: 1 IP address (1 host up) scanned in 0.23 seconds
```

`localhost` / `127.0.0.1` is the loopback address — it only ever refers to
"this machine," so including it here doesn't expose anything about my real
IP, hostname, or network to anyone reading this repo.

| Port | State | Service reported by Nmap | Likely purpose | Is it expected? |
|---|---|---|---|---|
| 135/tcp | open | msrpc | Windows RPC Endpoint Mapper — used internally by Windows services (DCOM, WMI, etc.) to locate other RPC services | Yes, normal on Windows. Should never be reachable from outside the machine — worth double-checking the firewall blocks it on public/untrusted networks. |
| 445/tcp | open | microsoft-ds | SMB — Windows file/printer sharing and authentication | Yes, if file sharing or Windows networking features are in use. This is the same port targeted by the EternalBlue/WannaCry exploit, so it's especially important this is never exposed beyond localhost/trusted LAN. |
| 902/tcp | open | iss-realsecure | This is just the port's default IANA-registered name in Nmap's database, not a confirmed identification. In practice, port 902 is very commonly opened by VMware software (`vmware-authd`) if VMware Workstation/Player is installed. | Likely yes if VMware is installed — worth verifying with `nmap -sV localhost` for a real fingerprint instead of the generic name. |
| 912/tcp | open | apex-mesh | Same caveat as above — the label is just Nmap's default guess for this port number. Also frequently associated with VMware's host management/auto-discovery service. | Likely yes if VMware is installed — same recommendation to verify with `-sV`. |
| 49400/tcp | open | compaqdiag | This falls in Windows' dynamic/ephemeral port range (49152–65535), which the OS hands out on the fly to background services. The "compaqdiag" label is just what happens to be registered for that port number in Nmap's database — it does not mean Compaq diagnostic software is actually running (Compaq hasn't existed as a brand since HP absorbed it in 2002). | Yes, expected — this is normal dynamic RPC allocation behavior on Windows, not a specific named product. |

## Interpretation

An open port means a service is listening for connections — it is not
automatically a vulnerability. Risk depends on the service, how it's
configured, whether it requires authentication, whether the software is
patched, and — critically — whether it's reachable from somewhere it
shouldn't be. All five ports found on localhost are normal for a Windows
machine and are only a concern if they end up exposed to an untrusted
network (home Wi-Fi guest network, public Wi-Fi, or the internet) rather
than staying bound to the local machine.

Nmap's default "service" column is a guess based on the port number,
looked up in a standard list — not a guaranteed identification of what's
actually running. Running `nmap -sV localhost` (version detection) would
give more confidence about ports like 902, 912, and 49400, where the
default label is ambiguous.
