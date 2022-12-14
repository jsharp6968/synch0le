# Synch0le

This tool is for exploring HTTP De-Sync attacks using the client-side, Connection-locked TE.CL and CL.TE methods detailed by [James Kettle](https://skeletonscribe.net/) in his [research](https://i.blackhat.com/USA-22/Wednesday/us-22-Kettle-Browser-Powered-Desync-Attacks-wp.pdf) "Browser-Powered Desync Attacks: A New Frontier in
HTTP Request Smuggling" published at Defcon and Blackhat. 

Full blog [post](https://sharpsec.run/?p=127).

This tool is for quickly scanning endpoints to figure out if they might be vulnerable to a Desync attack. Actually attacking such vulns in applications requires work on a case by case basis: this tool will not pwn anything for you. It is intended to be fed lists of subdomains from something like `subfinder`, and then also endpoints from something like `dirb` or `dirbuster` for CL.TE and TE.CL vectors, and indicate whether or not the basic conditions of the vuln exist.

Eventually it will support all known DeSync techniques, but for now it handles Client side Desync, and connection-locked TE.CL (server-side) and CL.TE vectors are under development.

# Capability
Synch0le will take a URL, or a file with a list of URLS, and probe each of them to determine:

- If the server supports HTTP/2
- If the server validates `Content-Length` on an incoming POST request to an unexpected endpoint (`/favicon.ico`)
- If a successful client-side De-Sync can be achieved by sending two requests across the same connection
- (in development) If the server appears vulnerable to connection-locked CL.TE DeSync based on a timeout condition from a CL.TE payload, with successful desync
- (in development) If the server appears vulnerable to connection-locked TE.CL DeSync based on a timeout condition from a TE.CL payload, with successful desync


It does not currently have any false positives (that I have seen), but it may have false negatives.
I say "appears" vulnerable to CL.TE and TE.CL because confirming these DeSync conditions can take on the order of 1k requests on higher traffic servers, so synch0le only runs the initial timing-based tests for those vectors.

# Installation & Usage

`pip install -r requirements.txt`

To use it one-shot: `python synch0le.py -o target.com`

To use it on a list of files: `python synch0le.py -t targets.txt`

# Collaboration

Is more than welcome. 
