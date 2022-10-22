# Synch0le

This tool is for exploring HTTP De-Sync attacks using the CL.0 methods detailed by [James Kettle](https://skeletonscribe.net/) in his [research](https://i.blackhat.com/USA-22/Wednesday/us-22-Kettle-Browser-Powered-Desync-Attacks-wp.pdf) "Browser-Powered Desync Attacks: A New Frontier in
HTTP Request Smuggling" published at Defcon and Blackhat. 

Full blog [post](https://sharpsec.run/?p=127).

# Capability
Synch0le will take a URL, or a file with a list of URLS, and probe each of them to determine:

- If the server supports HTTP/2
- If the server validates `Content-Length` on an incoming POST request to an unexpected endpoint (`favicon.ico`)
- If a successful De-Sync can be achieved by sending two requests across the same connection

It does not currently have any false positives (that I have seen), but it may have false negatives.

# Installation & Usage

`pip install -r requirements.txt`

To use it one-shot: `python synch0le.py -o target.com`

To use it on a list of files: `python synch0le.py -t targets.txt`

# Collaboration

Is more than welcome. 