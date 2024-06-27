#!/usr/bin/env python3
from tqdm import tqdm
import os.path
import subprocess
import argparse
import os, sys
import pickle
import time
import urllib.request
import json


def fetch_json_from_url(url: str) -> dict:
    """
    Fetches JSON data from a given URL and caches it locally.

    Args:
        url (str): The URL to fetch the JSON data from.

    Returns:
        dict: The JSON data fetched from the URL.

    """
    CACHE_FILE = '.json_cache.pkl'
    CACHE_EXPIRATION_TIME = 86400  # 1 day in seconds

    # Check if the cache file exists and is not expired
    if os.path.exists(CACHE_FILE) and time.time() - os.path.getmtime(CACHE_FILE) < CACHE_EXPIRATION_TIME:
        # If the cache file is not expired, load the data from the cache file
        with open(CACHE_FILE, 'rb') as cache_file:
            return pickle.load(cache_file)

    # If the cache file is expired or does not exist, fetch the data from the URL
    with urllib.request.urlopen(url) as response:
        data = response.read().decode()
        json_data = json.loads(data)

    # Cache the fetched data locally
    with open(CACHE_FILE, 'wb') as cache_file:
        pickle.dump(json_data, cache_file)

    return json_data


def cipher_suites_by_tls_version_security():
    """
    Check the support of various TLS versions and cipher suites for a given host.

    Args:
        hostname (str): The hostname of the server to check.
        cipherinfo (dict, optional): A dictionary containing information about the supported cipher suites for each TLS version.
            If not provided, the function will fetch the information from the cipher_suites_by_tls_version_security() function.
        min_tls_version (float, optional): The minimum TLS version to check. Defaults to 1.2.
        tls_versions (list, optional): A list of TLS versions to check. If not provided, the function will check all available TLS versions.
        target_security_type (str, optional): The target security type to check. Defaults to 'unacceptable' (i.e. weak or insecure cipher suites).
        ciphersuitelist (list, optional): A list of cipher suites to check. If not provided, all cipher suites will be checked.

    Returns:
        dict: A dictionary containing the results of the check. The keys are the TLS versions and the values are lists of problem cipher suites
    """
    ciphersuites = fetch_json_from_url('https://ciphersuite.info/api/cs')
    tls_versions = {}
    for row in ciphersuites['ciphersuites']:
        for name, cipherinfo in row.items():
            for tls_version in cipherinfo['tls_version']:
                if tls_version not in tls_versions:
                    tls_versions[tls_version] = {'unacceptable': {}, 'acceptable': {}}
                if cipherinfo['security'] in ['recommended', 'secure']:
                    security_type = 'acceptable'
                else:
                    security_type = 'unacceptable'
                tls_versions[tls_version][security_type][name] = cipherinfo
    return tls_versions


def check_host(hostname, cipherinfo=None, min_tls_version=1.2, tls_versions=None, progress=False,
               target_security_type='unacceptable', ciphersuitelist=None):
    """
    Check the host for various TLS versions and cipher suites.

    Args:
        hostname (str): The hostname of the server to check.
        cipherinfo (dict, optional): A dictionary containing information about the supported cipher suites for each TLS version. If not provided, the function will fetch the information from the cipher_suites_by_tls_version_security() function.
        min_tls_version (float, optional): The minimum TLS version to check. Defaults to 1.2.
        tls_versions (list, optional): A list of TLS versions to check. If not provided, the function will check all available TLS versions.
        target_security_type (str, optional): The target security type to check. Defaults to 'unacceptable' (i.e. weak or insecure cipher suites).
        ciphersuitelist (list, optional): A list of cipher suites to check. If not provided, all cipher suites will be checked.

    Returns:
        dict: A dictionary containing the results of the check. The keys are the TLS versions and the values are lists of problem cipher suites
    """
    report = {}
    if cipherinfo is None:
        cipherinfo = cipher_suites_by_tls_version_security()

    if ciphersuitelist is not None and type(ciphersuitelist) is str:
        ciphersuitelist = [line.strip() for line in ciphersuitelist.split(',')]

    if tls_versions is None:
        # check 'em all
        tls_versions = sorted([float(w.replace('TLS', '')) for w in cipherinfo.keys()])

    if progress:
        pbartlsversion = tqdm(total=len(tls_versions), desc=f"{hostname} {'TLS versions':20}", bar_format='{l_bar}{bar:10}{r_bar}{bar:-10b}')
    for tls_version in tls_versions:
        if tls_version < min_tls_version:
            supported = check_tls_response(hostname, 443, tls_version)
            if supported:
                report[f"TLS{tls_version}"] = {
                    'unacceptable': [f'support for TLS version {tls_version} should be disabled']}
            else:
                report[f"TLS{tls_version}"] = {
                    'acceptable': [f'support for TLS version {tls_version} is correctly disabled']}
            if progress:
                pbartlsversion.update(1)
        else:
            for security_type in cipherinfo[f"TLS{tls_version}"]:
                if target_security_type is None or security_type == target_security_type:
                    cipherstocheck = set(cipherinfo[f"TLS{tls_version}"][security_type].keys())
                    if ciphersuitelist is not None:
                        cipherstocheck = cipherstocheck.intersection(set(ciphersuitelist))
                        ciphersnotinthissecuritytype = set(ciphersuitelist).difference(cipherstocheck)
                        # if len(ciphersnotinthissecuritytype) > 0:
                        #     print(
                        #         f"WARNING: cipher suite(s) {ciphersnotinthissecuritytype} not in security type {security_type} for TLS version {tls_version}")
                    if f"TLS{tls_version}" not in report:
                        report[f"TLS{tls_version}"] = {}
                    if security_type not in report[f"TLS{tls_version}"]:
                        report[f"TLS{tls_version}"][security_type] = []

                    if len(cipherstocheck) > 0:
                        if progress:
                            if ciphersuitelist is None:
                                ciphercnt = len(cipherinfo[f"TLS{tls_version}"][security_type])
                            else:
                                ciphercnt = len(ciphersuitelist)
                            pbarciphers = tqdm(total=ciphercnt,
                                        desc=f"{hostname} TLS{tls_version} cipher suites",
                                        bar_format='{l_bar}{bar:10}{r_bar}{bar:-10b}')
                        for cipher_suite in cipherstocheck:
                            if progress:
                                pbarciphers.update(1)
                            if ciphersuitelist is None or cipher_suite in ciphersuitelist:
                                data = cipherinfo[f"TLS{tls_version}"][security_type][cipher_suite]
                                supported = check_tls_response(hostname, 443, tls_version, cipher_suite=cipher_suite)
                                report[f"TLS{tls_version}"][security_type].append(
                                    f"{data['security']} cipher suite {cipher_suite} {'is' if supported else 'is not'} supported")
                        pbarciphers.close()
            if progress:
                pbartlsversion.update(1)

    pbartlsversion.close()
    return report


def check_tls_response(host, port, tls_version, cipher_suite=None):
    """
    Check the TLS response of a host by connecting to it using openssl s_client.

    Parameters:
    - host (str): The host to connect to.
    - port (int): The port to connect to on the host.
    - tls_version (float): The TLS version to use for the connection.
    - cipher_suite (str, optional): The cipher suite to use for the connection. Defaults to None.

    Returns:
    - bool: True if the TLS response is successful, i.e. that TLS version or TLS version and ciphersuite is supported) by the host, False otherwise.
    """
    tls_version_str = str(tls_version).replace(".", "_").replace('1_0', '1')
    command = ['openssl', 's_client', '-connect', f'{host}:{port}', f"-tls{tls_version_str}"]
    if cipher_suite is not None:
        command += ['-cipher', cipher_suite]
    result = subprocess.run(command, capture_output=True, text=True)
    return result.returncode == 0


def build_hostlist(hostnamestring):
    """
    Builds a list of hostnames from either a file or a single hostname.

    Args:
        hostnamestring (str): The file path or single hostname.

    Returns:
        list: A list of hostnames.

    """
    if os.path.isfile(hostnamestring):
        with open(hostnamestring, 'r') as file:
            lines = file.readlines()
        hostnames = [line.strip() for line in lines]
    else:
        hostnames = [hostnamestring.strip()]
    return hostnames


def create_parser(arglist):
    parser = argparse.ArgumentParser(
        prog='TLS Check',
        description='Checks TLS posture for given host or list of hosts. Primarily intended for port 443 but may be used for other ports', )
    parser.add_argument('-m', '--min_tls_version', type=float, default=1.2, help='Minimum TLS version to check')
    parser.add_argument('-c', '--csv', type=str, help='output report in CSV format to specified file')
    parser.add_argument('-u', '--unacceptable', action='store_true', default=True,
                        help='port on weak or insecure cipher suites')
    parser.add_argument('-VV', '--reallyverbose', action='store_true', default=False, help='output report to console')
    parser.add_argument('-V', '--verbose', action='store_true', default=False, help='additional output to console')
    parser.add_argument('-l', '--ciphersuitelist', type=str, default=None, help='List of cipher suites to check')
    parser.add_argument('-v', '--tls_versions', type=str, default="1.0,1.1,1.2",
                        help='comma separated string of TLS versions to check')
    parser.add_argument('hostname', type=str,
                        help='comma separated list of hosts (or IP addresses) or filename with list of hosts (one per line)')
    parser.add_argument('-p', '--port', type=int, default=443, help='port to check (default 4430)')
    args = parser.parse_args(arglist)
    if args.unacceptable:
        args.target_security_type = 'unacceptable'
    else:
        args.target_security_type = None
    if type(args.tls_versions) == str:
        args.tls_version_list = [float(x) for x in args.tls_versions.split(',')]
    args.hostnames = build_hostlist(args.hostname)
    return args


def main(arglist):
    args = create_parser(arglist)
    if args.unacceptable:
        args.target_security_type = 'unacceptable'
    else:
        args.target_security_type = None
    hostlist = ", ".join(args.hostnames)
    print(f'checking {hostlist} on port {args.port} with TLS versions {args.tls_version_list}')

    if args.verbose:
        pbar = tqdm(total=len(args.hostnames), desc=f"{'hosts':20}", bar_format='{l_bar}{bar:10}{r_bar}{bar:-10b}')

    final_report = {}
    for hostname in args.hostnames:
        report = check_host(hostname, progress=args.verbose,
                            min_tls_version=args.min_tls_version, tls_versions=args.tls_version_list,
                            target_security_type=args.target_security_type, ciphersuitelist=args.ciphersuitelist)
        if args.verbose:
            pbar.update(1)

    if args.reallyverbose:
        for tlsver, rows in report.items():
            print(f"\n{tlsver}")
            for row in rows:
                print(f"  {row}")


if __name__ == '__main__':
    main(sys.argv[1:])
