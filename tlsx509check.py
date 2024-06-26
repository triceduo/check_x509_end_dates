import subprocess
import os
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


def check_host(hostname, cipherinfo=None, min_tls_version=1.2, tls_versions=None,
               target_security_type='unacceptable', ciphersuitelist=None):
    report={}
    if cipherinfo is None:
        cipherinfo = cipher_suites_by_tls_version_security()

    if tls_versions is None:
        #check 'em all
        tls_versions = sorted([float(w.replace('TLS', '')) for w in cipherinfo.keys()])

    for tls_version in tls_versions:
        if tls_version < min_tls_version:
            supported = check_tls_response(hostname, 443, tls_version)
            if supported:
                report[f"TLS{tls_version}"] = f'support for TLS version {tls_version} should be disabled'
        else:
            for security_type in cipherinfo[f"TLS{tls_version}"]:
                if security_type is None or security_type == target_security_type:
                    for cipher_suite in cipherinfo[f"TLS{tls_version}"][security_type]:
                        if ciphersuitelist is None or cipher_suite in ciphersuitelist:
                            data =  cipherinfo[f"TLS{tls_version}"][security_type][cipher_suite]
                            supported = check_tls_response(hostname, 443, tls_version, cipher_suite=cipher_suite)
                            if supported:
                                if f"TLS{tls_version}" not in report:
                                    report[f"TLS{tls_version}"] = []
                                report[ f"TLS{tls_version}"].append(f"{data['security']} cipher suite {cipher_suite}")
    return report


def check_tls_response(host, port, tls_version, cipher_suite=None):
    tls_version_str = str(tls_version).replace(".", "_").replace('1_0', '1')
    command = ['openssl', 's_client', '-connect', f'{host}:{port}', f"-tls{tls_version_str}"]
    if cipher_suite is not None:
        command+=['-cipher', cipher_suite]
    result = subprocess.run(command, capture_output=True, text=True)
    return result.returncode == 0

# # Example usage
# host = 'duo.com'
# port = 443
# tls_version = '1.2'
# cipher_suite = 'AES256-SHA'
#
# check_tls_support(host, port, tls_version, cipher_suite)
