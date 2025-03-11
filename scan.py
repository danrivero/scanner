import subprocess
import sys
import json
import time
import socket
import maxminddb
import os

input = sys.argv[1]
output = sys.argv[2]
print(input)
print(output)

TLS_VERSIONS = {
    "SSLv2": "-ssl2",
    "SSLv3": "-ssl3",
    "TLSv1.0": "-tls1",
    "TLSv1.1": "-tls1_1",
    "TLSv1.2": "-tls1_2",
    "TLSv1.3": "-tls1_3"
}

def get_ip_addresses(site, resolvers, record_type):
    ip_addresses = set()

    for resolver in resolvers:
        try:
            result = subprocess.check_output(["nslookup", "-type=" + record_type, site, resolver], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            index = result.find("Name:")
            addresses = result[index:]
            output = addresses.splitlines()
            output = output[1:]

            for line in output:
                line = line.strip()
                ip = line
                if "Address:" in line or "Addresses:" in line:
                    ip = line.split(":")[-1].strip()
                if record_type == "A" and "." in ip and "Aliases" not in ip:
                    ip_addresses.add(ip)
                if record_type == "AAAA" and ":" in ip and "Aliases" not in ip:
                    ip_addresses.add(ip)
                    
        except subprocess.TimeoutExpired:
            sys.stderr.write(f"Timeout querying {site} with resolver {resolver}\n")

        except Exception as e:
            sys.stderr.write(f"Error querying {site} with resolver {resolver}: {e}\n")
        
    return list(ip_addresses)

def get_http_server(site):
    try:
        result = subprocess.check_output(["curl", "-v", site], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
        index = result.find("Server:")
        newline_index = result.find("\r", index)
        line = result[index:newline_index]
        if line[8:] == "":
            return None
        return line[8:]
    except Exception as e:
        sys.stderr.write(f"Error getting http server for {site}: {e}\n")

def get_http_redirects(site):
    try:
        insecure_http = False
        redirect_to_https = False

        with socket.create_connection((site, 80), timeout=2):
            insecure_http = True
        
        if insecure_http:
            redirects = 0
            new_site = site
            while redirects < 10:
                result = subprocess.check_output(["curl", "-I", new_site], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
                index = result.find("HTTP")
                start_index = result.find(" ", index) + 1
                end_index = result.find(" ", start_index)
                response_code = int(result[start_index:end_index])
                
                if response_code // 100 != 3:
                    break
                redirect_index = result.lower().find("location:") + 10
                end_redirect_index = result.find("\n", redirect_index)
                new_site = result[redirect_index:end_redirect_index]

                if new_site.startswith("https"):
                    redirect_to_https = True
                    break
                
                redirects += 1

    except subprocess.CalledProcessError:
        sys.stderr.write(f"Error getting redirect for {site}\n")

    except Exception as e:
        sys.stderr.write(f"Error getting redirect for {site}: {e}\n")

    except (socket.timeout, ConnectionRefusedError):
        pass

    return insecure_http, redirect_to_https

def check_hsts(site):
    try:
        result = subprocess.check_output(
        ["curl", "-s", "-D", "-", f"https://{site}"],
        text=True
        )
        response_headers = result.lower()
        return "strict-transport-security:" in response_headers

    except subprocess.TimeoutExpired:
        sys.stderr.write(f"Timeout checking HSTS for {site}\n")

    except Exception as e:
        sys.stderr.write(f"Error checking HSTS for {site}: {e}\n")

    return False
    
def get_tls_versions(site):
    supported_versions = []

    for version, flag in TLS_VERSIONS.items():
        try:
            subprocess.check_output(["openssl", "s_client", flag, "-connect", f"{site}:443"], input=b"", timeout=5, stderr=subprocess.DEVNULL).decode('utf-8')
            supported_versions.append(version)

        except subprocess.TimeoutExpired:
            sys.stderr.write(f"Timeout checking TLS version {version} for {site}\n")

        except subprocess.CalledProcessError:
            sys.stderr.write(f"Error checking TLS version {version} for {site}\n")

        except Exception as e:
            sys.stderr.write(f"Unexpected error checking TLS version {version} for {site}: {e}\n")

    return supported_versions

def get_root_ca(site):
    try:
        command = f"echo | openssl s_client -connect {site}:443 -showcerts"
        result = subprocess.check_output(command, shell=True, input = b"", timeout=10, stderr=subprocess.STDOUT).decode('utf-8')
        index = result.find("O=")+2
        end_index = result.find(",", index)
        return result[index:end_index]

    except subprocess.TimeoutExpired:
        sys.stderr.write(f"Timeout checking Root CA for {site}\n")

    except subprocess.CalledProcessError:
        sys.stderr.write(f"Error checking Root CA for {site}\n")

    except Exception as e:
        sys.stderr.write(f"Unexpected error checking Root CA for {site}: {e}\n")
    
    return None

def get_rdns_names(ip_addresses):
    rdns_names = set()
    for ip in ip_addresses:
        try:
            result = subprocess.check_output(["nslookup", ip], timeout=3, stderr=subprocess.DEVNULL).decode('utf-8')
            lines = result.splitlines()
            for line in lines:
                if "Name:" in line:
                    rdns_name = line.split(":")[-1].strip()
                    rdns_names.add(rdns_name)

        except subprocess.TimeoutExpired:
            sys.stderr.write(f"Timeout checking rDNS for {ip}\n")

        except subprocess.CalledProcessError:
            sys.stderr.write(f"Error checking rDNS for {ip}\n")

        except Exception as e:
            sys.stderr.write(f"Unexpected error checking rDNS for {ip}: {e}\n")

        return sorted(rdns_names)

def get_rtt_range(ip_addresses):
    if not ip_addresses:
        return None
    
    rtt_times = []

    for ip in ip_addresses:
        for port in [80, 22, 443]:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(10)
                    start_time = time.time()
                
                    s.connect((ip, port))
                    s.sendto(b"hi", (ip, port))
                    _, _ = s.recvfrom(1024)
                
                    end_time = time.time()
                
                    rtt_ms = (end_time - start_time) * 1000
                    rtt_times.append(rtt_ms)

            except Exception as e:
                    sys.stderr.write(f"Timeout or error checking RTT for {ip}:{e}\n")

    return [round(min(rtt_times), 2), round(max(rtt_times), 2)] if rtt_times else None

def get_geo_locations(ip_addresses):
    if not ip_addresses:
        return []

    unique_locations = set()

    try:
        db_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "GeoLite2-City.mmdb")
        with maxminddb.open_database(db_path) as reader:
            for ip in ip_addresses:
                try:
                    geo_data = reader.get(ip)
                    if not geo_data:
                        continue

                    city = geo_data.get("city", {}).get("names", {}).get("en", "")
                    state = geo_data.get("subdivisions", [{}])[0].get("names", {}).get("en", "")
                    country = geo_data.get("country", {}).get("names", {}).get("en", "")

                    location = ", ".join(filter(None, [city, state, country]))
                    if location:
                        unique_locations.add(location)

                except Exception as e:
                    sys.stderr.write(f"Error fetching geo-location for {ip}: {e}\n")

    except FileNotFoundError:
        sys.stderr.write(f"Error trying to find {db_path}: {e}")

    return list(unique_locations)

resolvers_file = "public_dns_resolvers.txt"
with open(resolvers_file, "r") as f:
    resolvers = [line.strip() for line in f if line.strip()]

json_dictionary = {}
with open(input, "r") as f:
    for line in f:
        site = line.strip()
        if site:
            site_dictionary = {}

            site_dictionary["scan_time"] = time.time()
            site_dictionary["ipv4_addresses"] = get_ip_addresses(site, resolvers, "A")
            site_dictionary["ipv6_addresses"] = get_ip_addresses(site, resolvers, "AAAA")
            site_dictionary["http_server"] = get_http_server(site)

            insecure_http, redirect_to_https = get_http_redirects(site)
            site_dictionary["insecure_http"] = insecure_http
            site_dictionary["redirect_to_https"] = redirect_to_https
            site_dictionary["hsts"] = check_hsts(site)
            site_dictionary["tls_versions"] = get_tls_versions(site)
            site_dictionary["root_ca"] = get_root_ca(site)
            site_dictionary["rdns_names"] = get_rdns_names(site_dictionary["ipv4_addresses"])
            site_dictionary["rtt_range"] = get_rtt_range(site_dictionary["ipv4_addresses"])
            site_dictionary["geo_locations"] = get_geo_locations(site_dictionary["ipv4_addresses"])
            
            json_dictionary[site] = site_dictionary

with open(output, "w") as g:
    json.dump(json_dictionary, g, sort_keys=True, indent=4)