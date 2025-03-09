import subprocess
import sys
import json
import time

input = sys.argv[1]
output = sys.argv[2]
print(input)
print(output)

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
        insecure_http = True
        redirect_to_https = False

        if insecure_http:
            result = subprocess.check_output(["curl", "-I", site], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            redirects = 0

            while "HTTP" in result and redirects < 10:
                index = result.find("HTTP")
                start_index = result.find(" ", index) + 1
                end_index = result.find(" ", start_index)
                response_code = result[start_index:end_index]
                print(response_code)
                if not response_code.startswith("3"):
                    break

                redirect_index = result.lower().find("location:") + 10
                end_redirect_index = result.find("\n", redirect_index)
                redirect = result[redirect_index:end_redirect_index]
                print(redirect)

                if redirect.startswith("https"):
                    redirect_to_https = True
                    break
                result = subprocess.check_output(["curl", "-I", redirect], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
                redirects += 1

    except subprocess.CalledProcessError:
        sys.stderr.write(f"Error getting redirect for {site}\n")

    except Exception as e:
        sys.stderr.write(f"Error getting redirect for {site}: {e}\n")

    return insecure_http, redirect_to_https

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
            #site_dictionary["ipv4_addresses"] = get_ip_addresses(site, resolvers, "A")
            #site_dictionary["ipv6_addresses"] = get_ip_addresses(site, resolvers, "AAAA")
            site_dictionary["http_server"] = get_http_server(site)
            insecure_http, redirect_to_https = get_http_redirects(site)
            site_dictionary["insecure_http"] = insecure_http
            site_dictionary["redirect_to_https"] = redirect_to_https
            json_dictionary[site] = site_dictionary

with open(output, "w") as g:
    json.dump(json_dictionary, g, sort_keys=True, indent=4)