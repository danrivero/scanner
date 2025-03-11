import sys
import json
import texttable

input = sys.argv[1]
output = sys.argv[2]

with open(input, "r") as f:
    data_dict = json.load(f)

table = texttable.Texttable()
table.set_cols_width([20, 10, 20, 41, 20, 8, 8, 8, 20, 20, 20, 20, 20])
table.add_row(["Site", "Scan Time", "IPv4s", "IPv6s", "HTTP Server", "Insecure HTTP", "HTTPS Redirect", "HSTS", "TLS Versions", "Root CA", "RDNS Names", "RTT Range", "Geo Locs"])
for key in data_dict:
    row = [key,
           data_dict[key]["scan_time"],
           data_dict[key]["ipv4_addresses"],
           data_dict[key]["ipv6_addresses"],
           data_dict[key]["http_server"],
           data_dict[key]["insecure_http"],
           data_dict[key]["redirect_to_https"],
           data_dict[key]["hsts"],
           data_dict[key]["tls_versions"],
           data_dict[key]["root_ca"],
           data_dict[key]["rdns_names"],
           data_dict[key]["rtt_range"],
           data_dict[key]["geo_locations"]]
    table.add_row(row)

with open(output, "w") as g:
    g.write(table.draw() + "\n\n")

table = texttable.Texttable()
rtts = []
for key in data_dict:
    rtts.append((key, data_dict[key]["rtt_range"]))
sorted_rtts = sorted(rtts, key=lambda x: (float('inf') if x[1] is None else x[1][0]))

table.add_row(["Domain", "RTT Range"])
for item in sorted_rtts:
    row = [item[0], item[1]]
    table.add_row(row)

with open(output, "a") as g:
    g.write(table.draw() + "\n\n")

table = texttable.Texttable()
certificates = {}
for key in data_dict:
    certificate = data_dict[key]["root_ca"]
    if certificate is not None:
        if certificate not in certificates:
            certificates[certificate] = 1
        else:
            certificates[certificate] += 1
certs = []
for key in certificates:
    certs.append((key, certificates[key]))
sorted_certs = sorted(certs, key=lambda x: -x[1])

table.add_row(["Certificate Authority", "#"])
for item in sorted_certs:
    row = [item[0], item[1]]
    table.add_row(row)

with open(output, "a") as g:
    g.write(table.draw() + "\n\n")

table = texttable.Texttable()
web_servers = {}
for key in data_dict:
    web_server = data_dict[key]["http_server"]
    if web_server is not None:
        if web_server not in web_servers:
            web_servers[web_server] = 1
        else:
            web_servers[web_server] += 1
servs = []
for key in web_servers:
    servs.append((key, web_servers[key]))
sorted_servs = sorted(servs, key=lambda x: -x[1])

table.add_row(["Web Server", "#"])
for item in sorted_servs:
    row = [item[0], item[1]]
    table.add_row(row)

with open(output, "a") as g:
    g.write(table.draw() + "\n\n")

total = len(data_dict)
sslv2_count = 0
sslv3_count = 0
tlsv10_count = 0
tlsv11_count = 0
tlsv12_count = 0
tlsv13_count = 0
http_count = 0
redirect_count = 0
hsts_count = 0
ipv6_count = 0

for key in data_dict:
    domain = data_dict[key]
    if domain["insecure_http"]:
        http_count += 1
    if domain["redirect_to_https"]:
        redirect_count += 1
    if domain["hsts"]:
        hsts_count += 1
    if len(domain["ipv6_addresses"]) == 0:
        ipv6_count += 1
    if "SSLv2" in domain["tls_versions"]:
        sslv2_count += 1
    if "SSLv3" in domain["tls_versions"]:
        sslv3_count += 1
    if "TLSv1.0" in domain["tls_versions"]:
        tlsv10_count += 1
    if "TLSv1.1" in domain["tls_versions"]:
        tlsv11_count += 1
    if "TLSv1.2" in domain["tls_versions"]:
        tlsv12_count += 1
    if "TLSv1.3" in domain["tls_versions"]:
        tlsv13_count += 1

sslv2_percent = (sslv2_count / total) * 100
sslv3_percent = (sslv3_count / total) * 100
tlsv10_percent = (tlsv10_count / total) * 100
tlsv11_percent = (tlsv11_count / total) * 100
tlsv12_percent = (tlsv12_count / total) * 100
tlsv13_percent = (tlsv13_count / total) * 100
http_percent = (http_count / total) * 100
redirect_percent = (redirect_count / total) * 100
hsts_percent = (hsts_count / total) * 100
ipv6_percent = (ipv6_count / total) * 100

table = texttable.Texttable()

table.add_rows([["Domain Support", "Percentage"],
                ["SSLv2", f"{sslv2_percent}%"],
                ["SSLv3", f"{sslv3_percent}%"],
                ["TLSv1.0", f"{tlsv10_percent}%"],
                ["TLSv1.1", f"{tlsv11_percent}%"],
                ["TLSv1.2", f"{tlsv12_percent}%"],
                ["TLSv1.3", f"{tlsv13_percent}%"],
                ["Plain HTTP", f"{http_percent}%"],
                ["HTTPS Redirect", f"{redirect_percent}%"],
                ["HSTS", f"{hsts_percent}%"],
                ["IPv6", f"{ipv6_percent}%"]
                ])

with open(output, "a") as g:
    g.write(table.draw() + "\n\n")

TLS_VERSIONS = {
    "SSLv2": "-ssl2",
    "SSLv3": "-ssl3",
    "TLSv1.0": "-tls1",
    "TLSv1.1": "-tls1_1",
    "TLSv1.2": "-tls1_2",
    "TLSv1.3": "-tls1_3"
}

#A table showing the number of occurrences for each observed root certificate authority (from Part 2i), sorted from most popular to least.
#A table showing the number of occurrences of each web server (from Part 2d), ordered from most popular to least.
#A table showing the percentage of scanned domains supporting:
#each version of TLS listed in Part 2h. I expect to see close to zero percent for SSLv2 and SSLv3.
        #"plain http" (Part 2e)
        #"https redirect" (Part 2f)
        #"hsts" (Part 2g)
        #"ipv6" (from Part 2c)