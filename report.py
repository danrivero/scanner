import sys
import json
import texttable

input = sys.argv[1]
output = sys.argv[2]

with open(input, "r") as f:
    data_dict = json.load(f)

table = texttable.Texttable()
table.set_cols_width([20, 10, 20, 40, 20, 8, 8, 8, 20, 20, 20, 20, 20])
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
    g.write(table.draw())