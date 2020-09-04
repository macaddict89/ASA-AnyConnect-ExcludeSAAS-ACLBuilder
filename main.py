import urllib.request
import uuid
import json
import re


def print_acl_lines(acl_name, ips, section_comment):
    slash_to_mask = (
        "0.0.0.0",
        "128.0.0.0",
        "192.0.0.0",
        "224.0.0.0",
        "240.0.0.0",
        "248.0.0.0",
        "252.0.0.0",
        "254.0.0.0",
        "255.0.0.0",
        "255.128.0.0",
        "255.192.0.0",
        "255.224.0.0",
        "255.240.0.0",
        "255.248.0.0",
        "255.252.0.0",
        "255.254.0.0",
        "255.255.0.0",
        "255.255.128.0",
        "255.255.192.0",
        "255.255.224.0",
        "255.255.240.0",
        "255.255.248.0",
        "255.255.252.0",
        "255.255.254.0",
        "255.255.255.0",
        "255.255.255.128",
        "255.255.255.192",
        "255.255.255.224",
        "255.255.255.240",
        "255.255.255.248",
        "255.255.255.252",
        "255.255.255.254",
        "255.255.255.255",
    )
    print(
        "access-list {acl_name} remark {comment}".format(
            acl_name=acl_name, comment=section_comment
        )
    )
    for ip in sorted(ips):
        if ":" in ip:
            # IPv6 address
            print(
                "access-list {acl_name} extended permit ip {ip} any6".format(
                    acl_name=acl_name, ip=ip
                )
            )
        else:
            # IPv4 address.  Convert to a mask
            addr, slash = ip.split("/")
            slash_mask = slash_to_mask[int(slash)]
            print(
                "access-list {acl_name} extended permit ip {addr} {mask} any4".format(
                    acl_name=acl_name, addr=addr, mask=slash_mask
                )
            )


# Fetch the current endpoints for O365
http_res = urllib.request.urlopen(
    url="https://endpoints.office.com/endpoints/worldwide?clientrequestid={}".format(
        uuid.uuid4()
    )
)
res = json.loads(http_res.read())
o365_ips = set()
o365_fqdns = set()
for service in res:
    if service["category"] == "Optimize":
        for ip in service.get("ips", []):
            o365_ips.add(ip)
        for fqdn in service.get("urls", []):
            o365_fqdns.add(fqdn)

# Generate an acl for split excluding For instance
print("##### Step 1: Create an access-list to include the split-exclude networks\n")
acl_name = "ExcludeSass"
# O365 networks
print_acl_lines(
    acl_name=acl_name,
    ips=o365_ips,
    section_comment="v4 and v6 networks for Microsoft Office 365",
)
# Microsoft Teams
# https://docs.microsoft.com/en-us/office365/enterprise/office-365-vpn-implement-split-tunnel#configuring-and-securing-teams-media-traffic
print_acl_lines(
  acl_name=acl_name,
  ips=["13.107.60.1/32"],
  section_comment="v4 address for Microsoft Teams"
)
# Cisco Webex - Per https://help.webex.com/en-us/WBX000028782/Network-Requirements-for-Webex-Teams-Services
webex_ips = [
    "64.68.96.0/19",
    "66.114.160.0/20",
    "66.163.32.0/19",
    "170.133.128.0/18",
    "173.39.224.0/19",
    "173.243.0.0/20",
    "207.182.160.0/19",
    "209.197.192.0/19",
    "216.151.128.0/19",
    "114.29.192.0/19",
    "210.4.192.0/20",
    "69.26.176.0/20",
    "62.109.192.0/18",
    "69.26.160.0/19",
]
print_acl_lines(
    acl_name=acl_name,
    ips=webex_ips,
    section_comment="IPv4 and IPv6 destinations for Cisco Webex",
)
#RingCentral Office - Per https://support.ringcentral.com/s/article/9233?language=en_US#6.Supernets
ringcentral_ips = [
    "66.81.240.0/20",
    "80.81.128.0/20",
    "103.44.68.0/22",
    "104.245.56.0/21",
    "185.23.248.0/22",
    "192.209.24.0/21",
    "199.68.212.0/22",
    "199.255.120.0/22",
    "208.87.40.0/22",
]
print_acl_lines(
    acl_name=acl_name,
    ips=ringcentral_ips,
    section_comment="IPv4 and IPv6 destinations for RingCentral Office",
)
#Zoom Meetings - Per https://support.zoom.us/hc/en-us/articles/201362683-Network-firewall-or-proxy-server-settings-for-Zoom
zoom_ips = [
    "3.7.35.0/25",
    "3.21.137.128/25",
    "3.22.11.0/24",
    "3.23.93.0/24",
    "3.25.41.128/25",
    "3.25.42.0/25",
    "3.25.49.0/24",
    "3.80.20.128/25",
    "3.96.19.0/24",
    "3.101.32.128/25",
    "3.101.52.0/25",
    "3.104.34.128/25",
    "3.127.194.128/25",
    "3.208.72.0/25",
    "3.211.241.0/25",
    "3.235.69.0/25",
    "3.235.82.0/23",
    "3.235.71.128/25",
    "3.235.72.128/25",
    "3.235.73.0/25",
    "3.235.96.0/23",
    "3.235.96.97/32",
    "3.235.96.96/32",
    "3.235.96.95/32",
    "3.235.96.94/32",
    "4.34.125.128/25",
    "4.35.64.128/25",
    "8.5.128.0/23",
    "13.52.6.128/25",
    "13.52.146.0/25",
    "13.114.106.166/32",
    "18.157.88.0/24",
    "18.205.93.128/25",
    "50.239.202.0/23",
    "50.239.204.0/24",
    "52.61.100.128/25",
    "52.81.151.128/25",
    "52.81.215.0/24",
    "52.197.97.21/32",
    "52.202.62.192/26",
    "52.215.168.0/25",
    "64.69.74.0/24",
    "64.125.62.0/24",
    "64.211.144.0/24",
    "65.39.152.0/24",
    "69.174.57.0/24",
    "69.174.108.0/22",
    "99.79.20.0/25",
    "103.122.166.0/23",
    "109.94.160.0/22",
    "109.244.18.0/25",
    "109.244.19.0/24",
    "111.33.181.0/25",
    "115.110.154.192/26",
    "115.114.56.192/26",
    "115.114.115.0/26",
    "115.114.131.0/26",
    "120.29.148.0/24",
    "140.238.128.0/24",
    "147.124.96.0/19",
    "149.137.0.0/17",
    "152.67.20.0/24",
    "152.67.118.0/24",
    "152.67.180.0/24",
    "158.101.64.0/24",
    "160.1.56.128/25",
    "161.189.199.0/25",
    "161.199.136.0/22",
    "162.12.232.0/22",
    "162.255.36.0/22",
    "165.254.88.0/23",
    "168.138.16.0/24",
    "168.138.48.0/24",
    "168.138.72.0/24",
    "168.138.244.0/24",
    "173.231.80.0/20",
    "192.204.12.0/22",
    "193.122.32.0/22",
    "193.123.0.0/19",
    "193.123.40.0/22",
    "193.123.128.0/19",
    "198.251.128.0/17",
    "198.251.192.0/22",
    "202.177.207.128/27",
    "202.177.213.96/27",
    "204.80.104.0/21",
    "204.141.28.0/22",
    "207.226.132.0/24",
    "209.9.211.0/24",
    "209.9.215.0/24",
    "210.57.55.0/24",
    "213.19.144.0/24",
    "213.19.153.0/24",
    "213.244.140.0/24",
    "221.122.88.64/27",
    "221.122.88.128/25",
    "221.122.89.128/25",
    "221.123.139.192/27",
    "2620:123:2000::/40",
]
print_acl_lines(
    acl_name=acl_name,
    ips=zoom_ips,
    section_comment="IPv4 and IPv6 destinations for Zoom Meetings",
)
print("\n##### Step 2: Configure the split exclude in the group-policy\n")
print(
    """
group-policy GP1 attributes
 split-tunnel-policy excludespecified
 ipv6-split-tunnel-policy excludespecified
 split-tunnel-network-list value {acl_name}
""".format(
        acl_name=acl_name
    )
)
