def get_host_location(host_ip):
    for key in access_table.keys():
        if access_table[key][0] == host_ip:
            return key

access_table = {
    (1, 1) : ['10.0.0.1'],
    (1, 2) : ['10.0.0.2'],
    (5, 1) : ['10.0.0.3']
}
user_ip = '10.0.0.1'

# access_key : (dpid, port_num)
access_key = get_host_location(user_ip)

for key, ip_list in access_table.items():
    if access_key != key:
        print ip_list