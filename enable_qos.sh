#!/bin/bash

# this script is used for 5 switches topo

# set the version of OpenFlow to be used in each switch to version 1.3
ovs-vsctl set Bridge s1 protocols=OpenFlow13
ovs-vsctl set Bridge s2 protocols=OpenFlow13 # if no s2, then print error
ovs-vsctl set Bridge s3 protocols=OpenFlow13
ovs-vsctl set Bridge s4 protocols=OpenFlow13
ovs-vsctl set Bridge s5 protocols=OpenFlow13

# listen on port 6632 to access OVSDB
ovs-vsctl set-manager ptcp:6632

# access OVSDB
curl -X PUT -d '"tcp:127.0.0.1:6632"' http://localhost:8080/v1.0/conf/switches/0000000000000001/ovsdb_addr
curl -X PUT -d '"tcp:127.0.0.1:6632"' http://localhost:8080/v1.0/conf/switches/0000000000000002/ovsdb_addr # if no s2, no print
curl -X PUT -d '"tcp:127.0.0.1:6632"' http://localhost:8080/v1.0/conf/switches/0000000000000003/ovsdb_addr
curl -X PUT -d '"tcp:127.0.0.1:6632"' http://localhost:8080/v1.0/conf/switches/0000000000000004/ovsdb_addr
curl -X PUT -d '"tcp:127.0.0.1:6632"' http://localhost:8080/v1.0/conf/switches/0000000000000005/ovsdb_addr

# execute setting of Queue
curl -X POST -d '{"port_name": "s1-eth1", "type": "linux-htb", "max_rate": "1000000", "queues": [{"max_rate": "500000"}, {"min_rate": "800000"}]}' http://localhost:8080/qos/queue/0000000000000001

# install the following flow entry to the switch
curl -X POST -d '{"match": {"nw_dst": "10.0.0.1", "nw_proto": "UDP", "tp_dst": "5002"}, "actions":{"queue": "1"}}' http://localhost:8080/qos/rules/0000000000000001

# verify the setting
curl -X GET http://localhost:8080/qos/rules/0000000000000001