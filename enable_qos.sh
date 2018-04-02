#!/bin/bash

# this script is used for 5 switches topo

# set the version of OpenFlow to be used in each switch to version 1.3
ovs-vsctl set Bridge s1 protocols=OpenFlow13
ovs-vsctl set Bridge s2 protocols=OpenFlow13
ovs-vsctl set Bridge s3 protocols=OpenFlow13
ovs-vsctl set Bridge s4 protocols=OpenFlow13
ovs-vsctl set Bridge s5 protocols=OpenFlow13

# listen on port 6632 to access OVSDB
ovs-vsctl set-manager ptcp:6632

# access OVSDB
curl -X PUT -d '"tcp:127.0.0.1:6632"' http://localhost:8080/v1.0/conf/switches/0000000000000001/ovsdb_addr
curl -X PUT -d '"tcp:127.0.0.1:6632"' http://localhost:8080/v1.0/conf/switches/0000000000000002/ovsdb_addr
curl -X PUT -d '"tcp:127.0.0.1:6632"' http://localhost:8080/v1.0/conf/switches/0000000000000003/ovsdb_addr
curl -X PUT -d '"tcp:127.0.0.1:6632"' http://localhost:8080/v1.0/conf/switches/0000000000000004/ovsdb_addr
curl -X PUT -d '"tcp:127.0.0.1:6632"' http://localhost:8080/v1.0/conf/switches/0000000000000005/ovsdb_addr


