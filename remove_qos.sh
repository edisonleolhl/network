#!/bin/bash
# remove-qos cmd
ovs-vsctl --all destroy qos
ovs-vsctl --all destroy queue
