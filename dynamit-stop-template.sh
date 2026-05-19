#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    echo "Please run as root"
    exit 1
fi

set -a && source /home/{{ ansible_user_id }}/dynamit/.env_dynamit && set +a
docker ps -aq --filter ancestor=dynamit-builder | xargs -r docker rm -f
/usr/bin/docker compose -f /home/{{ ansible_user_id }}/dynamit/dynamit-run.yaml --env-file /home/{{ ansible_user_id }}/dynamit/.env --env-file /home/{{ ansible_user_id }}/dynamit/.env_dynamit down -v
iptables -D INPUT -i ${DYNAMIT_HPOT_INTERFACE} -j DROP 2>/dev/null
sysctl -w net.ipv4.conf.${DYNAMIT_HPOT_INTERFACE}.arp_ignore=0
sysctl -w net.ipv4.conf.${DYNAMIT_HPOT_INTERFACE}.arp_filter=0
ip addr add ${DYNAMIT_SCANHOST_IPADDR} dev ${DYNAMIT_HPOT_INTERFACE}

