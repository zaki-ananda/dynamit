#!/usr/bin/env bash

# Function: check_command_fail "ErrorMsg"
# Check whether the previous command fails. If so, print error message "ErrMsg", then exits
check_command_fail() {
    if [ $? -ne 0 ]; then
        echo "[dynamit-start.sh] Fatal Error: $1"
        exit 1
    fi
}

# Function: check_var_empty varname
# Check whether varname is empty variable. If so, print error message then exits
check_var_empty() {
    local var_name="$1"
    if [ -z "${!var_name}" ]; then
        echo "[dynamit-start.sh] Fatal Error: $var_name is empty string!"
        exit 1
    fi
}
############################################################################################
# Ensure that DYNAMIT is currently down (not yet started)
docker compose \
    -f /home/{{ ansible_user_id }}/dynamit/dynamit-run.yaml \
    --env-file /home/{{ ansible_user_id }}/dynamit/.env \
    --env-file /home/{{ ansible_user_id }}/dynamit/.env_dynamit down

# Disable host-wide IPv6 (for better security)
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1

# Initialize all env vars as empty string
DYNAMIT_HPOT_INTERFACE=""
DYNAMIT_HPOT_SUBNET=""
DYNAMIT_SCANHOST_IPADDR=""
DYNAMIT_MAX_CLUSTER=""
DYNAMIT_HPOT_HOST_RATIO=""
DYNAMIT_NEXT_BUILD=""

# Read dotenv files, and check whether all essential env var is nonempty
set -a && source /home/{{ ansible_user_id }}/dynamit/.env_dynamit && set +a
check_var_empty "DYNAMIT_SCANHOST_IPADDR"
check_var_empty "DYNAMIT_HPOT_SUBNET"
check_var_empty "DYNAMIT_HPOT_INTERFACE"
check_var_empty "DYNAMIT_MAX_CLUSTER"
check_var_empty "DYNAMIT_HPOT_HOST_RATIO"


# If DYNAMIT_NEXT_BUILD has not been reached, enter this block, where DYNAMIT will use previous honeypot profile configuration. 
if [[ -n "$DYNAMIT_NEXT_BUILD" && "$(date +%s)" -lt "$DYNAMIT_NEXT_BUILD" ]]; then
    echo "[dynamit-start.sh] Next build time has not been reached. Reusing previous honeynet configuration."

    # If host production interface has valid IP address, remove it, configure firewall to block any traffic to said interface and
    # to ignore any ARP traffic (to ensure DYNAMIT host doesn't get detected in production network)
    if ip addr show dev "$DYNAMIT_HPOT_INTERFACE" | grep -q 'inet '; then
	iptables -A INPUT -i ${DYNAMIT_HPOT_INTERFACE} -j DROP 2>/dev/null
	sysctl -w net.ipv4.conf.${DYNAMIT_HPOT_INTERFACE}.arp_ignore=1
	sysctl -w net.ipv4.conf.${DYNAMIT_HPOT_INTERFACE}.arp_filter=1
        ip addr del ${DYNAMIT_SCANHOST_IPADDR} dev ${DYNAMIT_HPOT_INTERFACE}
        check_command_fail "[dynamit-start.sh] Fatal Error: Removing IP ${DYNAMIT_SCANHOST_IPADDR} to ${DYNAMIT_HPOT_INTERFACE} failed!"
    fi

    # Run existing compose file to start DYNAMIT
    docker compose \
    -f /home/{{ ansible_user_id }}/dynamit/dynamit-run.yaml \
    --env-file /home/{{ ansible_user_id }}/dynamit/.env \
    --env-file /home/{{ ansible_user_id }}/dynamit/.env_dynamit up

	# Exit when compose failed
    check_command_fail "[dynamit-start.sh] Fatal Error: Composing dynamit-run failed!"
    exit 1
fi

# If DYNAMIT_NEXT_BUILD has been reached, rebuild honeypot profile configuration
echo "[dynamit-start.sh] Next build time has been reached. Rebuilding honeynet configuration."

# Assign IP address to production interface, remove firewall config that blocks traffic on said interface,
# and remove config that ignores ARP traffic
if ! ip addr show dev "$DYNAMIT_HPOT_INTERFACE" | grep -q 'inet '; then
    iptables -D INPUT -i ${DYNAMIT_HPOT_INTERFACE} -j DROP 2>/dev/null
    sysctl -w net.ipv4.conf.${DYNAMIT_HPOT_INTERFACE}.arp_ignore=0
    sysctl -w net.ipv4.conf.${DYNAMIT_HPOT_INTERFACE}.arp_filter=0
    ip addr add ${DYNAMIT_SCANHOST_IPADDR} dev ${DYNAMIT_HPOT_INTERFACE}
    check_command_fail "[dynamit-start.sh] Fatal Error: Assigning IP ${DYNAMIT_SCANHOST_IPADDR} to ${DYNAMIT_HPOT_INTERFACE} failed!"
fi

# Run honeypot config builder, creating new dynamit-run.yaml file
docker run --rm \
    -v /home/{{ ansible_user_id }}/dynamit/dynamit-run.yaml:/dynamit-run.yaml:rw \
    -v /home/{{ ansible_user_id }}/dynamit/data/:/data/:rw \
    --env-file /home/{{ ansible_user_id }}/dynamit/.env_dynamit \
    --network host \
    --cap-add=NET_RAW \
    --cap-add=CHOWN \
    dynamit-builder:1.0
check_command_fail "[dynamit-start.sh] Fatal Error: Failure at dynamit-start container!"

# From the newly-created dynamit-run.yaml, pull any images not yet present in local image repo
docker compose \
    -f /home/{{ ansible_user_id }}/dynamit/dynamit-run.yaml \
    --env-file /home/{{ ansible_user_id }}/dynamit/.env \
    --env-file /home/{{ ansible_user_id }}/dynamit/.env_dynamit pull

# Remove IP address from host production interface, configure firewall to block any traffic to said interface and
# to ignore any ARP traffic (to ensure DYNAMIT host doesn't get detected in production network)
iptables -A INPUT -i ${DYNAMIT_HPOT_INTERFACE} -j DROP 2>/dev/null
sysctl -w net.ipv4.conf.${DYNAMIT_HPOT_INTERFACE}.arp_ignore=1
sysctl -w net.ipv4.conf.${DYNAMIT_HPOT_INTERFACE}.arp_filter=1
CUR_IP=$(ip -o -f inet addr show "$DYNAMIT_HPOT_INTERFACE" | awk '{print $4}')
ip addr del ${CUR_IP} dev ${DYNAMIT_HPOT_INTERFACE}
check_command_fail "[dynamit-start.sh] Fatal Error: Removing IP ${DYNAMIT_SCANHOST_IPADDR} from ${DYNAMIT_HPOT_INTERFACE} failed!"

echo "[dynamit-start.sh] Rebuilding honeynet configuration successful."
echo "[dynamit-start.sh] Next honeynet rebuild will be done at $(date -d 'next week')"

# Update DYNAMIT_NEXT_BUILD to next week
DYNAMIT_NEXT_BUILD=$(date -d "next week" +%s)
DYNAMIT_NEXT_BUILD_COMMENT=$(date -d "next week")
sed -i "s|^DYNAMIT_NEXT_BUILD=.*|DYNAMIT_NEXT_BUILD=${DYNAMIT_NEXT_BUILD} #${DYNAMIT_NEXT_BUILD_COMMENT}|"\
        /home/{{ ansible_user_id }}/dynamit/.env_dynamit

# Run compose file to start DYNAMIT
docker compose \
    -f /home/{{ ansible_user_id }}/dynamit/dynamit-run.yaml \
    --env-file /home/{{ ansible_user_id }}/dynamit/.env \
    --env-file /home/{{ ansible_user_id }}/dynamit/.env_dynamit up

# Exit when compose failed
check_command_fail "[dynamit-start.sh] Fatal Error: Composing dynamit-run failed!"
exit 1
