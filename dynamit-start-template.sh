#!/usr/bin/env bash

check_command_fail() {
    if [ $? -ne 0 ]; then
        echo "[dynamit-start.sh] Fatal Error: $1"
        exit 1
    fi
}

check_var_empty() {
    local var_name="$1"
    if [ -z "${!var_name}" ]; then
        echo "[dynamit-start.sh] Fatal Error: $var_name is empty string!"
        exit 1
    fi
}

docker compose \
    -f /home/{{ ansible_user_id }}/tpotce/dynamit-run.yaml \
    --env-file /home/{{ ansible_user_id }}/tpotce/.env \
    --env-file /home/{{ ansible_user_id }}/tpotce/.env_dynamit down

DYNAMIT_HPOT_INTERFACE=""
DYNAMIT_HPOT_SUBNET=""
DYNAMIT_SCANHOST_IPADDR=""
DYNAMIT_MAX_CLUSTER=""
DYNAMIT_HPOT_HOST_RATIO=""
DYNAMIT_NEXT_BUILD=""
set -a && source /home/{{ ansible_user_id }}/tpotce/.env_dynamit && set +a
check_var_empty "DYNAMIT_SCANHOST_IPADDR"
check_var_empty "DYNAMIT_HPOT_SUBNET"
check_var_empty "DYNAMIT_HPOT_INTERFACE"
check_var_empty "DYNAMIT_MAX_CLUSTER"
check_var_empty "DYNAMIT_HPOT_HOST_RATIO"

if [[ -n "$DYNAMIT_NEXT_BUILD" && "$(date +%s)" -lt "$DYNAMIT_NEXT_BUILD" ]]; then
    echo "[dynamit-start.sh] Next build time has not been reached. Reusing previous honeynet configuration."

    if ip addr show dev "$DYNAMIT_HPOT_INTERFACE" | grep -q 'inet '; then
        ip addr del ${DYNAMIT_SCANHOST_IPADDR} dev ${DYNAMIT_HPOT_INTERFACE}
        check_command_fail "[dynamit-start.sh] Fatal Error: Removing IP ${DYNAMIT_SCANHOST_IPADDR} to ${DYNAMIT_HPOT_INTERFACE} failed!"
    fi

    docker compose \
    -f /home/{{ ansible_user_id }}/tpotce/dynamit-run.yaml \
    --env-file /home/{{ ansible_user_id }}/tpotce/.env \
    --env-file /home/{{ ansible_user_id }}/tpotce/.env_dynamit up
    check_command_fail "[dynamit-start.sh] Fatal Error: Composing dynamit-run failed!"
    exit 1
fi

echo "[dynamit-start.sh] Next build time has been reached. Rebuilding honeynet configuration."

if ! ip addr show dev "$DYNAMIT_HPOT_INTERFACE" | grep -q 'inet '; then
    ip addr add ${DYNAMIT_SCANHOST_IPADDR} dev ${DYNAMIT_HPOT_INTERFACE}
    check_command_fail "[dynamit-start.sh] Fatal Error: Assigning IP ${DYNAMIT_SCANHOST_IPADDR} to ${DYNAMIT_HPOT_INTERFACE} failed!"
fi

docker run --rm \
    -v /home/{{ ansible_user_id }}/tpotce/dynamit-run.yaml:/dynamit-run.yaml:rw \
    -v /home/{{ ansible_user_id }}/tpotce/data/:/data/:rw \
    --env-file /home/{{ ansible_user_id }}/tpotce/.env_dynamit \
    --network host \
    --cap-add=NET_RAW \
    --cap-add=NET_ADMIN \
    --cap-add=CHOWN \
    dynamit-start:1.0
check_command_fail "[dynamit-start.sh] Fatal Error: Failure at dynamit-start container!"

CUR_IP=$(ip -o -f inet addr show "$DYNAMIT_HPOT_INTERFACE" | awk '{print $4}')
ip addr del ${CUR_IP} dev ${DYNAMIT_HPOT_INTERFACE}
check_command_fail "[dynamit-start.sh] Fatal Error: Removing IP ${DYNAMIT_SCANHOST_IPADDR} from ${DYNAMIT_HPOT_INTERFACE} failed!"

echo "[dynamit-start.sh] Rebuilding honeynet configuration successful."
echo "[dynamit-start.sh] Next honeynet rebuild will be done at $(date -d 'next week')"

DYNAMIT_NEXT_BUILD=$(date -d "next week" +%s)
DYNAMIT_NEXT_BUILD_COMMENT=$(date -d "next week")
sed -i "s|^DYNAMIT_NEXT_BUILD=.*|DYNAMIT_NEXT_BUILD=${DYNAMIT_NEXT_BUILD} #${DYNAMIT_NEXT_BUILD_COMMENT}|"\
        /home/{{ ansible_user_id }}/tpotce/.env_dynamit

docker compose \
    -f /home/{{ ansible_user_id }}/tpotce/dynamit-run.yaml \
    --env-file /home/{{ ansible_user_id }}/tpotce/.env \
    --env-file /home/{{ ansible_user_id }}/tpotce/.env_dynamit up
check_command_fail "[dynamit-start.sh] Fatal Error: Composing dynamit-run failed!"
exit 1
