#!/usr/bin/env bash

myINSTALL_NOTIFICATION="### Now installing required packages ..."
myUSER=$(whoami)
myTPOT_CONF_FILE="/home/${myUSER}/tpotce/.env"
dynamit_CONF_FILE="/home/${myUSER}/tpotce/.env_dynamit"
myPACKAGES_DEBIAN="ansible apache2-utils cracklib-runtime wget nmap"
myPACKAGES_FEDORA="ansible cracklib httpd-tools wget nmap"
myPACKAGES_ROCKY="ansible-core ansible-collection-redhat-rhel_mgmt epel-release cracklib httpd-tools wget nmap"
myPACKAGES_OPENSUSE="ansible apache2-utils cracklib wget nmap"
myANSIBLE_TPOT_PLAYBOOK="installer/install/dynamit.yml"


myINSTALLER=$(cat << "EOF"
 _____     ____       _      ___           _        _ _
|_   _|   |  _ \ ___ | |_   |_ _|_ __  ___| |_ __ _| | | ___ _ __
  | |_____| |_) / _ \| __|   | || '_ \/ __| __/ _` | | |/ _ \ '__|
  | |_____|  __/ (_) | |_    | || | | \__ \ || (_| | | |  __/ |
  |_|     |_|   \___/ \__|  |___|_| |_|___/\__\__,_|_|_|\___|_|
EOF
)

# Check if running with root privileges
if [ ${EUID} -eq 0 ];
  then
    echo "This script should not be run as root. Please run it as a regular user."
    echo
    exit 1
fi

# Check if running on a supported distribution
mySUPPORTED_DISTRIBUTIONS=("AlmaLinux" "Debian GNU/Linux" "Fedora Linux" "openSUSE Tumbleweed" "Raspbian GNU/Linux" "Rocky Linux" "Ubuntu")
myCURRENT_DISTRIBUTION=$(awk -F= '/^NAME/{print $2}' /etc/os-release | tr -d '"')

if [[ ! " ${mySUPPORTED_DISTRIBUTIONS[@]} " =~ " ${myCURRENT_DISTRIBUTION} " ]];
  then
    echo "### Only the following distributions are supported: AlmaLinux, Fedora, Debian, openSUSE Tumbleweed, Rocky Linux and Ubuntu."
    echo "### Please follow the T-Pot documentation on how to run T-Pot on macOS, Windows and other currently unsupported platforms."
    echo
    exit 1
fi

# Begin of Installer
echo "$myINSTALLER"
echo
echo
echo "### This script will now install T-Pot and all of its dependencies."
while [ "${myQST}" != "y" ] && [ "${myQST}" != "n" ];
  do
    echo
    read -p "### Install? (y/n) " myQST
    echo
  done
if [ "${myQST}" = "n" ];
  then
    echo
    echo "### Aborting!"
    echo
    exit 0
fi

# Install packages based on the distribution
case ${myCURRENT_DISTRIBUTION} in
  "Fedora Linux")
    echo
    echo ${myINSTALL_NOTIFICATION}
    echo
    sudo dnf -y --refresh install ${myPACKAGES_FEDORA}
    ;;
  "Debian GNU/Linux"|"Raspbian GNU/Linux"|"Ubuntu")
    echo
    echo ${myINSTALL_NOTIFICATION}
    echo
    if ! command -v sudo >/dev/null;
      then
        echo "### ‘sudo‘ is not installed. To continue you need to provide the ‘root‘ password"
        echo "### or press CTRL-C to manually install ‘sudo‘ and add your user to the sudoers."
        echo
        su -c "apt -y update && \
               NEEDRESTART_SUSPEND=1 apt -y install sudo ${myPACKAGES_DEBIAN} && \
               /usr/sbin/usermod -aG sudo ${myUSER} && \
               echo '${myUSER} ALL=(ALL:ALL) ALL' | tee /etc/sudoers.d/${myUSER} >/dev/null && \
               chmod 440 /etc/sudoers.d/${myUSER}"
        echo "### We need sudo for Ansible, please enter the sudo password ..."
        sudo echo "### ... sudo for Ansible acquired."
        echo
      else
        sudo apt update
        sudo NEEDRESTART_SUSPEND=1 apt install -y ${myPACKAGES_DEBIAN}
    fi
    ;;
  "openSUSE Tumbleweed")
    echo
    echo ${myINSTALL_NOTIFICATION}
    echo
    sudo zypper refresh
    sudo zypper install -y ${myPACKAGES_OPENSUSE}
    echo "export ANSIBLE_PYTHON_INTERPRETER=/bin/python3" | sudo tee /etc/profile.d/ansible.sh >/dev/null
    source /etc/profile.d/ansible.sh
    ;;
  "AlmaLinux"|"Rocky Linux")
    echo
    echo ${myINSTALL_NOTIFICATION}
    echo
    sudo dnf -y --refresh install ${myPACKAGES_ROCKY}
    ansible-galaxy collection install ansible.posix
    ;;
esac
echo

echo "### Testing MACVLAN capability on available interface ... "
supported_ifaces=()
active_ifaces=$(ip route | grep -v '^default' | grep -v 'linkdown' | grep 'kernel' | awk '{print $3}')
if [ ${#active_ifaces[@]} -eq 0 ]; then
    echo "### No active interface found. Please ensure that the desired honeynet interface is active and configured with IPv4 address"
    echo "### Aborting."
    echo
    exit 1
fi

# Check macvlan routing support on every interfaces with default gateway
for iface in $active_ifaces; do
    # Get IP addr and gateway for current interface
    ip_info=$(ip -o -f inet addr show "$iface" | awk '{print $4}')
    gateway_ip=$(ip route | grep "^default.*$iface" | awk '{print $3}')
    if [ -z "$ip_info" ]; then #If no IP addr then skip
      continue
    fi

    # Get base IP (first 3 byte) and prefix length (ex: /24) of current interface
    full_ip=$(echo "$ip_info" | cut -d'/' -f1)
    ip_base=$(echo "$ip_info" | cut -d'.' -f1-3)
    prefix_len=$(echo "$ip_info" | cut -d'/' -f2)

    # Get list of used IP inside network
    live_ips=$(nmap -sn -n "${ip_base}.0/24" | grep 'Nmap scan report for' | awk '{print $5}')

    # Network host other than this host
    nethost_ips=$(echo "$live_ips" | grep -v "$full_ip" | grep -v $(hostname))

    # If this host is the only active one in network, skip
    if [ -z nethost_ips ]; then
       continue
    fi

    # Generate IP pool (.2 to .254), then eliminate active IPs to get unused IPs
    unused_ips=()
    for i in $(seq 2 254); do
        candidate="${base}.${i}"
        if ! echo "$live_ips" | grep -q "$candidate"; then
            unused_ips+=("$candidate")
        fi
    done

    # If no unused IP, skip interface
    if [ ${#unused_ips[@]} -eq 0 ]; then
        continue
    fi

    # Pick random unused IP as test source
    test_ip="${ip_base}.$((RANDOM % ${#unused_ips[@]}))"

    # Pick random active IP as target
    test_target="$(echo "$nethost_ips" | shuf -n 1)"

    # Generate random MAC
    test_mac="AA:BB:CC:$(hexdump -n3 -e '3/1 "%02X"' /dev/urandom | sed 's/\(..\)/\1:/g;s/:$//')"

    # Set up interface for macvlan routing test
    sudo ip link add link "$iface" name macvlan-test addr "$test_mac" type macvlan mode bridge
    sudo ip link set macvlan-test up
    sudo ip addr add "$test_ip/$prefix_len" dev macvlan-test

    # Perform macvlan routing test via ping to gateway, add interface to list if successful
    if ping -I macvlan-test -c 4 -W 1 "$test_target" > /dev/null; then
        supported_ifaces+=("$iface")
    fi

    # Clean up current macvlan test configuration
    sudo ip addr del "$test_ip/$prefix_len" dev macvlan-test
    sudo ip link set macvlan-test down
    sudo ip link del macvlan-test
done

if [ ${#supported_ifaces[@]} -eq 0 ]; then
    echo "### MACVLAN-supported interface not found. Note that this script only tests interfaces that have a configured IPv4 address, and whose network has other active host(s)"
    echo "### Aborting."
    echo
    exit 1
fi

echo "### MACVLAN-supported interface found."
printf "%-6s %-10s %-25s %-25s %-20s\n" "------" "---------" "-------------------------" "---------------------"
printf "%-6s %-10s %-25s %-25s %-20s\n" "Select" "Interface"        "IP Address"              "MAC Address"
printf "%-6s %-10s %-25s %-25s %-20s\n" "------" "---------" "-------------------------" "---------------------"
index=1
for iface in "${supported_ifaces[@]}"; do
    ip_addr=$(ip -o -f inet addr show "$iface" | awk '{print $4}')
    mac=$(cat /sys/class/net/$iface/address)

    printf "%-6s %-10s %-25s %-25s %-20s\n" "$index" "$iface" "$ip_addr" "$mac"
    ((index++))
done
echo
while true; do
  read -p "### Select an interface that will act as honeynet interface: " dynamit_HONEYINT_SELECT
  if ((dynamit_HONEYINT_SELECT >= 1 && dynamit_HONEYINT_SELECT < index)); then
    if ! [ -f ${dynamit_CONF_FILE} ]; then
      echo "### Error: .env_dynamit file not found!"
      echo "### Aborting."
      echo
      exit 1
    fi
    dynamit_HONEYINT=${supported_ifaces[$((dynamit_HONEYINT_SELECT-1))]}
    dynamit_HONEYIP=$(ip -o -f inet addr show "$dynamit_HONEYINT" | awk '{print $4}')
    dynamit_HONEYSUBNET=$(ip route | grep -v '^default' | grep "$dynamit_HONEYINT" | awk '{print $1}')
    sed -i "s|^DYNAMIT_HPOT_INTERFACE=.*|DYNAMIT_HPOT_INTERFACE=${dynamit_HONEYINT}|" ${dynamit_CONF_FILE}
    sed -i "s|^DYNAMIT_HPOT_SUBNET=.*|DYNAMIT_HPOT_SUBNET=${dynamit_HONEYSUBNET}|" ${dynamit_CONF_FILE}
    sed -i "s|^DYNAMIT_SCANHOST_IPADDR=.*|DYNAMIT_SCANHOST_IPADDR=${dynamit_HONEYIP}|" ${dynamit_CONF_FILE}
    break
  fi
done

# Define tag for Ansible
myANSIBLE_DISTRIBUTIONS=("Fedora Linux" "Debian GNU/Linux" "Raspbian GNU/Linux" "Rocky Linux")
if [[ "${myANSIBLE_DISTRIBUTIONS[@]}" =~ "${myCURRENT_DISTRIBUTION}" ]];
  then
    myANSIBLE_TAG=$(echo ${myCURRENT_DISTRIBUTION} | cut -d " " -f 1)
  else
    myANSIBLE_TAG=${myCURRENT_DISTRIBUTION}
fi

# Check type of sudo access
sudo -n true > /dev/null 2>&1
if [ $? -eq 1 ];
  then
    myANSIBLE_BECOME_OPTION="--ask-become-pass"
    echo "### ‘sudo‘ not acquired, setting ansible become option to ${myANSIBLE_BECOME_OPTION}."
    echo "### Ansible will ask for the ‘BECOME password‘ which is typically the password you ’sudo’ with."
    echo
  else
    myANSIBLE_BECOME_OPTION="--become"
    echo "### ‘sudo‘ acquired, setting ansible become option to ${myANSIBLE_BECOME_OPTION}."
    echo
fi

# Run Ansible Playbook
echo "### Now running T-Pot Ansible Installation Playbook ..."
echo
rm ${HOME}/install_tpot.log > /dev/null 2>&1
ANSIBLE_LOG_PATH=${HOME}/install_tpot.log ansible-playbook ${myANSIBLE_TPOT_PLAYBOOK} -i 127.0.0.1, -c local --tags "${myANSIBLE_TAG}" ${myANSIBLE_BECOME_OPTION}

# Something went wrong
if [ ! $? -eq 0 ];
  then
    echo "### Something went wrong with the Playbook, please review the output and / or install_tpot.log for clues."
    echo "### Aborting."
    echo
    exit 1
  else
    echo "### Playbook was successful."
    echo
fi

## Ask for T-Pot Installation Type
#echo
#echo "### Choose your T-Pot type:"
#echo "### (H)ive   - T-Pot Standard / HIVE installation."
#echo "###            Includes also everything you need for a distributed setup with sensors."
#echo "### (S)ensor - T-Pot Sensor installation."
#echo "###            Optimized for a distributed installation, without WebUI, Elasticsearch and Kibana."
#echo "### (L)LM    - T-Pot LLM installation."
#echo "###            Uses LLM based honeypots Beelzebub & Galah."
#echo "###            Requires Ollama (recommended) or ChatGPT subscription."
#echo "### M(i)ni   - T-Pot Mini installation."
#echo "###            Run 30+ honeypots with just a couple of honeypot daemons."
#echo "### (M)obile - T-Pot Mobile installation."
#echo "###            Includes everything to run T-Pot Mobile (available separately)."
#echo "### (T)arpit - T-Pot Tarpit installation."
#echo "###            Feed data endlessly to attackers, bots and scanners."
#echo "###            Also runs a Denial of Service Honeypot (ddospot)."
#echo
#while true; do
#  read -p "### Install Type? (h/s/l/i/m/t) " myTPOT_TYPE
#  case "${myTPOT_TYPE}" in
#    h|H)
#      echo
#      echo "### Installing T-Pot Standard / HIVE."
#      myTPOT_TYPE="HIVE"
#      cp ${HOME}/tpotce/compose/standard.yml ${HOME}/tpotce/docker-compose.yml
#      myINFO=""
#      break ;;
#    s|S)
#      echo
#      echo "### Installing T-Pot Sensor."
#      myTPOT_TYPE="SENSOR"
#      cp ${HOME}/tpotce/compose/sensor.yml ${HOME}/tpotce/docker-compose.yml
#      myINFO="### Make sure to deploy SSH keys to this SENSOR and disable SSH password authentication.
#### On HIVE run the tpotce/deploy.sh script to join this SENSOR to the HIVE."
#      break ;;
#    l|L)
#      echo
#      echo "### Installing T-Pot LLM."
#      myTPOT_TYPE="HIVE"
#      cp ${HOME}/tpotce/compose/llm.yml ${HOME}/tpotce/docker-compose.yml
#      myINFO="Make sure to adjust the T-Pot config file (.env) for Ollama / ChatGPT settings."
#      break ;;
#    i|I)
#      echo
#      echo "### Installing T-Pot Mini."
#      myTPOT_TYPE="HIVE"
#      cp ${HOME}/tpotce/compose/mini.yml ${HOME}/tpotce/docker-compose.yml
#      myINFO=""
#      break ;;
#    m|M)
#      echo
#      echo "### Installing T-Pot Mobile."
#      myTPOT_TYPE="MOBILE"
#      cp ${HOME}/tpotce/compose/mobile.yml ${HOME}/tpotce/docker-compose.yml
#      myINFO=""
#      break ;;
#    t|T)
#      echo
#      echo "### Installing T-Pot Tarpit."
#      myTPOT_TYPE="HIVE"
#      cp ${HOME}/tpotce/compose/tarpit.yml ${HOME}/tpotce/docker-compose.yml
#      myINFO=""
#      break ;;
#  esac
#done

# Preparing web user for T-Pot
echo
echo "### T-Pot User Configuration ..."
echo
# Asking for web user name
myWEB_USER=""
while [ 1 != 2 ];
  do
    myOK=""
    read -rp "### Enter your web user name: " myWEB_USER
    myWEB_USER=$(echo $myWEB_USER | tr -cd "[:alnum:]_.-")
    echo "### Your username is: ${myWEB_USER}"
    while [[ ! "${myOK}" =~ [YyNn] ]];
      do
        read -rp "### Is this correct? (y/n) " myOK
      done
    if [[ "${myOK}" =~ [Yy] ]] && [ "$myWEB_USER" != "" ];
      then
        break
      else
        echo
    fi
  done

# Asking for web user password
myWEB_PW="pass1"
myWEB_PW2="pass2"
mySECURE=0
myOK=""
while [ "${myWEB_PW}" != "${myWEB_PW2}"  ] && [ "${mySECURE}" == "0" ]
  do
    echo
    while [ "${myWEB_PW}" == "pass1"  ] || [ "${myWEB_PW}" == "" ]
      do
        read -rsp "### Enter password for your web user: " myWEB_PW
        echo
      done
    read -rsp "### Repeat password you your web user: " myWEB_PW2
    echo
    if [ "${myWEB_PW}" != "${myWEB_PW2}" ];
      then
        echo "### Passwords do not match."
        myWEB_PW="pass1"
        myWEB_PW2="pass2"
    fi
    mySECURE=$(printf "%s" "$myWEB_PW" | /usr/sbin/cracklib-check | grep -c "OK")
    if [ "$mySECURE" == "0" ] && [ "$myWEB_PW" == "$myWEB_PW2" ];
      then
        while [[ ! "${myOK}" =~ [YyNn] ]];
          do
            read -rp "### Keep insecure password? (y/n) " myOK
          done
        if [[ "${myOK}" =~ [Nn] ]] || [ "$myWEB_PW" == "" ];
          then
            myWEB_PW="pass1"
            myWEB_PW2="pass2"
            mySECURE=0
            myOK=""
        fi
    fi
done

# Write username and password to T-Pot config file
echo "### Creating base64 encoded htpasswd username and password for T-Pot config file: ${myTPOT_CONF_FILE}"
myWEB_USER_ENC=$(htpasswd -b -n "${myWEB_USER}" "${myWEB_PW}")
  myWEB_USER_ENC_B64=$(echo -n "${myWEB_USER_ENC}" | base64 -w0)

echo
sed -i "s|^WEB_USER=.*|WEB_USER=${myWEB_USER_ENC_B64}|" ${myTPOT_CONF_FILE}

# Pull docker images
echo "### Now pulling images ..."
sudo docker compose \
    -f /home/${myUSER}/tpotce/dynamit-run.yaml \
    --env-file /home/${myUSER}/tpotce/.env \
    --env-file /home/${myUSER}/tpotce/.env_dynamit pull
sudo docker buildx build -t dynamit-start:1.0 /home/${myUSER}/tpotce/dynamit-start-image/
echo



# Show running services
echo "### Please review for possible honeypot port conflicts."
echo "### While SSH is taken care of, other services such as"
echo "### SMTP, HTTP, etc. might prevent T-Pot from starting."
echo
sudo grc netstat -tulpen
echo

# Done
echo "### Done. Please reboot and re-connect via SSH on tcp/64295."
echo "${myINFO}"
echo
