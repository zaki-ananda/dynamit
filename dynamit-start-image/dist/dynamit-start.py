import math
import secrets
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
import time
import random
import numpy as np
import kmedoids
from collections import defaultdict
from collections import Counter
import os
from ruamel.yaml import YAML

honeynet_addr = os.environ['DYNAMIT_HPOT_SUBNET']
honeynet_scan_ip = os.environ['DYNAMIT_SCANHOST_IPADDR']
max_cluster_amount = int(os.environ['DYNAMIT_MAX_CLUSTER'])
hpot_host_ratio = float(os.environ['DYNAMIT_HPOT_HOST_RATIO'])

## Comprehensive options='-n -sS -sU -p- -sV --version-all -O --osscan-limit --fuzzy -T4'
## Fast options='-n -sS -sU -p- -sV -O --osscan-limit -T4'
## Faster options = '-n -sS -sU -p "U:53,123,1900,T:-" -sV -T4'

####################################
### NMAP SCANNING
####################################
#For container: delete every flag file here (error and done)
network_scan = NmapProcess(targets=honeynet_addr,
                           options='-n -sS -sU -p "U:53,123,1900,T:-" -sV -T4',
                           fqp='/usr/bin/nmap')
network_scan.run_background()
print("Running nmap...")
timeout_counter = 0
while not network_scan.has_terminated():
    if timeout_counter == 30:
        print("Exited: Nmap scan took longer than 30 minutes. Please check the network connectivity.")
        exit(1)

    time.sleep(60)
    timeout_counter += 1
    print(f"Running nmap... ({network_scan.progress})")

if network_scan.rc != 0:
    print("FATAL ERROR!")
    print(network_scan.stderr)
    exit(1)

scan_result = NmapParser.parse(network_scan.stdout)

# If empty network, no need further processing
if scan_result.hosts_total == 0 or scan_result.hosts_up == 0:
    print("Exited: No active host from scan result")
    exit(1)

if scan_result.hosts_up < 2:
    print("Exited: Too few host inside network")
    exit(1)

# Enumerate active host from scan result
active_hosts = [host for host in scan_result.hosts if host.is_up()]

# Format active host data to standard format
cur_dataset = []
for host_id, host in enumerate(active_hosts):
    # Exclude host with empty MAC addr. # Those are usually scanning host (where this script is run)
    if not host.mac:
       continue

    ## PORT AND SERVICE DATA FORMATTING
    list_service = []
    for service_match in host.services:
        service_appinfo = service_match.service_dict

        # Filter service data to only get: Generic Service Name. Ex: {'name': 'http'}
        keys_to_remove = ["servicefp", "conf", "cpelist", "method", "ostype", "hostname", "product", "version", "extrainfo"]
        for key in keys_to_remove:
            service_appinfo.pop(key, None)

        # Format port and service data. Ex: {'name': 'msrpc', 'port': '1337/tcp'}
        service_appinfo['port'] = f"{service_match.port}/{service_match.protocol}"
        list_service.append(service_appinfo)

    ## WHOLE DATA FORMATTING
    host_stddata = {
        "id": host_id,
        "ip": host.ipv4,
        "mac": host.mac,
        "oui": host.mac[0:8],
        "svc": list_service,
    }
    cur_dataset.append(host_stddata)

#print(cur_dataset)

####################################
### NETWORK CLUSTERING
####################################
host_count = len(cur_dataset)
to_cluster = [{k: v for k, v in host.items() if id != 'id' and id != 'ip' and 'id' != 'mac'} for host in cur_dataset]

distance_matrix = np.zeros((host_count, host_count), dtype=float)
for row,hostr in enumerate(to_cluster):
    for col,hostc in enumerate(to_cluster):
        if hostr['oui'] != hostc['oui']:
            dist_oui = 1
        else:
            dist_oui = 0
        svc_hostr = set([elem['name'] for elem in hostr['svc']])
        svc_hostc = set([elem['name'] for elem in hostc['svc']])
        svc_intersect = svc_hostr & svc_hostc
        svc_union = svc_hostr | svc_hostc
        if len(svc_union) != 0:
            dist_svc = 1 - (len(svc_intersect) / len(svc_union))
        else:
            dist_svc = 0
        dist = (dist_oui + dist_svc)/2
        distance_matrix[row][col] = dist

prev_sill = 0
prev_loss = 0
prev_cluster = []
optimal_cluster = []
for i in range(1, min(max_cluster_amount,host_count)+1): #TODO this is still one iteration per cluster attempt
    # No optimal clustering found, so assume 1 host per cluster (aka no clustering)
    if i == min(max_cluster_amount, host_count):
        optimal_cluster = list(range(0, host_count))

    netcluster_kmedoid = kmedoids.fasterpam(distance_matrix, medoids=i, max_iter=500)
    loss = netcluster_kmedoid.loss
    cluster = netcluster_kmedoid.labels
    sill = kmedoids.silhouette(distance_matrix, cluster, False)[0]

    if i == 1:
        prev_sill = sill
        prev_loss = loss
        prev_cluster = cluster
        continue

    if sill - prev_sill < 0.03 and loss - prev_loss >= -1.6:
        optimal_cluster = prev_cluster
        break

    prev_loss = loss
    prev_sill = sill
    prev_cluster = cluster

#print(optimal_cluster)

####################################
### HONEYPOT PROFILE GENERATION
####################################
# Form list (cluster) of list (host) of dict (scan data)
# Ex: cluster_data[0][1]['ip'] = 0th cluster's 1st host's IP address
cluster_data = defaultdict(list)
for host, cluster in zip(cur_dataset, optimal_cluster):
    cluster_data[cluster].append(host)
cluster_data = [cluster_data[cluster] for cluster in sorted(cluster_data.keys())]
# Get host count per cluster. _calc won't reflect actual count, used for cluster selection (see usage below)
cluster_hcount_real = Counter(optimal_cluster)
cluster_hcount_calc = cluster_hcount_real

# Number of honeypot to be deployed in mgnet (managed network)
hpot_count = int(math.ceil(hpot_host_ratio * host_count))

# Get base address and subnet from IP string
base_addr, subnet = honeynet_addr.split('/') #Ex: "192.168.0.0/24" => ["192.168.0.0", "24"]
subnet = int(subnet)
base_addr = [int(byte) for byte in base_addr.split('.')] #Ex: "192.168.0.0" => [192, 168, 0, 0]

# Get IP bytes that starts to have nonzero range. Ex: /8 => byte_count=3; /30 => byte_count=1
# Then get range of highest byte. Ex: /24 => hbr=256; /30 => hbr=4
byte_nonzero_start = 4 - int(math.ceil((32 - subnet) / 8))
highest_byte_range = pow(2, 8 - (subnet % 8))

# Result list of tuple(range_start, range_end, range_count)
# Ex: netaddr="172.17.0.0/16" => [(0,0,0), (0,0,0), (1,254,254), (1,254,254)]
#     netaddr="172.17.0.4/30" => [(0,0,0), (0,0,0), (0,0,0), (5,6,2)]
netaddr_range = []
for idx, byte in enumerate(base_addr):
    if idx < byte_nonzero_start:
        netaddr_range.append(tuple((byte, byte, 0)))
    elif idx == byte_nonzero_start:
        netaddr_range.append(tuple((byte + 1, byte + highest_byte_range - 1, highest_byte_range - 2)))
    else:
        netaddr_range.append(tuple((1, 254, 254)))

# Get collection of hpot profile to deploy
hpot_profile = []
for i in range(hpot_count):
    # When max(cluster_hcount_calc) <= 1, stop. More hpot assumed would saturate the network
    #if (cluster_hcount_calc.most_common(1)[0][1]) <= 1: break

    # Pick random host from cluster with most host, as base profile for hpot.
    # Divide the cluster host count, to ensure overall deployment are spread out across cluster [D. Fraunholz]
    # Ex: cluster_hcount_calc = (10, 8) => Pick from 0th cluster => (5, 8) => Pick from 1st cluster => (5, 4)
    cluster = cluster_hcount_calc.most_common(1)[0][0]
    cluster_hcount_calc[cluster] = int(cluster_hcount_calc[cluster] / 2)
    cur_profile = random.choice(cluster_data[cluster]).copy()

    # Mutate IP address
    # Get range of 3rd byte (192.168.0.>>>0-255<<<), remove existing IP from range, pick one randomly
    base_ip = cur_profile['ip'].split('.')
    unused_last_byte = list(range(netaddr_range[3][0], netaddr_range[3][1] + 1))
    unused_last_byte.remove(1)
    unused_last_byte.remove(2)
    unused_last_byte.remove(254)
    scanning_host_ip_lastbyte = int(honeynet_scan_ip.split('.')[3].split('/')[0])
    if scanning_host_ip_lastbyte in unused_last_byte:
        unused_last_byte.remove(scanning_host_ip_lastbyte)
    for host in cur_dataset:
        host_ip = host['ip'].split('.')
        if host_ip[:3] == base_ip[:3] and int(host_ip[3]) in unused_last_byte:
            unused_last_byte.remove(int(host_ip[3]))
    # TODO: IP that doesn't follow real host distribution (ie: use x first/last IP) might be suspicious
    base_ip[3] = str(random.choice(unused_last_byte))
    cur_profile['ip'] = '.'.join(base_ip)
    # TODO Still assumes there's always free address on 3rd byte range
    # TODO IF none, get another used 2nd byte, get range of 3rd byte, subtract it by IP from scan data, pick one randomly
    # TODO IF out of used 2nd byte, STOP

    # Mutate MAC
    hasCollision = True
    while hasCollision:
        oui_hpot = cur_profile['mac'][0:8]
        hid_hpot = secrets.token_hex(3).upper()
        cur_profile['mac'] = f"{oui_hpot}:{hid_hpot[:2]}:{hid_hpot[2:4]}:{hid_hpot[4:6]}"

        hasCollision = False
        for host in cur_dataset:
            if host['mac'] == cur_profile['mac']:
                hasCollision = True
                break

    #TODO Mutate service/port/idk: NOPE, don't have time lol

    cur_profile['id'] = host_count
    host_count += 1
    hpot_profile.append(cur_profile)
    cur_dataset.append(cur_profile)

#print(hpot_profile)

####################################
### HONEYNET COMPOSING
####################################

def mkdir_and_set_ownership(dir:str):
    os.makedirs(dir, exist_ok=True)
    os.chown(dir, 2000, 2000)
    os.chmod(dir, 0o770)


# Load the template with comments
yaml = YAML()
yaml.preserve_quotes = True
with open("docker-compose-template.yaml") as f:
    data = yaml.load(f)

# Keep track of container index inside compose template's 'services'
container_idx = list(data['services']).index('tpotinit') + 1

to_logstash_conf = [] # Lines to be added to input section of logstash.conf

for host_idx, hpot in enumerate(hpot_profile):
    # Add internal top-level networking for each host
    data['networks'][f'internal_host{host_idx + 1}'] = None

    # Nginx-as-Honeypot-Host (NaHH) service template
    cur_nginx = {
        "container_name": f"nginx_host{host_idx + 1}",
        "restart": "always",
        "depends_on": {"tpotinit": {"condition": "service_healthy"}},
        "tmpfs": [
          "/var/tmp/nginx/client_body", "/var/tmp/nginx/proxy", "/var/tmp/nginx/fastcgi", "/var/tmp/nginx/uwsgi",
          "/var/tmp/nginx/scgi", "/run", "/var/lib/nginx/tmp:uid=100,gid=82", "/var/cache/nginx", "/tmp"
        ],
        "cap_add": ["NET_BIND_SERVICE"],
        "user": "2000:2000",
        "tty": True,
        "networks": {
          f"internal_host{host_idx+1}": None,
          "external_hosts": {"mac_address": hpot['mac'], "ipv4_address": hpot['ip']}
        },
        "image": "nginx:stable-alpine",
        "volumes": [
            f"${{TPOT_DATA_PATH}}/nginx_host{host_idx + 1}/nginx.conf:/etc/nginx/nginx.conf:ro",
            f"${{TPOT_DATA_PATH}}/nginx_host{host_idx + 1}/log/:/var/log/nginx/:rw"
        ],
        "pull_policy": "${TPOT_PULL_POLICY}",
        "read_only": True
    }
    # Add NaHH service after tpotinit or after last NaHH's honeypot service
    data['services'].insert(container_idx, f'nginx_host{host_idx + 1}', cur_nginx)
    container_idx += 1
    nginx_conf = []

    mkdir_and_set_ownership(f'/data/nginx_host{host_idx+1}/')
    mkdir_and_set_ownership(f'/data/nginx_host{host_idx + 1}/log')

    # Add nginx related lines to add to logstash.conf
    nginx_to_logstash_conf = (
     '  file {\n' +
    f'    path => ["/data/nginx_host{host_idx + 1}/log/access.log"]\n' +
    f'    codec => json\n' +
    f'    type => "nginx_host{host_idx + 1}"\n' +
    f'    add_field => {{ \n' +
    f'      "host_group" => "host{host_idx+1}"\n' +
    f'      "container_group" => "nginx" \n' +
     '    }\n' +
     '  }\n\n'
    )
    to_logstash_conf.append(nginx_to_logstash_conf)

    # Keep track of whether a container is alrd in compose (in case of multiple instance of same service in same host)
    container_composed = {'snare': False, 'cowrie': False, 'qhoneypots': False, 'ddospot': False}
    # Add honeypot container for each services
    for service in hpot['svc']:
        ###################
        ### Unknown service
        ####################
        if 'name' not in service:
            nginx_conf.append((None, service['port'].split('/')[0]))
        ### END OF Unknown service

        ##################
        ### Snare-Tanner
        #################
        elif service['name'] == 'http':
            # If snare container has been added before, only connect new port to existing snare container
            if container_composed['snare']:
                nginx_conf.append((f"snare_host{host_idx + 1}:80", service['port'].split('/')[0]))
                continue

            # Add tanner-redis to compose file
            tanner_redis = {
                "container_name": f"tanner_redis_host{host_idx+1}",
                "restart": "always",
                "depends_on": {"tpotinit": {"condition": "service_healthy"}},
                "tty": True,
                "networks": {f"internal_host{host_idx+1}": None},
                "image": "${TPOT_REPO}/redis:${TPOT_VERSION}",
                "pull_policy": "${TPOT_PULL_POLICY}",
                "read_only": True
            }
            data['services'].insert(container_idx, f"tanner_redis_host{host_idx+1}", tanner_redis)
            container_idx += 1

            # Add tanner-phpox to compose file
            tanner_phpox = {
                "container_name": f"tanner_phpox_host{host_idx + 1}",
                "restart": "always",
                "depends_on": {"tpotinit": {"condition": "service_healthy"}},
                "tty": True,
                "networks": {f"internal_host{host_idx+1}": None},
                "image": "${TPOT_REPO}/phpox:${TPOT_VERSION}",
                "pull_policy": "${TPOT_PULL_POLICY}",
                "read_only": True
            }
            data['services'].insert(container_idx, f"tanner_phpox_host{host_idx + 1}", tanner_phpox)
            container_idx += 1

            # Add tanner-api
            tanner_api = {
                "container_name": f"tanner_api_host{host_idx + 1}",
                "restart": "always",
                "depends_on": [f"tanner_redis_host{host_idx + 1}"],
                "tmpfs": ["/tmp/tanner:uid=2000,gid=2000"],
                "tty": True,
                "networks": {f"internal_host{host_idx+1}": None},
                "image": "${TPOT_REPO}/tanner:${TPOT_VERSION}",
                "pull_policy": "${TPOT_PULL_POLICY}",
                "read_only": True,
                "volumes": [
                  f"${{TPOT_DATA_PATH}}/tanner_host{host_idx+1}/config.yaml:/opt/tanner/data/config.yaml:ro",
                  f"${{TPOT_DATA_PATH}}/tanner_host{host_idx+1}/log:/var/log/tanner"
                ],
                "command": "tannerapi"
            }
            data['services'].insert(container_idx, f"tanner_api_host{host_idx + 1}", tanner_api)
            container_idx += 1

            # Add tanner to compose file
            tanner = {
                "container_name": f"tanner_host{host_idx+1}",
                "restart": "always",
                "depends_on": [f"tanner_api_host{host_idx+1}", f"tanner_phpox_host{host_idx+1}"],
                "tmpfs": ["/tmp/tanner:uid=2000,gid=2000"],
                "tty": True,
                "networks": {f"internal_host{host_idx+1}": None},
                "image": "${TPOT_REPO}/tanner:${TPOT_VERSION}",
                "pull_policy": "${TPOT_PULL_POLICY}",
                "command": "tanner",
                "read_only": True,
                "volumes": [
                  f"${{TPOT_DATA_PATH}}/tanner_host{host_idx+1}/config.yaml:/opt/tanner/data/config.yaml:ro",
                  f"${{TPOT_DATA_PATH}}/tanner_host{host_idx+1}/log:/var/log/tanner",
                  f"${{TPOT_DATA_PATH}}/tanner_host{host_idx+1}/files:/opt/tanner/files"
                ]
            }
            data['services'].insert(container_idx, f"tanner_host{host_idx + 1}", tanner)
            container_idx += 1

            # Add snare to compose file
            snare = {
                "container_name": f"snare_host{host_idx+1}",
                "restart": "always",
                "depends_on": [f"tanner_host{host_idx+1}"],
                "tty": True,
                "networks": {f"internal_host{host_idx+1}": None},
                "command": f"sh -c \"snare --tanner tanner_host{host_idx+1} --debug true --auto-update false \
                    --host-ip 0.0.0.0 --port 80 --page-dir $(shuf -i 1-10 -n 1)\"\n",
                "image": "${TPOT_REPO}/snare:${TPOT_VERSION}",
                "pull_policy": "${TPOT_PULL_POLICY}"
            }
            data['services'].insert(container_idx, f"snare_host{host_idx + 1}", snare)
            container_idx += 1

            mkdir_and_set_ownership(f'/data/tanner_host{host_idx + 1}')
            mkdir_and_set_ownership(f'/data/tanner_host{host_idx + 1}/log')
            mkdir_and_set_ownership(f'/data/tanner_host{host_idx + 1}/files')

            with open('tanner-template.yaml', 'r') as f:
                config = f.read()
            config = config.replace('host1', f'host{host_idx + 1}')
            with open(f'/data/tanner_host{host_idx+1}/config.yaml', 'w') as f:
                f.write(config)
            os.chown(f"/data/tanner_host{host_idx+1}/config.yaml", 2000, 2000)

            # Add log path of this container to logstash.conf
            tanner_to_logstash_conf = (
                     '  file {\n' +
                    f'    path => ["/data/tanner_host{host_idx + 1}/log/tanner_report.json"]\n' +
                    f'    codec => json\n' +
                    f'    type => "tanner_host{host_idx + 1}"\n' +
                    f'    add_field => {{ "host_group" => "host{host_idx + 1}" }}\n' +
                     '  }\n\n'
            )
            to_logstash_conf.append(tanner_to_logstash_conf)

            data['services'][f'nginx_host{host_idx+1}']['depends_on'].update(
                {f'snare_host{host_idx+1}': {'condition': 'service_started'}}
            )

            # Append nginx config for snare
            nginx_conf.append((f"snare_host{host_idx + 1}:80", service['port'].split('/')[0]))
            container_composed['snare'] = True


        ### END OF Snare-Tanner

        ############
        ### Cowrie
        ###########
        elif service['name'] == 'ssh':
            # If cowrie container has been added before, only connect new port to existing cowrie container
            if container_composed['cowrie']:
                nginx_conf.append((f"cowrie_host{host_idx + 1}:22", service['port'].split('/')[0]))
                continue

            # Add Cowrie to compose file
            cowrie = {
                "container_name": f"cowrie_host{host_idx+1}",
                "restart": "always",
                "depends_on": {"tpotinit": {"condition": "service_healthy"}},
                "tmpfs": ["/tmp/cowrie:uid=2000,gid=2000","/tmp/cowrie/data:uid=2000,gid=2000"],
                "networks": [f"internal_host{host_idx+1}"],
                "image": "${TPOT_REPO}/cowrie:${TPOT_VERSION}",
                "pull_policy": "${TPOT_PULL_POLICY}",
                "read_only": True,
                "volumes": [
                  f"${{TPOT_DATA_PATH}}/cowrie_host{host_idx+1}/downloads:/home/cowrie/cowrie/dl",
                  f"${{TPOT_DATA_PATH}}/cowrie_host{host_idx+1}/keys:/home/cowrie/cowrie/etc",
                  f"${{TPOT_DATA_PATH}}/cowrie_host{host_idx+1}/log:/home/cowrie/cowrie/log",
                  f"${{TPOT_DATA_PATH}}/cowrie_host{host_idx+1}/log/tty:/home/cowrie/cowrie/log/tty"
                ]
            }
            data['services'].insert(container_idx, f"cowrie_host{host_idx + 1}", cowrie)
            container_idx += 1

            mkdir_and_set_ownership(f'/data/cowrie_host{host_idx + 1}')
            mkdir_and_set_ownership(f'/data/cowrie_host{host_idx + 1}/downloads')
            mkdir_and_set_ownership(f'/data/cowrie_host{host_idx + 1}/keys')
            mkdir_and_set_ownership(f'/data/cowrie_host{host_idx + 1}/log')
            mkdir_and_set_ownership(f'/data/cowrie_host{host_idx + 1}/log/tty')

            # Add log path of this container to logstash.conf
            cowrie_to_logstash_conf = (
                    '  file {\n' +
                    f'    path => ["/data/cowrie_host{host_idx + 1}/log/cowrie.json"]\n' +
                    f'    codec => json\n' +
                    f'    type => "cowrie_host{host_idx + 1}"\n' +
                    f'    add_field => {{ "host_group" => "host{host_idx + 1}" }}\n' +
                    '  }\n\n'
            )
            to_logstash_conf.append(cowrie_to_logstash_conf)

            data['services'][f'nginx_host{host_idx+1}']['depends_on'].update(
                {f'cowrie_host{host_idx+1}': {'condition': 'service_started'}}
            )

            # Append nginx config for cowrie
            nginx_conf.append((f"cowrie_host{host_idx + 1}:22", service['port'].split('/')[0]))
            container_composed['cowrie'] = True
        ### END OF Cowrie

        #####################
        ### Qeeqbox-honeypots
        #####################
        # microsoft-ds aka SMB,  ms-wbt-server aka RDP
        elif service['port'].split('/')[1] == 'tcp' and service['name'] in ['microsoft-ds', 'vnc', 'ms-wbt-server']:
            #service['name'] in ['dhcp', 'dns', 'ftp', 'ntp', 'ipp', 'microsoft-ds', 'imap', 'pop3', 'smtp', 'vnc', 'rdp', 'mysql', 'mssql', 'elastic', 'redis', 'oracle']

            # If qhoneypots container has been added before, only connect new port to existing qhoneypots container
            if container_composed['qhoneypots']:
                if service['name'] == 'microsoft-ds':
                    nginx_conf.append((f"qhoneypots_host{host_idx + 1}:445", service['port'].split('/')[0]))
                elif service['name'] == 'vnc':
                    nginx_conf.append((f"qhoneypots_host{host_idx + 1}:5900", service['port'].split('/')[0]))
                elif service['name'] == 'ms-wbt-server':
                    nginx_conf.append((f"qhoneypots_host{host_idx + 1}:3389", service['port'].split('/')[0]))
                continue

            # Add qhoneypots to compose file
            qhoneypots = {
                "container_name": f"qhoneypots_host{host_idx+1}",
                "stdin_open": True,
                "tty": True,
                "restart": "always",
                "depends_on": {"tpotinit": {"condition": "service_healthy"}},
                "tmpfs": ["/tmp:uid=2000,gid=2000"],
                "networks": [f"internal_host{host_idx+1}"],
                "image": "${TPOT_REPO}/honeypots:${TPOT_VERSION}",
                "pull_policy": "${TPOT_PULL_POLICY}",
                "read_only": True,
                "volumes": [f"${{TPOT_DATA_PATH}}/qhoneypots_host{host_idx+1}/log:/var/log/honeypots"]
            }
            data['services'].insert(container_idx, f"qhoneypots_host{host_idx + 1}", qhoneypots)
            container_idx += 1

            mkdir_and_set_ownership(f'/data/qhoneypots_host{host_idx + 1}')
            mkdir_and_set_ownership(f'/data/qhoneypots_host{host_idx + 1}/log')

            # Add log path of this container to logstash.conf
            qhoneypots_to_logstash_conf = (
                     '  file {\n' +
                    f'    path => ["/data/qhoneypots_host{host_idx + 1}/log/*.log"]\n' +
                    f'    codec => json\n' +
                    f'    type => "qhoneypots_host{host_idx + 1}"\n' +
                    f'    add_field => {{ "host_group" => "host{host_idx + 1}" }}\n' +
                     '  }\n\n'
            )
            to_logstash_conf.append(qhoneypots_to_logstash_conf)

            data['services'][f'nginx_host{host_idx+1}']['depends_on'].update(
                {f'qhoneypots_host{host_idx+1}': {'condition': 'service_started'}}
            )

            # Append nginx config for qeeqbox-honeypots
            if service['name'] == 'microsoft-ds':
                nginx_conf.append((f"qhoneypots_host{host_idx + 1}:445", service['port'].split('/')[0]))
            elif service['name'] == 'vnc':
                nginx_conf.append((f"qhoneypots_host{host_idx + 1}:5900", service['port'].split('/')[0]))
            elif service['name'] == 'ms-wbt-server':
                nginx_conf.append((f"qhoneypots_host{host_idx + 1}:3389", service['port'].split('/')[0]))
            container_composed['qhoneypots'] = True
        ### END OF qeeqbox-honeypots

        #############
        ### Ddospot
        #############
        elif service['port'].split('/')[1] == 'udp' and service['name'] in ['domain', 'upnp', 'ntp']:
            # If ddospot container has been added before, only connect new port to existing ddospot container
            if container_composed['ddospot']:
                if service['name'] == 'domain':
                    nginx_conf.append((f"ddospot_host{host_idx + 1}:53", f"{service['port'].split('/')[0]} udp"))
                elif service['name'] == 'upnp':
                    nginx_conf.append((f"ddospot_host{host_idx + 1}:1900", f"{service['port'].split('/')[0]} udp"))
                elif service['name'] == 'ntp':
                    nginx_conf.append((f"ddospot_host{host_idx + 1}:123", f"{service['port'].split('/')[0]} udp"))
                continue

            # Add ddospot to compose file
            ddospot = {
                "container_name": "ddospot",
                "restart": "always",
                "depends_on": {"tpotinit": {"condition": "service_healthy"}},
                "networks": [f"internal_host{host_idx+1}"],
                "image": "${TPOT_REPO}/ddospot:${TPOT_VERSION}",
                "pull_policy": "${TPOT_PULL_POLICY}",
                "read_only": True,
                "volumes": [
                  f"${{TPOT_DATA_PATH}}/ddospot_host{host_idx+1}/log:/opt/ddospot/ddospot/logs",
                  f"${{TPOT_DATA_PATH}}/ddospot_host{host_idx+1}/bl:/opt/ddospot/ddospot/bl",
                  f"${{TPOT_DATA_PATH}}/ddospot_host{host_idx+1}/db:/opt/ddospot/ddospot/db"
                ]
            }
            data['services'].insert(container_idx, f"ddospot_host{host_idx + 1}", ddospot)
            container_idx += 1

            mkdir_and_set_ownership(f'/data/ddospot_host{host_idx + 1}')
            mkdir_and_set_ownership(f'/data/ddospot_host{host_idx + 1}/log')
            mkdir_and_set_ownership(f'/data/ddospot_host{host_idx + 1}/bl')
            mkdir_and_set_ownership(f'/data/ddospot_host{host_idx + 1}/db')

            # Add log path of this container to logstash.conf
            ddospot_to_logstash_conf = (
                    '  file {\n' +
                    f'    path => ["/data/ddospot_host{host_idx + 1}/log/*.log"]\n' +
                    f'    codec => json\n' +
                    f'    type => "ddospot_host{host_idx + 1}"\n' +
                    f'    add_field => {{ "host_group" => "host{host_idx + 1}" }}\n' +
                    '  }\n\n'
            )
            to_logstash_conf.append(ddospot_to_logstash_conf)

            data['services'][f'nginx_host{host_idx+1}']['depends_on'].update(
                {f'ddospot_host{host_idx+1}': {'condition': 'service_started'}}
            )

            # Append nginx config for ddospot
            if service['name'] == 'domain':
                nginx_conf.append((f"ddospot_host{host_idx + 1}:53", f"{service['port'].split('/')[0]} udp"))
            elif service['name'] == 'upnp':
                nginx_conf.append((f"ddospot_host{host_idx + 1}:1900", f"{service['port'].split('/')[0]} udp"))
            elif service['name'] == 'ntp':
                nginx_conf.append((f"ddospot_host{host_idx + 1}:123", f"{service['port'].split('/')[0]} udp"))
            container_composed['ddospot'] = True
        ### END OF Ddospot
        else:
            nginx_conf.append((None, service['port'].split('/')[0]))

    #############################################
    ### Process nginx.conf for each nginx_host*
    #############################################
    stream_blocks = ""
    for c in nginx_conf:
        # If no service is associated with a port, just open it without connecting it anywhere
        if c[0] is None:
            block = (
                 "  server {\n" +
                f"    listen {c[1]};\n" +
                 "    return 444;\n" +
                 "  }\n"
            )
            stream_blocks += block

        # Else when a port has service associated with port, connect it to relevant container
        else:
            block = (
                 "    server {\n" +
                f"        listen {c[1]};\n" +
                f"        proxy_pass {c[0]};\n" +
                 "    }\n"
            )
            stream_blocks += block

    # # Write nginx conf file
    # final_nginx_conf = (
    #     "pid /tmp/nginx.pid;\n" +
    #     "access_log /var/log/nginx/access.log;\n" +
    #     "events {\n" +
    #     "  worker_connections  1024;\n" +
    #     "}\n" +
    #     "stream {\n" +
    #     log_format stream_json escape=json '{'\n
    # '"timestamp": "$time_iso8601", '
    # '"src_ip": "$remote_addr", '
    # '"src_port": "$remote_port", '
    # '"dst_ip": "$server_addr", '
    # '"dst_port": "$server_port", '
    # '"protocol": "$protocol", '
    # '"status": "$status", '
    # '"bytes_sent": "$bytes_sent", '
    # '"bytes_received": "$bytes_received", '
    # '"session_time": "$session_time", '
    # '"connection_serial": "$connection", '
    # '"pid": "$pid", '
    # '"upstream": "$upstream_addr"'
    # '}';
    # stream_blocks +
    #     "}\n"
    # )
    # with open(f"/data/nginx_host{host_idx+1}/nginx.conf", "w") as nginx_file:
    #     nginx_file.write(final_nginx_conf)
    # os.chown(f"/data/nginx_host{host_idx+1}/nginx.conf", 2000, 2000)

    with open("nginx-template.conf", "r") as f:
        lines = f.readlines()

    new_lines = []
    for line in lines:
        new_lines.append(line)
        if "### START OF TEMPLATE ENTRY" in line:
            new_lines.extend(stream_blocks)

    mkdir_and_set_ownership(f"/data/nginx_host{host_idx+1}")
    with open(f"/data/nginx_host{host_idx+1}/nginx.conf", "w") as f:
        f.writelines(new_lines)
    os.chown(f"/data/nginx_host{host_idx+1}/nginx.conf", 2000, 2000)

    ### END of nginx.conf processing

##############################
### Logstash.conf processing
##############################
with open("logstash-template.conf", "r") as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    new_lines.append(line)
    if "### DYNAMIT INPUT SECTION" in line:
        new_lines.extend(to_logstash_conf)

mkdir_and_set_ownership(f"/data/logstash")
with open("/data/logstash/logstash.conf", "w") as f:
    f.writelines(new_lines)
os.chown(f"/data/logstash/logstash.conf", 2000, 2000)
### END OF logstash.conf processing

####################################
### Write honeypot orchestration file
####################################
with open("/dynamit-run.yaml", "w") as f:
    yaml.dump(data, f)
os.chown("/dynamit-run.yaml", 1000, 1000)
