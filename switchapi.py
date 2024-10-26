#!python
import copy
import json
import logging
import re
from fastapi import FastAPI, HTTPException
import requests


class MacLookup():
    def __init__(self):
        self.vendor_db = {}
        self.class_db = {}
        with open("vendors.txt") as file:
            for line in file:
                self.vendor_db[line[0:6]] = line[7:].replace("\n", "")
        with open("classes.txt") as file:
            for line in file:
                parts = line.split(":")
                self.class_db[parts[0]] = parts[1].replace("\n", "")

    def lookup(self, mac):
        mac_prefix = mac.replace(":", "").replace(".", "").replace("-", "").upper()[0:6]

        if mac_prefix in self.vendor_db.keys():
            return self.vendor_db[mac_prefix]
        else:
            return "unknown"

    def lookup_class(self, mac, device_info=None):
        vendor = self.lookup(mac)
        vendor = vendor.replace(":", "")

        if vendor in self.class_db.keys():
            category = self.class_db[vendor]

            if category == "deep_classify":
                # custom rules
                # cannot deep classify if no other data is available
                if device_info is None:
                    return "unknown"

                if vendor == "Aruba Networks" or vendor == "Hewlett Packard Enterprise":
                    if 'description' in device_info.keys() and "Aruba AP" in device_info['description']:
                        return "wireless_ap"

                # at this point, we don't know
                return "unknown"
            else:
                return category
        else:
            return "unknown"


mac_lookup = MacLookup()
logger = logging.getLogger('uvicorn.error')
BASE_URL = "http://localhost:8000"
app = FastAPI(title="switchapi")


def run_command(switch, command):
    data = json.dumps({"hostname": switch, "command": command})
    response = requests.post(f"{BASE_URL}/command", data=data, headers={"Content-Type": "application/json"})

    if response.status_code > 300:
        raise Exception(f"Returned error {response.status_code} for request: {response.content}")

    json_response = json.loads(response.content)
    return json_response['output']


@app.get("/")
def read_root():
    return {"status": "success"}


@app.get("/ports/summary")
def get_port_summary(switch):
    try:
        response = run_command(switch, "show ip int brief")
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Upstream API error: {str(e)}")

    lines = response.split("\n")
    ports = {}
    for line in lines:
        if len(line) < 10 or line[0:9] == "Interface":
            continue
        parts = re.split("  +", line)
        ports[parts[0]] = {'name': parts[0], 'ip_address': parts[1], 'method': parts[2].split(" ")[1],
                           'admin_state': parts[3], 'protocol_state': parts[4]}
    return ports


@app.get("/ports/mac_table")
def get_macs_on_port(switch, port):
    try:
        response = run_command(switch, f"sh mac address-table interface {port} | include DYNAMIC")
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Upstream API error: {str(e)}")

    lines = response.split("\n")
    data = []
    for line in lines:
        if len(line.strip()) == 0:
            continue
        parts = re.split("  +", line)
        if len(parts) >= 3:
            data.append(parts[2])
    return data


@app.get("/ports/lldp_neighbors")
def get_lldp_neighbors_info(switch, port):
    try:
        response = run_command(switch, f"sh lldp neighbors {port} detail")
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Upstream API error: {str(e)}")

    neighbors = re.split("----+", response)
    parsed_neighbors = []
    for neighbor in neighbors:
        if "Local Intf" not in neighbor:
            continue

        parsed_neighbor = {}
        if "Chassis id:" in neighbor:
            parsed_neighbor['lldp_device_id'] = re.search("[\\s\\S]*Chassis id: ([\S]+)[\\s\\S]*", neighbor).group(1)
            if re.match("[A-Fa-f0-9:\\.]{12,17}", parsed_neighbor['lldp_device_id']) is not None:
                # maybe a mac address, lets format it
                try:
                    mac = parsed_neighbor['lldp_device_id'].replace(":", "").replace(".", "").upper()
                    mac = ':'.join(mac[i:i + 2] for i in range(0, 12, 2))
                    parsed_neighbor['device_id'] = mac
                    parsed_neighbor['mac_address'] = mac
                except:
                    parsed_neighbor['device_id'] = parsed_neighbor['lldp_device_id']
            else:
                parsed_neighbor['device_id'] = parsed_neighbor['lldp_device_id']
        if "Port id:" in neighbor:
            parsed_neighbor['remote_port'] = re.search("[\\s\\S]*Port id: (\\S+)[\\s\\S]*", neighbor).group(1)
        if "Port Description:" in neighbor:
            parsed_neighbor['remote_port'] = re.search("[\\s\\S]*Port Description: (\\S+)[\\s\\S]*", neighbor).group(1)
        if "System Name:" in neighbor:
            parsed_neighbor['device_name'] = re.search("[\\s\\S]*System Name: (.+)[\\s\\S]*", neighbor).group(1)
        if "System Description:" in neighbor:
            parsed_neighbor['description'] = re.search("[\\s\\S]*System Description: \\n(.+)[\\s\\S]*", neighbor).group(1)
        if "IP:" in neighbor:
            parsed_neighbor['ip_address'] = re.search("[\\s\\S]*IP: (.+)[\\s\\S]*", neighbor).group(1)
            parsed_neighbor['ip_type'] = "unknown"
        if "Serial number:" in neighbor:
            parsed_neighbor['serial_number'] = re.search("[\\s\\S]*Serial number: (.+)[\\s\\S]*", neighbor).group(1)
        if "Manufacturer:" in neighbor:
            parsed_neighbor['vendor'] = re.search("[\\s\\S]*Manufacturer: (.+)[\\s\\S]*", neighbor).group(1)
        if "Model:" in neighbor:
            parsed_neighbor['model'] = re.search("[\\s\\S]*Model: (.+)[\\s\\S]*", neighbor).group(1)

        parsed_neighbors.append(parsed_neighbor)

    return parsed_neighbors


@app.get("/ports/dhcp_bindings")
def get_port_dhcp_bindings(switch, port):
    try:
        response = run_command(switch, f"show ip dhcp snooping binding int {port}")
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Upstream API error: {str(e)}")

    data = []
    matches = re.findall("([A-z0-9:\\.]+) +([0-9\\.]+) +([0-9]+) +[A-z\\-]+ +([0-9]+) +([A-z0-9\\/\\-]+)", response)
    for match in matches:
        mac, ip, time_left, vlan, port = match
        data.append({'mac': mac, 'ip_address': ip, 'life_left': int(time_left), 'vlan': int(vlan), 'port': port})

    return data


@app.get("/ports/poe_status")
def get_port_poe_status(switch, port):
    try:
        response = run_command(switch, f"show power inline {port} detail")
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Upstream API error: {str(e)}")

    data = {}

    if "Inline Power Mode" not in response:
        data['supported'] = False
        return data
    else:
        data['supported'] = True

    data['mode'] = re.search("[\\s\\S]*Inline Power Mode: (.+)[\\s\\S]*", response).group(1)

    if "Operational status: on" in response:
        data['powered'] = True

        if "Power drawn from the source" in response:
            data['reserved_power'] = float(re.search("[\\s\\S]*Power drawn from the source: (.+)[\\s\\S]*", response).group(1))
            if "Measured at" in response:
                data['actual_power'] = float(re.search("[\\s\\S]*Measured at the port: (.+)[\\s\\S]*", response).group(1))
            else:
                data['actual_power'] = data['reserved_power']

        if "IEEE Class" in response:
            data['class'] = int(re.search("[\\s\\S]*IEEE Class: (.+)[\\s\\S]*", response).group(1))
    else:
        data['powered'] = False

    return data


@app.get("/vlans")
def get_vlans(switch):
    try:
        response = run_command(switch, "show vlan brief")
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Upstream API error: {str(e)}")

    matches = re.findall("([0-9]{0,5}) +([A-z0-9\\-\\\"']+) +([A-z\\/]+) +([A-z0-9, \\-\\/]+){0,1}", response)
    vlans = {}
    for match in matches:
        vlan_id, vlan_name, vlan_status, ports = match
        if len(vlan_id) == 0:
            continue
        vlans[vlan_id] = vlan_name

    return vlans


@app.get("/info")
def get_switch_info(switch):
    try:
        response = run_command(switch, "show version")
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Upstream API error: {str(e)}")

    data = {'manufacturer': 'Cisco'}

    if "Model number" in response:
        try:
            model_name = re.search("Model number +: +([A-z0-9\\-]+)", response).group(1)
            data['model'] = model_name
        except:
            data['model'] = 'unknown'
    if "System serial number" in response:
        try:
            serial = re.search("System serial number +: +([A-z0-9\\-]+)", response).group(1)
            data['serial_number'] = serial
        except:
            data['serial_number'] = 'unknown'
    if "License Level" in response:
        try:
            license_level = re.search("License Level: +([A-z0-9\\-]+)", response).group(1)
            data['license'] = license_level
        except:
            data['license'] = 'unknown'

    try:
        software_version = re.search("Cisco.+Software.*Version ([A-z0-9\\-\\(\\)\\.]+)", response).group(1)
        data['software_version'] = software_version
    except:
        data['software_version'] = 'unknown'

    return data


@app.get("/ports/devices")
def get_port_devices(switch, port, auth_sessions=None):
    macs = get_macs_on_port(switch, port)
    neighbors = get_lldp_neighbors_info(switch, port)
    bindings = get_port_dhcp_bindings(switch, port)
    if auth_sessions is None:
        auth_sessions = get_port_auth_sessions(switch, port)

    combined_devices = {}

    # remove any duplicate mac addresses
    for neighbor in neighbors:
        # try to find the mac address using dhcp snooping in case it is different
        if 'ip_address' in neighbor.keys():
            for binding in bindings:
                if binding['ip_address'] == neighbor['ip_address']:
                    neighbor['ip_type'] = "dhcp"
                    neighbor['dhcp_lease_expires'] = binding['life_left']
                    neighbor['mac_address'] = binding['mac']

        # lldp information will supersede any mac table or dhcp info
        if neighbor['device_id'] in macs:
            macs.remove(neighbor['device_id'])
        if 'mac_address' in neighbor.keys() and neighbor['mac_address'] in macs:
            macs.remove(neighbor('mac_address'))

        if 'mac_address' in neighbor.keys():
            if neighbor['mac_address'] in auth_sessions.keys():
                # has an active auth session
                auth_session = auth_sessions[neighbor['mac_address']]
                neighbor['ip_address'] = auth_session['ip_address']
                if 'ip_type' not in neighbor.keys():
                    neighbor['ip_type'] = 'unknown'
                auth_session.pop('ip_address')
                auth_session.pop('mac_address')
                neighbor['authentication_detail'] = auth_session

        neighbor['identified_by'] = "lldp"

        if 'vendor' not in neighbor.keys():
            try:
                if 'mac_address' in neighbor.keys():
                    neighbor['vendor'] = mac_lookup.lookup(neighbor['mac_address'])
                else:
                    neighbor['vendor'] = mac_lookup.lookup(neighbor['device_id'])
            except:
                neighbor['vendor'] = "unknown"

        # fix the device_id for devices that don't use mac ad ID
        if 'mac_address' in neighbor.keys() and neighbor['device_id'] != neighbor['mac_address']:
            neighbor['device_id'] = neighbor['mac_address'];

        if neighbor['device_id'] in combined_devices.keys():
            existing = combined_devices[neighbor['device_id']]
            for key in neighbor.keys():
                if key == "remote_port" and "vlan" in neighbor[key] and "vlan" not in existing[key]:
                    # mikrotik bug fix: don't replace physical port with virtual port name
                    continue
                existing[key] = neighbor[key]
            combined_devices[neighbor['device_id']] = existing
        else:
            combined_devices[neighbor['device_id']] = neighbor

    # add any macs from auth sessions
    for session_mac in auth_sessions.keys():
        session = auth_sessions[session_mac]
        if session_mac in combined_devices.keys():
            continue

        try:
            vendor = mac_lookup.lookup(session_mac)
        except Exception as e:
            raise e
            vendor = "unknown"

        device = {'vendor': vendor, 'identified_by': 'auth_session', 'mac_address': session_mac,
                  'device_id': session_mac}

        if 'ip_address' in session.keys():
            device['ip_address'] = session['ip_address']
            device['ip_type'] = "unknown"
            session.pop('ip_address')

        if 'mac_address' in session.keys():
            session.pop('mac_address')

        device['authentication_detail'] = session

        for binding in bindings:
            if binding['mac'].replace(":", "").replace(".", "").upper() == session_mac.replace(":", ""):
                device['ip_address'] = binding['ip_address']
                device['ip_type'] = "dhcp"
                device['dhcp_lease_expires'] = binding['life_left']

        combined_devices[session_mac] = device

    # add any mac address table or dhcp snooping entries
    for mac in macs:
        # use IEEE format mac address
        mac = mac.replace(":", "").replace(".", "").upper()
        mac = ':'.join(mac[i:i+2] for i in range(0,12,2))

        if mac in combined_devices.keys():
            continue

        try:
            vendor = mac_lookup.lookup(mac)
        except:
            vendor = "unknown"

        device = {'vendor': vendor, 'identified_by': 'mac_table', 'mac_address': mac, 'device_id': mac}

        for binding in bindings:
            if binding['mac'].replace(":", "").replace(".", "").upper() == mac.replace(":", ""):
                device['ip_address'] = binding['ip_address']
                device['ip_type'] = "dhcp"
                device['dhcp_lease_expires'] = binding['life_left']
                device['identified_by'] = "dhcp_snooping"

        if mac not in combined_devices.keys():
            combined_devices[mac] = device

    for device_key in combined_devices.keys():
        device = combined_devices[device_key]
        if 'mac_address' not in device.keys():
            continue
        if 'vendor' in device.keys() and device['vendor'] != "unknown":
            combined_devices[device_key]['profiled_class'] = mac_lookup.lookup_class(device['mac_address'], device)

    return list(combined_devices.values())


@app.get("/ports/multiple_detail")
def get_port_multiple_detail(switch, ports, include_devices=True):
    ports = ports.split(",")
    output = {}
    for port in ports:
        port_detail = get_port_detail(switch, port, include_devices)
        output[port] = port_detail
    return output


@app.get("/ports/auth_sessions")
def get_port_auth_sessions(switch, port):
    try:
        response = run_command(switch, f"show auth sessions int {port} detail")
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Upstream API error: {str(e)}")

    devices = response.split("Interface: ")
    sessions = {}

    for response in devices:
        matches = re.findall("MAC Address: +(\\S+)\\n +IPv6 Address: +(\\S+)\\n +IPv4 Address: +(\\S+)\\n +User\\-Name: +(\\S+)\\n +Status: +([A-z\\-]+)\\n +Domain: +([A-Z]+)", response)
        for match in matches:
            mac, ipv6, ipv4, username, status, domain = match

            # use IEEE format mac address
            mac = mac.replace(":", "").replace(".", "").upper()
            mac = ':'.join(mac[i:i + 2] for i in range(0, 12, 2))

            sessions[mac] = {'mac_address': mac, 'ip_address': ipv4, 'username': username,
                             'status': status, 'auth_domain': domain}

            if sessions[mac]['ip_address'].strip() == "None":
                sessions[mac].pop('ip_address')

            if re.search("dot1x +Authc Success", response) is not None:
                sessions[mac]['method'] = 'dot1x'
            elif re.search("mab +Authc Success", response) is not None:
                sessions[mac]['method'] = 'mab'
            else:
                sessions[mac]['method'] = 'unknown'

            vlan_match = re.search("Vlan Group: +Vlan: +([0-9]+)", response)
            if vlan_match is not None:
                sessions[mac]['radius_assigned_vlan'] = int(vlan_match.group(1))

            dacl_match = re.search("ACS ACL: +([A-z0-9\-_]+)", response)
            if dacl_match is not None:
                sessions[mac]['radius_assigned_dacl'] = dacl_match.group(1)

    return sessions


@app.get("/ports/detail")
def get_port_detail(switch, port, include_devices=True):
    try:
        response = run_command(switch, f"show int {port}")
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Upstream API error: {str(e)}")

    data = {}

    status_regex = re.search("[\\s\\S]*is ([A-z ]+), line protocol is ([A-z ]+) \\(([A-z \\-]+)\\)[\\s\\S]*", response)
    data['admin_state'] = status_regex.group(1)
    data['protocol_state'] = status_regex.group(2)
    data['state'] = status_regex.group(3)

    type_mac_regex = re.search("[\\s\\S]*Hardware is ([A-z ]+), address is ([A-z0-9.-]+)[\\s\\S]*", response)
    data['interface_type'] = type_mac_regex.group(1)
    mac = type_mac_regex.group(2).replace(":", "").replace(".", "").upper()
    mac = ':'.join(mac[i:i + 2] for i in range(0, 12, 2))
    data['mac_address'] = mac

    if "Description" in response:
        data['description'] = re.search("[\\s\\S]*Description: '?\"?([^\"']+).*\\n[\\s\\S]*", response).group(1)

    data['mtu'] = int(re.search("[\\s\\S]*MTU ([0-9]{0,5})[\\s\\S]*", response).group(1))
    if "Auto-speed" in response:
        data['speed_text'] = "Auto-speed"
    else:
        data['speed_text'] = re.search("[\\s\\S]*, ([0-9]+[A-z\\/]{2,4}),[\\s\\S]*", response).group(1)

    if "Mb/s" in data['speed_text']:
        data['speed'] = int(data['speed_text'][:-4])
    if "Kb/s" in data['speed_text']:
        data['speed'] = int(data['speed_text'][:-4]) / 1000
    if "Gb/s" in data['speed_text']:
        data['speed'] = int(data['speed_text'][:-4]) * 1000

    if "Full-duplex" in response:
        data['duplex'] = "full"
    elif "Auto-duplex" in response:
        data['duplex'] = "auto"
    else:
        data['duplex'] = "half"

    try:
        response = run_command(switch, f"show int {port} switchport")
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Upstream API error: {str(e)}")

    if "Switchport: Enabled" in response:
        data['switchport'] = True

        if "Operational Mode: static access" in response or \
                ("Operational Mode: down" in response and "Administrative Mode: static access" in response):
            access_vlan_search = re.search("[\\s\\S]*Access Mode VLAN: ([0-9]{0,5}) \\(([A-z0-9\"\\-_]+)\\)[\\s\\S]*", response)
            data['native_vlan_id'] = int(access_vlan_search.group(1))
            data['native_vlan_name'] = access_vlan_search.group(2).replace("\"", "")
            data['mode'] = "access"
        elif "Operational Mode: trunk" in response or \
                ("Operational Mode: down" in response and "Administrative Mode: trunk" in response):
            data['mode'] = "trunk"
            access_vlan_search = re.search("[\\s\\S]*Trunking Native Mode VLAN: ([0-9]{0,5}) \\(([A-z0-9\\-_]+)\\)[\\s\\S]*",
                                           response)
            data['native_vlan_id'] = int(access_vlan_search.group(1))
            data['native_vlan_name'] = access_vlan_search.group(2)
        else:
            data['mode'] = "unknown"

        if "Voice VLAN:" in response and "Voice VLAN: none" not in response:
            access_vlan_search = re.search("[\\s\\S]*Voice VLAN: ([0-9]{0,5}) \\(([A-z0-9\"\\-_]+)\\)[\\s\\S]*",
                                           response)
            print(response)
            data['voice_vlan_id'] = int(access_vlan_search.group(1))
            data['voice_vlan_name'] = access_vlan_search.group(2).replace("\"", "")
            data['voice_vlan_enabled'] = True
        else:
            data['voice_vlan_enabled'] = False
    else:
        data['switchport'] = False

    data['poe'] = get_port_poe_status(switch, port)

    if include_devices is True:
        auth_sessions = get_port_auth_sessions(switch, port)
        data['auth_sessions'] = list(auth_sessions.values())
        data['devices'] = get_port_devices(switch, port, copy.deepcopy(auth_sessions))

    return data
