# backend/proxmox_api.py
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ProxmoxAPI:
    def __init__(self, host, user, password, verify_ssl=False):
        self.host = host
        self.user = user
        self.password = password
        self.verify_ssl = verify_ssl
        self.ticket = None
        self.csrf_token = None
        self.headers = {}
        self.login()

    def login(self):
        url = f"https://{self.host}:8006/api2/json/access/ticket"
        data = {
            'username': self.user,
            'password': self.password
        }
        response = requests.post(url, data=data, verify=self.verify_ssl)
        if response.status_code == 200:
            resp_json = response.json()['data']
            self.ticket = resp_json['ticket']
            self.csrf_token = resp_json['CSRFPreventionToken']
            self.headers = {
                'CSRFPreventionToken': self.csrf_token,
                'Cookie': f"PVEAuthCookie={self.ticket}"
            }
        else:
            raise Exception(f"Failed to authenticate with Proxmox: {response.text}")

    def get_vms(self):
        url = f"https://{self.host}:8006/api2/json/nodes"
        response = requests.get(url, headers=self.headers, verify=self.verify_ssl)
        if response.status_code == 200:
            nodes = response.json()['data']
            vms = []
            for node in nodes:
                node_name = node['node']
                vm_url = f"https://{self.host}:8006/api2/json/nodes/{node_name}/qemu"
                vm_response = requests.get(vm_url, headers=self.headers, verify=self.verify_ssl)
                if vm_response.status_code == 200:
                    node_vms = vm_response.json()['data']
                    for vm in node_vms:
                        vm['node'] = node_name
                        vms.append(vm)
            return vms
        else:
            raise Exception(f"Failed to retrieve nodes: {response.text}")

    def start_vm(self, node, vmid):
        url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/status/start"
        response = requests.post(url, headers=self.headers, verify=self.verify_ssl)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to start VM {vmid}: {response.text}")

    def stop_vm(self, node, vmid):
        url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/status/stop"
        response = requests.post(url, headers=self.headers, verify=self.verify_ssl)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to stop VM {vmid}: {response.text}")

    def reboot_vm(self, node, vmid):
        url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/status/reboot"
        response = requests.post(url, headers=self.headers, verify=self.verify_ssl)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to reboot VM {vmid}: {response.text}")

    def migrate_vm(self, node, vmid, target_node):
        url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/migrate"
        data = {'target': target_node}
        response = requests.post(url, headers=self.headers, data=data, verify=self.verify_ssl)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to migrate VM {vmid}: {response.text}")

    def get_nodes(self):
        url = f"https://{self.host}:8006/api2/json/nodes"
        response = requests.get(url, headers=self.headers, verify=self.verify_ssl)
        if response.status_code == 200:
            return [node['node'] for node in response.json()['data']]
        else:
            raise Exception(f"Failed to get nodes: {response.text}")

    def get_node_resources(self, node):
        url = f"https://{self.host}:8006/api2/json/nodes/{node}/status"
        response = requests.get(url, headers=self.headers, verify=self.verify_ssl)
        if response.status_code == 200:
            data = response.json()['data']
            return {
                'cpu': data.get('cpu', 0),
                'memory': data.get('memory', 0),
                'maxcpu': data.get('maxcpu', 1),
                'maxmemory': data.get('maxmem', 1)
            }
        else:
            raise Exception(f"Failed to get resources for node {node}: {response.text}")

    def get_vm_stats(self, node, vmid):
        url = f"https://{self.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/status/current"
        response = requests.get(url, headers=self.headers, verify=self.verify_ssl)
        if response.status_code == 200:
            data = response.json()['data']
            cpu = data.get('cpu', 0)
            mem = data.get('mem', 0)
            maxmem = data.get('maxmem', 1)
            mem_usage = (mem / maxmem) * 100 if maxmem else 0
            return {
                'cpu': cpu,
                'memory': mem_usage
            }
        else:
            raise Exception(f"Failed to get stats for VM {vmid}: {response.text}")
