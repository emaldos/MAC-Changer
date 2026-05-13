import random
import re
import shutil
import subprocess
class AdapterChangeError(Exception):
    def __init__(self,iface,step,target_mac,detail):
        self.iface=iface
        self.step=step
        self.target_mac=target_mac
        self.detail=detail
    def __str__(self):
        target=f" Target MAC: {self.target_mac}." if self.target_mac else ""
        return f"Adapter change failed. Interface: {self.iface}. Step: {self.step}.{target} Details: {self.detail}"
def command_exists(name):
    return shutil.which(name) is not None
def check_environment(require_sudo=False):
    if not command_exists("ip"):
        return False,"The ip command was not found. Install iproute2."
    if require_sudo and not command_exists("sudo"):
        return False,"sudo was not found. Install sudo or run in a supported Linux environment."
    return True,""
def get_interfaces():
    ok,message=check_environment(False)
    if not ok:
        return []
    try:
        result=subprocess.run(["ip","link","show"],capture_output=True,text=True)
        interfaces=[]
        for line in result.stdout.splitlines():
            match=re.match(r"^\d+:\s+([\w@]+):",line)
            if match:
                iface=match.group(1).split("@")[0]
                if iface!="lo":
                    interfaces.append(iface)
        return interfaces
    except Exception:
        return []
def get_current_mac_iface(iface):
    exists,mac=get_interface_status(iface)
    return mac if exists else "00:00:00:00:00:00"
def get_interface_status(iface):
    if not iface:
        return False,"N/A"
    ok,message=check_environment(False)
    if not ok:
        return False,message
    try:
        result=subprocess.run(["ip","link","show",iface],capture_output=True,text=True)
        if result.returncode!=0:
            return False,"unavailable"
        mac_search=re.search(r"link/ether ([0-9a-fA-F:]{17})",result.stdout)
        return True,mac_search.group(1) if mac_search else "00:00:00:00:00:00"
    except Exception:
        return False,"unavailable"
def generate_random_mac():
    first_octet=random.randint(0,255)&0xFE
    mac=[first_octet]+[random.randint(0,255) for _ in range(5)]
    return ":".join("{:02X}".format(value) for value in mac)
def generate_vendor_mac(oui):
    return oui+":"+":".join("{:02X}".format(random.randint(0,255)) for _ in range(3))
def validate_sudo_password(password):
    if not password:
        return False,"Please enter a sudo password."
    if not command_exists("sudo"):
        return False,"sudo was not found. Install sudo or run in a supported Linux environment."
    try:
        result=subprocess.run(["sudo","-S","-v"],input=password+"\n",text=True,capture_output=True,timeout=10)
        if result.returncode==0:
            return True,"Sudo password validated for this session."
        detail=(result.stderr or result.stdout or "Validation failed.").strip().splitlines()
        return False,detail[-1] if detail else "Sudo validation failed."
    except subprocess.TimeoutExpired:
        return False,"Sudo validation timed out."
    except Exception as error:
        return False,str(error)
def run_sudo_ip_link(iface,sudo_password,*args):
    step=args[0] if args else "unknown"
    target_mac=args[1] if step=="address" and len(args)>1 else None
    ok,message=check_environment(True)
    if not ok:
        raise AdapterChangeError(iface,step,target_mac,message)
    try:
        result=subprocess.run(["sudo","-S","ip","link","set",iface,*args],input=sudo_password+"\n",text=True,capture_output=True,timeout=15)
    except subprocess.TimeoutExpired:
        raise AdapterChangeError(iface,step,target_mac,"Command timed out.")
    except Exception as error:
        raise AdapterChangeError(iface,step,target_mac,str(error))
    if result.returncode!=0:
        detail=(result.stderr or result.stdout or f"exit code {result.returncode}").strip()
        raise AdapterChangeError(iface,step,target_mac,detail)
def set_interface_down(iface,sudo_password):
    run_sudo_ip_link(iface,sudo_password,"down")
def set_interface_up(iface,sudo_password):
    run_sudo_ip_link(iface,sudo_password,"up")
def set_interface_mac(iface,sudo_password,mac):
    run_sudo_ip_link(iface,sudo_password,"address",mac)
def apply_mac_change(iface,sudo_password,mac):
    set_interface_down(iface,sudo_password)
    set_interface_mac(iface,sudo_password,mac)
    set_interface_up(iface,sudo_password)
