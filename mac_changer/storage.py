from pathlib import Path
import json
import logging
ROOT_DIR=Path(__file__).resolve().parent.parent
DATA_DIR=ROOT_DIR/"data"
LOG_DIR=ROOT_DIR/"logs"
COMPANY_OUIS_FILE=DATA_DIR/"company_ouis.json"
DEFAULT_MAC_FILE=DATA_DIR/"default_mac_address.json"
MANUAL_CHANGES_FILE=DATA_DIR/"changes_tracking.json"
AUTO_CHANGES_FILE=DATA_DIR/"auto_changes.json"
SMART_CHANGES_FILE=DATA_DIR/"changes_smart.json"
MAC_PROFILES_FILE=DATA_DIR/"mac_profiles.json"
SETTINGS_FILE=DATA_DIR/"settings.json"
LOG_FILE=LOG_DIR/"mac_changer.log"
DEFAULT_COMPANIES={"iPhone":["00:1A:2B","00:1B:3C"],"Samsung":["00:16:3E"],"Dell":["00:1D:4F"]}
DEFAULT_SETTINGS={"theme":"dark_glass","auto_restore_on_close":True,"refresh_interval_seconds":5}
def ensure_runtime_files():
    DATA_DIR.mkdir(exist_ok=True)
    LOG_DIR.mkdir(exist_ok=True)
    if not COMPANY_OUIS_FILE.exists():
        save_json(COMPANY_OUIS_FILE,DEFAULT_COMPANIES)
    if not DEFAULT_MAC_FILE.exists():
        save_json(DEFAULT_MAC_FILE,{})
    if not SETTINGS_FILE.exists():
        save_settings(DEFAULT_SETTINGS)
    if not LOG_FILE.exists():
        LOG_FILE.write_text("",encoding="utf-8")
def load_json(path,default):
    try:
        with open(path,"r",encoding="utf-8") as file:
            return json.load(file)
    except Exception:
        return default
def save_json(path,data):
    Path(path).parent.mkdir(exist_ok=True)
    with open(path,"w",encoding="utf-8") as file:
        json.dump(data,file,indent=4)
def write_text(path,text):
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    Path(path).write_text(text,encoding="utf-8")
def export_changes(source_path,target_path):
    records=load_json(source_path,[])
    if not records:
        return 0
    if Path(target_path).suffix.lower()==".json":
        save_json(target_path,records)
    else:
        lines=[f"{record.get('interface','N/A')} | {record.get('old_mac','N/A')} | {record.get('new_mac','N/A')}" for record in records]
        write_text(target_path,"\n".join(lines))
    return len(records)
def export_log(source_path,target_path,filter_text=None):
    path=Path(source_path)
    if not path.exists():
        return 0
    lines=path.read_text(encoding="utf-8",errors="ignore").splitlines()
    if filter_text:
        lines=[line for line in lines if filter_text in line]
    if not lines:
        return 0
    if Path(target_path).suffix.lower()==".json":
        save_json(target_path,lines)
    else:
        write_text(target_path,"\n".join(lines))
    return len(lines)
def append_change(path,iface,old_mac,new_mac):
    data=load_json(path,[])
    data.append({"interface":iface,"old_mac":old_mac,"new_mac":new_mac})
    save_json(path,data)
def load_default_macs():
    return load_json(DEFAULT_MAC_FILE,{})
def load_mac_profiles():
    return load_json(MAC_PROFILES_FILE,{})
def save_mac_profiles(profiles):
    save_json(MAC_PROFILES_FILE,profiles)
def get_profiles_for_interface(iface):
    profiles=load_mac_profiles()
    return profiles.get(iface,{})
def save_mac_profile(iface,name,mac):
    profiles=load_mac_profiles()
    profiles.setdefault(iface,{})[name]=mac
    save_mac_profiles(profiles)
def delete_mac_profile(iface,name):
    profiles=load_mac_profiles()
    if iface in profiles and name in profiles[iface]:
        profiles[iface].pop(name)
        if not profiles[iface]:
            profiles.pop(iface)
        save_mac_profiles(profiles)
def normalize_settings(settings):
    if not isinstance(settings,dict):
        settings={}
    data=DEFAULT_SETTINGS.copy()
    theme=settings.get("theme",data["theme"])
    data["theme"]=theme if theme in ["dark_glass","dark_compact","high_contrast"] else DEFAULT_SETTINGS["theme"]
    auto_restore=settings.get("auto_restore_on_close",data["auto_restore_on_close"])
    if isinstance(auto_restore,bool):
        data["auto_restore_on_close"]=auto_restore
    else:
        data["auto_restore_on_close"]=str(auto_restore).strip().lower() in ["1","true","yes","on"]
    try:
        refresh=int(settings.get("refresh_interval_seconds",data["refresh_interval_seconds"]))
    except Exception:
        refresh=DEFAULT_SETTINGS["refresh_interval_seconds"]
    data["refresh_interval_seconds"]=max(2,min(60,refresh))
    return data
def load_settings():
    raw=load_json(SETTINGS_FILE,{})
    settings=normalize_settings(raw)
    if raw!=settings:
        save_settings(settings)
    return settings
def save_settings(settings):
    normalized=normalize_settings(settings)
    save_json(SETTINGS_FILE,normalized)
    return normalized
def setup_logging():
    ensure_runtime_files()
    logging.basicConfig(filename=str(LOG_FILE),level=logging.INFO,format="%(asctime)s - %(message)s")
