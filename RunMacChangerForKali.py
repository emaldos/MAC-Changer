import argparse
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
ROOT_DIR=Path(__file__).resolve().parent
VENV_DIR=Path(os.environ.get("VENV_DIR","myenv"))
if not VENV_DIR.is_absolute():
    VENV_DIR=ROOT_DIR/VENV_DIR
VENV_BIN_DIR=VENV_DIR/("Scripts" if os.name=="nt" else "bin")
PYTHON_EXE=VENV_BIN_DIR/("python.exe" if os.name=="nt" else "python")
PIP_EXE=VENV_BIN_DIR/("pip.exe" if os.name=="nt" else "pip")
logger=logging.getLogger("mac_changer_setup")
logger.setLevel(logging.INFO)
formatter=logging.Formatter("[%(levelname)s] %(message)s")
if not logger.handlers:
    console_handler=logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    file_handler=logging.FileHandler(ROOT_DIR/"auto_setup.log")
    file_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
def resolve_path(path):
    value=Path(path)
    return value if value.is_absolute() else ROOT_DIR/value
def validate_file(path,description):
    if not path.is_file():
        logger.error(f"Missing required {description}: {path}")
        sys.exit(1)
    logger.info(f"{description.capitalize()} {path} is present")
def create_virtual_env(force=False):
    if force and VENV_DIR.exists():
        shutil.rmtree(VENV_DIR)
    if not VENV_DIR.exists():
        subprocess.check_call([sys.executable,"-m","venv",str(VENV_DIR)],cwd=str(ROOT_DIR))
        logger.info(f"Virtual environment created: {VENV_DIR}")
    else:
        logger.info(f"Virtual environment already exists: {VENV_DIR}")
def install_libraries(lib_file):
    subprocess.check_call([str(PIP_EXE),"install","--upgrade","pip"],cwd=str(ROOT_DIR))
    subprocess.check_call([str(PIP_EXE),"install","-r",str(lib_file)],cwd=str(ROOT_DIR))
    logger.info(f"Requirements installed from {lib_file}")
def run_script(script_file,extra_args=None,foreground=False):
    command=[str(PYTHON_EXE),str(script_file)]
    if extra_args:
        command.extend(extra_args)
    if foreground:
        logger.info(f"Running {script_file}")
        sys.exit(subprocess.call(command,cwd=str(ROOT_DIR)))
    process=subprocess.Popen(command,cwd=str(ROOT_DIR),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,close_fds=True)
    logger.info(f"Script {script_file} launched with PID: {process.pid}")
def parse_arguments():
    parser=argparse.ArgumentParser(description="Setup and run Kali MAC Changer")
    parser.add_argument("-f","-F",dest="script_file",default="MAC_Changer.py")
    parser.add_argument("-l","-L",dest="lib_file",default="requirements.txt")
    parser.add_argument("--force",action="store_true")
    parser.add_argument("--foreground",action="store_true")
    parser.add_argument("--extra",nargs=argparse.REMAINDER,dest="extra_args")
    return parser.parse_args()
def main():
    args=parse_arguments()
    script_file=resolve_path(args.script_file)
    lib_file=resolve_path(args.lib_file)
    validate_file(script_file,"script file")
    validate_file(lib_file,"library file")
    create_virtual_env(args.force)
    install_libraries(lib_file)
    run_script(script_file,args.extra_args,args.foreground)
if __name__=="__main__":
    main()
