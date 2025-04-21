import os
import subprocess
import sys
import argparse
import logging
import shutil
import unittest

# Use an environment variable to optionally override the virtual environment directory.
VENV_DIR = os.environ.get('VENV_DIR', 'myenv')
VENV_BIN_DIR = os.path.join(VENV_DIR, 'bin')

# Set up logging to output to both console and a file.
logger = logging.getLogger()
logger.setLevel(logging.INFO)
formatter = logging.Formatter('[%(levelname)s] %(message)s')

# Console handler.
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(formatter)
logger.addHandler(ch)

# File handler.
fh = logging.FileHandler('auto_setup.log')
fh.setFormatter(formatter)
logger.addHandler(fh)

def validate_file(path, description):
    """Check that a file exists; exit if it does not."""
    if not os.path.isfile(path):
        logger.error(f'Missing required {description}: {path}')
        sys.exit(1)
    logger.info(f'{description.capitalize()} {path} is present')

def create_virtual_env(force=False, dry_run=False):
    """Create a virtual environment. If force is True, remove any existing env."""
    if force and os.path.exists(VENV_DIR):
        logger.info('Force option enabled: Removing existing virtual environment.')
        if not dry_run:
            shutil.rmtree(VENV_DIR)
        else:
            logger.info(f'[Dry-run] Would remove directory: {VENV_DIR}')
    try:
        if not os.path.exists(VENV_DIR):
            if dry_run:
                logger.info(f'[Dry-run] Would create virtual environment in {VENV_DIR}')
            else:
                subprocess.check_call([sys.executable, '-m', 'venv', VENV_DIR])
                logger.info('Virtual environment was created successfully')
        else:
            logger.info('Virtual environment already exists')
    except Exception as e:
        logger.error(f'Failed to create virtual environment: {e}')
        sys.exit(1)

def install_libraries(lib_file, dry_run=False):
    """Install libraries listed in the provided file."""
    try:
        with open(lib_file, 'r') as f:
            libraries = [line.strip() for line in f if line.strip()]
        if not libraries:
            logger.error(f'No libraries listed in {lib_file}')
            sys.exit(1)
        pip_path = os.path.join(VENV_BIN_DIR, 'pip')
        upgrade_cmd = [pip_path, 'install', '--upgrade', 'pip']
        if dry_run:
            logger.info(f'[Dry-run] Would run: {" ".join(upgrade_cmd)}')
        else:
            subprocess.check_call(upgrade_cmd)
        for library in libraries:
            install_cmd = [pip_path, 'install', library]
            if dry_run:
                logger.info(f'[Dry-run] Would run: {" ".join(install_cmd)}')
            else:
                try:
                    subprocess.check_call(install_cmd)
                    logger.info(f'{library} installed successfully')
                except subprocess.CalledProcessError as e:
                    logger.error(f'Failed to install {library}: {e}')
    except Exception as e:
        logger.error(f'Failed to process library file {lib_file}: {e}')
        sys.exit(1)

def run_script(script_file, extra_args=None, dry_run=False):
    """Run the target script as a detached background process so that it continues running after terminal closure."""
    python_executable = os.path.join(VENV_BIN_DIR, 'python')
    command = [python_executable, script_file]
    if extra_args:
        command.extend(extra_args)
    
    if dry_run:
        logger.info(f'[Dry-run] Would run in detached mode: {" ".join(command)}')
        return

    try:
        # Launch process in detached mode by starting a new session.
        process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
            close_fds=True
        )
        logger.info(f'Script {script_file} launched in detached mode with PID: {process.pid}')
    except Exception as e:
        logger.error(f'Failed to run script {script_file} in detached mode: {e}')

def parse_arguments():
    parser = argparse.ArgumentParser(description='Auto Setup and Run Script')
    parser.add_argument('-f', '-F', dest='script_file',
                        help='Path to the script to run (not needed for --test)')
    parser.add_argument('-l', '-L', dest='lib_file', default=None,
                        help='Path to the file containing libraries (optional)')
    parser.add_argument('--force', action='store_true',
                        help='Force re-creation of the virtual environment')
    parser.add_argument('--dry-run', action='store_true',
                        help='Simulate the actions without making any changes')
    parser.add_argument('--extra', nargs=argparse.REMAINDER, dest='extra_args',
                        help='Extra arguments to pass to the target script')
    parser.add_argument('--test', action='store_true',
                        help='Run unit tests')
    return parser.parse_args()

# Basic unit tests for some of the functions.
class TestAutoSetup(unittest.TestCase):
    def test_validate_file_nonexistent(self):
        # validate_file should exit if the file does not exist.
        with self.assertRaises(SystemExit):
            validate_file("nonexistent_file.txt", "test file")
    # Additional tests could be added for functions that don't require system changes.

def run_tests():
    suite = unittest.TestLoader().loadTestsFromTestCase(TestAutoSetup)
    unittest.TextTestRunner(verbosity=2).run(suite)

def main():
    args = parse_arguments()
    if args.test:
        run_tests()
        return

    if not args.script_file:
        logger.error("No script file specified. Use the -f flag followed by the script file path.")
        sys.exit(1)

    validate_file(args.script_file, 'script file')
    if args.lib_file:
        validate_file(args.lib_file, 'library file')
    
    create_virtual_env(force=args.force, dry_run=args.dry_run)
    if args.lib_file:
        install_libraries(args.lib_file, dry_run=args.dry_run)
    run_script(args.script_file, extra_args=args.extra_args, dry_run=args.dry_run)

if __name__ == '__main__':
    main()
