import hashlib
import subprocess
import re
from itertools import islice
from typing import List, Dict, Any, Iterable
# Configuration
SANDBOX_TIMEOUT = 30  # seconds for dynamic analysis
DYNAMIC_ANALYSIS_DIR = "/tmp/malware_analysis"


_JSON_RE = re.compile(
    r"```(?:json)?\s*|\s*```|^\s*json\s*|\s*$",  # fences / leading "json"
    re.IGNORECASE | re.MULTILINE
)

def _clean_json(raw: str) -> str:
    """
    Strip common wrappers so `json.loads` succeeds.
    Handles:
      • ```json ... ```
      • ``` ... ```
      • leading 'json' token
      • extra whitespace/new-lines
    """
    return _JSON_RE.sub("", raw).strip()

def batched(iterable: Iterable[Dict[str, Any]], size: int = 10) -> Iterable[List[Dict[str, Any]]]:
    """
    Yield successive `size`-sized chunks from *iterable*.
    """
    it = iter(iterable)
    while (chunk := list(islice(it, size))):      # stops when chunk is empty
        yield chunk

def calculate_file_hash(file_path: str) -> str:
    with open(file_path, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    return file_hash

def get_file_type(file_path: str) -> str:
    result = subprocess.run(['file', file_path], capture_output=True, text=True)
    return result.stdout.strip()

def decode_strings(strings: List[str]) -> Dict[str, List[str]]:
    decoded = {
        "base64": [],
        "rot13": [],
        "hex": []
    }
    
    for s in strings:
        # Skip very long strings
        if len(s) > 1000:
            continue
            
        # Base64 detection
        try:
            if len(s) % 4 == 0 and re.match(r'^[A-Za-z0-9+/]+={0,2}$', s):
                decoded_str = base64.b64decode(s).decode('utf-8', errors='ignore')
                if len(decoded_str) > 3:  # Minimum meaningful length
                    decoded["base64"].append(f"{s} -> {decoded_str}")
        except:
            pass
            
        # ROT13 detection
        rot13_str = codecs.decode(s, 'rot_13')
        if rot13_str != s and len(rot13_str) > 3:
            decoded["rot13"].append(f"{s} -> {rot13_str}")
            
        # Hex detection
        if re.match(r'^([0-9a-fA-F]{2})+$', s):
            try:
                hex_str = bytes.fromhex(s).decode('utf-8', errors='ignore')
                if len(hex_str) > 3:
                    decoded["hex"].append(f"{s} -> {hex_str}")
            except:
                pass
                
    return decoded

def get_elf_info(file_path: str) -> Dict[str, str]:
    try:
        result = subprocess.run(['readelf', '-h', file_path], capture_output=True, text=True)
        if result.returncode != 0:
            return {}
        elf_info = {}
        for line in result.stdout.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                elf_info[key.strip()] = value.strip()
        return elf_info
    except:
        return {}

def create_sandbox() -> str:
    os.makedirs(DYNAMIC_ANALYSIS_DIR, exist_ok=True)
    return tempfile.mkdtemp(dir=DYNAMIC_ANALYSIS_DIR)


def cleanup_sandbox(sandbox_dir: str):
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if sandbox_dir in ' '.join(proc.info['cmdline'] or []):
                    os.kill(proc.info['pid'], signal.SIGKILL)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        time.sleep(1)  # Give processes time to terminate
        subprocess.run(['rm', '-rf', sandbox_dir])
    except:
        pass