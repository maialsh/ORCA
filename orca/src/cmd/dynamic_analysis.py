# Dynamic analysis module - DISABLED by user request
# import docker
# import time
# import sys
# from pathlib import Path
# from typing import Optional, Dict, Any
# import json
# from typing import List, TypedDict, Annotated, Optional
# from langgraph.prebuilt import ToolNode, tools_condition
# # Check for Binary Ninja API
# BINARY_NINJA_PATH = "/Applications/Binary Ninja.app/Contents/Resources/python"
# if not os.path.exists(BINARY_NINJA_PATH):
#     print(f"Binary Ninja python API not found in expected folder: {BINARY_NINJA_PATH}")
#     sys.exit(1)
# sys.path.insert(0, BINARY_NINJA_PATH)
# from binaryninja import BinaryView, open_view, SymbolType
# from .state import AnalysisState

import sys
import os
from pathlib import Path
from typing import Optional, Dict, Any

class DockerDynamicAgent:
    """
    Dynamic analysis agent - DISABLED by user request
    Returns minimal results to maintain compatibility
    """

    def __init__(self, config: Dict[str, Any]):
        # Minimal initialization for compatibility
        self.image_name = config.get("image_name", "ubuntu:22.04")
        self.timeout = config.get("timeout", 30)
        print("⚠️  Dynamic analysis is disabled - DockerDynamicAgent will return minimal results")

    def analyze(self, file_path: Path) -> Dict[str, Any]:
        """Returns disabled status instead of performing analysis"""
        return {
            "syscalls": [],
            "processes": [],
            "files_created": [],
            "network": [],
            "errors": ["Dynamic analysis disabled by user request"],
            "status": "disabled"
        }

    def _is_process_running(self, container, process_name: str) -> bool:
        return False

    def _collect_results(self, container) -> Dict[str, Any]:
        return {"status": "disabled"}

# Original dynamic analysis code commented out:
# class DockerDynamicAgent:
#     """
#     A class to manage Docker containers for dynamic analysis of malware.
#     """
# 
#     def __init__(self, config: Dict[str, Any]):
#         self.image_name = config.get("image_name", "ubuntu:22.04")
#         self.client = docker.from_env()
#         self.timeout = config.get("timeout", 30)
# 
#     def analyze(self, file_path: Path) -> Dict[str, Any]:
#         results = {
#             "syscalls": [],
#             "processes": [],
#             "files_created": [],
#             "network": [],
#             "errors": []
#         }
#         try:
#             # Create a container
#             print(self.client.containers.list())
#             print(str(file_path.parent))
#             # exec_id = self.client.containers.run(self.image_name,"strace -h", privileged=True)
#             # print(exec_id)
#             container = self.client.containers.run(
#                 self.image_name,
#                 command="sleep infinity",
#                 detach=True,
#                 volumes={str(file_path.parent): {'bind': '/analysis', 'mode': 'ro'}},
#                 cap_drop=['ALL'],
#                 security_opt=['no-new-privileges'],
#                 network_mode='none',
#                 mem_limit='100m',
#                 cpu_quota=50000,
#                 pids_limit=50,
#                 read_only=False
#             )
#             try:
#                 # Copy the sample into container
#                 container.start()
#                 # container.exec_run(f"cp /analysis/{file_path.name} /tmp/sample")
#                 # container.exec_run("chmod +x /tmp/sample")
#                 #exec_id = container.exec_run("apt-get update -y", privileged=True)
#                 exec_id = container.exec_run(f"ls -l analysis/")
#                 # Start strace monitoring
#                 print("Helloo: ", exec_id)
#                 # exec_id = container.exec_run(
#                 #     "strace -f -o /tmp/strace.log /usr/bin/ls -l",
#                 #     detach=True,
#                 #     socket=True
#                 # )
#                 # print(exec_id)
#                 # Wait for completion or timeout
#                 start_time = time.time()
#                 while time.time() - start_time < self.timeout:
#                     print("Hellolo")
#                     if not self._is_process_running(container, "/tmp/sample"):
#                         break
#                     time.sleep(1)
# 
#                 # Collect results
#                 results.update(self._collect_results(container))
#             finally:
#                 container.stop(timeout=1)
#                 container.remove(force=True)
#         except Exception as e:
#             results["errors"].append(str(e))
#         return results
# 
#     def _is_process_running(self, container, process_name: str) -> bool:
#         try:
#             top = container.top()
#             return any(process_name in p for p in top.get('Processes', []))
#         except:
#             return False
# 
#     def _collect_results(self, container) -> Dict[str, Any]:
#         results = {}
#         # Get syscalls
#         exit_code, output = container.exec_run("cat /tmp/strace.log")
#         if exit_code == 0:
#             results["syscalls"] = output.decode('utf-8', errors='ignore').split('\n')[-100:]
#         # Get created files
#         _, files_output = container.exec_run("find /tmp -type f -newer /tmp/sample")
#         results["files_created"] = files_output.decode('utf-8', errors='ignore').split('\n')
#         return results
