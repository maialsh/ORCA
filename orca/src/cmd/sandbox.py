import docker
import time
from typing import Dict, Any, Optional
# Configuration
DOCKER_IMAGE = "ubuntu:22.04"  # Lightweight analysis container
DOCKER_TAG = "orca-sandbox"
SANDBOX_TIMEOUT = 30
DYNAMIC_ANALYSIS_DIR = "/analysis"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

# Initialize Docker client
import os
# Check if we're using Colima (macOS)
colima_socket = os.path.expanduser("~/.colima/default/docker.sock")
if os.path.exists(colima_socket):
    docker_client = docker.DockerClient(base_url=f"unix://{colima_socket}")
else:
    docker_client = docker.from_env()
# Docker sandbox management
class DockerSandbox:
    def __init__(self):
        self.container = None
        self.network_monitor = None

        
    def start(self, file_path: str) -> Optional[str]:
        try:
            # Create a volume mapping
            host_dir = os.path.dirname(os.path.abspath(file_path))
            sample_name = os.path.basename(file_path)

            # Get the directory containing this script (where Dockerfile is located)
            script_dir = os.path.dirname(os.path.abspath(__file__))
            
            image, build_logs = docker_client.images.build(
                path=script_dir,
                tag=DOCKER_TAG,
                rm=True,
                forcerm=True,)
            # Create container with limited capabilities using the built image
            self.container = docker_client.containers.run(
                DOCKER_TAG,
                command="sleep infinity",  # Keep container running
                detach=True,
                tty=True,
                volumes={host_dir: {'bind': DYNAMIC_ANALYSIS_DIR, 'mode': 'ro'}},
                tmpfs={'/tmp': 'rw,noexec,nosuid,size=100m'},  # Writable /tmp for analysis
                cap_drop=['ALL'],
                cap_add=['NET_RAW'],  # Only allow raw sockets for monitoring
                security_opt=['no-new-privileges'],
                network_mode='none',  # No network access
                mem_limit='512m',  # 512mb memory limit
                cpu_quota=50000,  # Limit CPU
                pids_limit=100,  # Limit processes
                read_only=True
            )
            
            # Copy sample into container with error handling
            # Note: strace and readelf are already installed in the Docker image
            copy_result = self.container.exec_run(f"cp {DYNAMIC_ANALYSIS_DIR}/{sample_name} /tmp/sample")
            if copy_result.exit_code != 0:
                error_msg = f"Failed to copy sample file: {copy_result.output.decode('utf-8', errors='ignore')}"
                print(error_msg)
                return error_msg
            
            chmod_result = self.container.exec_run("chmod +x /tmp/sample")
            if chmod_result.exit_code != 0:
                error_msg = f"Failed to make sample executable: {chmod_result.output.decode('utf-8', errors='ignore')}"
                print(error_msg)
                return error_msg
            
            # Verify the file exists and is executable
            verify_result = self.container.exec_run("ls -la /tmp/sample")
            if verify_result.exit_code != 0:
                error_msg = "Sample file was not copied successfully"
                print(error_msg)
                return error_msg
            
            print(f"Sample file copied successfully: {verify_result.output.decode('utf-8', errors='ignore').strip()}")
            
            return None
        except Exception as e:
            print(f"Error starting Docker container: {str(e)}")
            return str(e)
    
    def run_analysis(self) -> Dict[str, Any]:
        if not self.container:
            return {"error": "Container not initialized"}
            
        results = {
            "syscalls": [],
            "network": [],
            "files": [],
            "processes": [],
            "errors": []
        }
        
        try:
            # Verify sample file exists before running analysis
            verify_result = self.container.exec_run("test -f /tmp/sample")
            if verify_result.exit_code != 0:
                results["errors"].append("Sample file not found in container")
                return results
            # assign executable permissions to the sample
            perms_cmd = f"chmod +u /tmp/sample"
            exec_id = self.container.exec_run(
                perms_cmd,
                detach=True,
                socket=True
            )
            # Start strace for syscall monitoring
            strace_cmd = f"strace -f -o /tmp/strace.log /tmp/sample"
            exec_id = self.container.exec_run(
                strace_cmd,
                detach=True,
                socket=True
            )
            
            # Monitor for timeout
            start_time = time.time()
            while time.time() - start_time < SANDBOX_TIMEOUT:
                # Check if process is still running
                processes = self.container.top().get('Processes', [])
                sample_running = any("/tmp/sample" in p for p in processes)
                
                if not sample_running:
                    break
                
                time.sleep(1)
            
            # Get strace results
            exit_code, strace_output = self.container.exec_run("cat /tmp/strace.log")
            if exit_code == 0:
                results["syscalls"] = strace_output.decode('utf-8', errors='ignore').split('\n')[-100:]  # Last 100 lines
            else:
                results["errors"].append("Failed to read strace log")
            
            # Get file changes
            _, files_output = self.container.exec_run("find /tmp -type f -newer /tmp/sample")
            results["files"] = files_output.decode('utf-8', errors='ignore').split('\n')
            
            # Get process list
            results["processes"] = processes
            
        except Exception as e:
            print(f"Error during analysis: {str(e)}")
            results["errors"].append(str(e))
        finally:
            return results
    
    def cleanup(self):
        if self.container:
            try:
                self.container.stop(timeout=1)
                self.container.remove()
            except:
                pass

if __name__ == "__main__":
    import sys
    dockers = DockerSandbox()
    dockers.start(sys.argv[1])
    res = dockers.run_analysis()
    print(res)
    dockers.cleanup()
