import time
import subprocess
from common import stop_event
import frida

CDB_PATH = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"

def run_cdb_command(proc, command):
    proc.stdin.write(command + "\n")
    proc.stdin.flush()
    output = []
    while True:
        line = proc.stdout.readline()
        if not line: 
            continue
        output.append(line)
        if line.startswith("0:"): 
            break
    return output


def process_cdb(pid):
    cmd = [CDB_PATH, "-p", str(pid)]
    addr_cmd = "x kernelbase!GetProcAddress"
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

    output = run_cdb_command(proc, addr_cmd)
    address = None
    for line in output:
        if "KERNELBASE!GetProcAddress" in line:
            address = line.split()[1]
            break

    if address:
        print("Extracted Address:", address)

        bp_cmd = f"bp {address}"
        proc.stdin.write(bp_cmd+"\n")
        proc.stdin.flush()
        print(f"Setting breakpoint at {address}")
        
        proc.stdin.write("g\n")
        proc.stdin.flush()


        try:
            while not stop_event.is_set():
                output = proc.stdout.readline().strip()
                if output:
                    print(output)
                    if ("breakpoint" in output.lower()) or ("single step exception" in output.lower()) or ("80000003" in output):
                        time.sleep(0.1)
                        proc.stdin.write("g\n")
                        proc.stdin.flush()
            proc.stdin.write("qd\n")
            proc.stdin.flush()
        except KeyboardInterrupt:
            proc.terminate()
            exit(1)
    else:
        print("Failed to extract address from the output")
