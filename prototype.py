import re 
import csv 
import subprocess
import ctypes
import sys 
import os 
from Evtx.Evtx import Evtx 
from windows_toasts import InteractableWindowsToaster, Toast,  ToastButton, WindowsToaster 

# Event log path
sys_log_channel = "Microsoft-Windows-Sysmon/Operational"
ps_log_channel = "Microsoft-Windows-PowerShell/Operational"

# all the files made
pr_log_file = "privilege.evtx"  
pr_output_file =  "privilege.csv"
pr_name = "privilege Escalation"

macro_log_file = "office_macro.evtx"  
macro_output_file =  "macro_report.csv"
macro_name = "Macro Spawning"

match_log_file = "powershell_operational.evtx"
match_output_file = "pattern_matching_report.csv"
match_name = "Pattern Matching"

# Milliseconds 
ms_hour = 60 * 60 * 1000

# Field types
ma_fieldname = ["Event ID", "Timestamp", "Category" , "Risk Level", "Command"]
pr_fieldname = ["Event ID", "Timestamp", "Category" , "Risk Level", "Expected Value", "Changed to", "Changed by"]

# Privilage Lists and Dictonary
UAC_rules = [
    {"name": "ConsentPromptBehaviorAdmin",
     "base_no": 5},
    {"name": "ConsentPromptBehaviorEnhancedAdmin",
     "base_no": 1},
    {"name": "ConsentPromptBehaviorUser",
     "base_no": 3},
    {"name": "EnableLUA",
     "base_no": 1},
    {"name": "PromptOnSecureDesktop",
     "base_no": 1},
     ]

# Macros Lists and Dictonary
office_app = ["WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE"]

risk_image = [
    "powershell.exe", "cmd.exe", "sc.exe", "misexec.exe",
    "wmic.exe", "wscript.exe", "rundll32.exe", "reg.exe",
    "findstr.exe", "schtask.exe", "csc.exe", "wmic.exe",
    "mshta.exe", "cscript.exe",  "certutil.exe" 
    ]

risk_low = ["ai.exe","splwow64.exe"]

# Pattern Dictonary
RULEBOOK = [    
    {"label": "Command was Encoded",
     "pattern": r"-enc(odedcommand)?\b",
     "score": 4},
    # One way attckers can encode is using -enc  
    {"label": "Command was Encoded",
     "pattern": r"--encryption",
     "score": 4},
    # Encryptions like the one before
    {"label": "Command downloaded Content from the web",
     "pattern": r"Invoke-WebRequest|wget|curl",
     "score": 3},
    # Downloaded content from commands, not normally done by SMEs without CS knowledge
    {"label": "Command executed text as script",
     "pattern": r"\biex\b|Invoke-Expression",
     "score": 3},
    # Texts is made into script
    {"label": "Powershell Window is Hidden",
     "pattern": r"-WindowStyle\s+Hidden",
     "score": 2},
    # Powershell window is hidden, attackers can avoid detection
    {"label": "Base64 Encoded Command",
     "pattern": r"FromBase64String",
     "score": 4},
    # Base64 can be used for encoding
    {"label": "Mimitakz installed on system",
     "pattern": r"mimikatz",
     "score": 4},
    # Mimikats is a tool used for credential dumping
    {"label": "Shadow Copies Deleted",
     "pattern": r"shadow(copy)",
     "score": 4},
    # Not sure about shadowcopy
    ]

# Runs code as admin for sysmon
def ensure_admin():
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False
    if not is_admin:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv) , None, 1)
        sys.exit(0)

# Function to check file against RULEBOOK and score
def check_rulebook(text):
    score = 0
    matched_labels = []

    for rule in RULEBOOK:
        if re.search(rule["pattern"], text, re.IGNORECASE):
            score += rule["score"]
            matched_labels.append(rule["label"])
            
    return matched_labels, score

# make the number into hex
def hex_int(detail):
    # matches the hex
    match = re.search(r'0x([0-9A-Fa-f]+)', detail)
    if not match:
        return None
    # returns it as a base 10 int from base 16
    return int(match.group(1),16)

# Creates evtx file
def evtx_file(log_channel,log_file,hours=24,eventID=None):

    # query takes milisecond argument, default makes 24 hours
    
    milisecond = hours * ms_hour

    query = f"*[System[(EventID={eventID}) and TimeCreated[timediff(@SystemTime) <= {milisecond}]]]"

    command = [
        "wevtutil",
        "epl",
        log_channel,
        log_file,
        f"/q:{query}",
        "/ow:true"
    ]

    try:
        subprocess.run(command, check=True, capture_output=True, text=True)

    except subprocess.CalledProcessError as error:
        print(f"{error.stderr}")
        sys.exit(1)

    except FileNotFoundError:
        print("Error: File not found.")
        sys.exit(1)

# Checks for macro parts of the event log
def macro_reader():
    evtx_file(sys_log_channel, macro_log_file,eventID=1)
    all_results = []

    with Evtx(macro_log_file) as log:
        for record in log.records():
            macro = record.xml()

            parent = re.search(r'<Data Name="ParentImage">(.*?)</Data>', macro)          
            image = re.search(r'<Data Name="Image">(.*?)</Data>', macro)
            cmdline = re.search(r'<Data Name="CommandLine">(.*?)</Data>', macro)
            event = re.search(r'<EventRecordID>(.*?)</EventRecordID>', macro)
            time = re.search(r'<TimeCreated SystemTime="(.*?) (.*?)\..*?"></TimeCreated>', macro)

            if not (parent and image):
                continue

            parent = os.path.basename(parent.group(1))
            image= os.path.basename(image.group(1))

            office = parent.upper() in office_app 
            if not office:
                continue

            event = event.group(1) if event else "unknown"
            time = time.group(1) + f" " + time.group(2) if time else "unknown"
            cmd = cmdline.group(1) if cmdline else "No command shown"

            child = image.lower() in risk_image
            if child:
                risk = "High"
                reason = f"Office app {parent} spwaned {image}"         
            else:
                low = image.lower() in risk_low
                if low:
                    continue
                else:
                    risk = "Medium"
                    reason = f"Office app {parent} spwaned {image}, not a recognised High risk child process."

            result = {
                "Event ID" : event,
                "Timestamp" : time,
                "Category": reason,
                "Risk Level" : risk,
                "Command" : cmd,
            }

            all_results.append(result)

    return all_results

# Checks for pattern matching parts of event log
def pattern_reader():
     evtx_file(ps_log_channel,match_log_file,eventID=4104)
     all_results = []

     with Evtx(match_log_file) as log:
         for record in log.records():
             
             pattern = record.xml()
             argument = re.search(r'<Data Name="ScriptBlockText">(.*?)</Data>', pattern)
             event = re.search(r'<EventRecordID>(.*?)</EventRecordID>', pattern)
             time = re.search(r'<TimeCreated SystemTime="(.*?) (.*?)\..*?"></TimeCreated>', pattern)

             if not argument:
                 continue                     
             argument = argument.group(1) 
             event = event.group(1) if event else "unknown"
             time = time.group(1) + f" " + time.group(2) if time else "unknown"

             label, score = check_rulebook(argument)
             if not label:
                 continue
             
             if score >= 4:
                 risk = "High"
             else:
                 risk = "Medium"

             result = {
                "Event ID": event,
                "Timestamp": time,
                "Category": label,    
                "Risk Level": risk,
                "Command": argument,
                }

             all_results.append(result)

     return all_results

# Checks for any privilege changes
def pr_reader():
    evtx_file(sys_log_channel,pr_log_file,eventID=13)
    all_results = []

    with Evtx(pr_log_file) as log:
        for record in log.records():
            privilege = record.xml()

            target = re.search(r'<Data Name="TargetObject">(.*?)</Data>', privilege)
            details = re.search(r'<Data Name="Details">(.*?)</Data>', privilege)
            image =  re.search(r'<Data Name="Image">(.*?)</Data>', privilege)    
            event = re.search(r'<EventRecordID>(.*?)</EventRecordID>', privilege)
            time = re.search(r'<TimeCreated SystemTime="(.*?) (.*?)\..*?"></TimeCreated>', privilege)
           
            if not (target and details):
                continue

            if not (target and details):
                continue
            target = os.path.basename(target.group(1))
            change = None
            for line in UAC_rules:
                if line["name"] == target:
                    safe_value = line["base_no"]
                    change = target
                    break
            # this is for any changes that we are not looking at
            if not change:
                continue

            details = hex_int(details.group(1))
            if details is None:
                continue
            if details == safe_value:
                continue

            image = os.path.basename(image.group(1)) if image else "unknown"    
            time = time.group(1) + f" " + time.group(2) if time else "unknown"
            event = event.group(1) if event else "unknown"

            if image in risk_image:
                risk = "High"
            else:
                risk = "Medium"

            result = {
                "Event ID" : event,
                "Timestamp" : time,
                "Category" : target, 
                "Risk Level" : risk,
                "Expected Value" : safe_value,
                "Changed to" : details,
                "Changed by" : image,
                }
            
            all_results.append(result)

    return all_results

# Checks if the event ID already there, so not writing twice
def check_log_id(output_file):
    already_logged = set()

    if not os.path.exists(output_file):
        return already_logged # no file was done before

    with open(output_file, "r", newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            already_logged.add(row["Event ID"])

    return already_logged
                    
def new_results(result,log,output_file,field_name):
    new_result = []
    for r in result:
        if r["Event ID"] not in log:
            new_result.append(r)
    if len(new_result) == 0:
        return new_result
    already_csv = os.path.exists(output_file)

    with open(output_file, "a", newline="", encoding="utf-8") as csvfile:
        result_writer =csv.DictWriter(csvfile,
            fieldnames=field_name)
        # if the file already exists, we want to keep a record of what has happened before
        if not already_csv:
            result_writer.writeheader()
        result_writer.writerows(new_result)

    return new_result

def main():
    print("Checking for new suspicious activity, this may take a while.")
    #Malicious Macro Spawning output
    macro_result = macro_reader()
    macro_log = check_log_id(macro_output_file)
    new_macro = new_results(macro_result,macro_log,macro_output_file,ma_fieldname)

    #Pattern Matching output
    match_result = pattern_reader()
    match_log = check_log_id(match_output_file)
    new_match =new_results(match_result,match_log,match_output_file,ma_fieldname)

    # Privilage Escalation output
    pr_result = pr_reader()
    pr_log = check_log_id(pr_output_file)
    new_pr = new_results(pr_result,pr_log,pr_output_file,pr_fieldname) 

    if len(new_macro) == 0 and len(new_match) == 0 and len(new_pr) == 0 :
        nothing_new = WindowsToaster("Protype")
        text = Toast()
        text.text_fields = ["No new suspicious alerts found!"]
        nothing_new.show_toast(text)

    else:
        Some_found = WindowsToaster("Protype")
        text = Toast()
        text.text_fields = [f"Found {len(new_macro)} {macro_name} alerts! Full details in {macro_output_file} \n Found {len(new_match)} {match_name} alerts! Full details in {match_output_file} \n Found {len(new_pr)} {pr_name} alerts! Full details in {pr_output_file}"]
        Some_found.show_toast(text)

if __name__ == "__main__":
    ensure_admin()
    main()
