import ctypes
import csv # creating csv file for RISK
from Evtx.Evtx import Evtx # allows us to read the evtx files to check them
import os # used to check if the output file already exists
import re # regular expression for pattern matching
import subprocess # used to run commands in the terminal so user does not have to run them manually
import sys # used to exit the program if there is an error
from windows_toasts import Toast, WindowsToaster # For notification purposes
import win32com.client
# Event log path
sys_log_channel = "Microsoft-Windows-Sysmon/Operational"
ps_log_channel = "Microsoft-Windows-PowerShell/Operational"

# all the files made
# Privillage change files and name
pr_log_file = "privilege.evtx"  
pr_output_file =  "privilege_report.csv"
pr_name = "Privilege Escalation"

# Macro finding files and name
macro_log_file = "office_macro.evtx"  
macro_output_file =  "macro_report.csv"
macro_name = "Macro Spawning"

# Command string matching files and name
match_log_file = "powershell_operational.evtx"
match_output_file = "pattern_matching_report.csv"
match_name = "Command Pattern Matching"

#Start-up files and names
start_log_file = "start_up.evtx" 
start_output_file =  "start_up_report.csv"
startup_name = "Start-up Folder"

# Milliseconds 
ms_hour = 60 * 60 * 1000

# Field types
ma_fieldname = ["Event ID", "Timestamp (UTC)", "Category" , "Risk Level", "Command"]
pr_fieldname = ["Event ID", "Timestamp (UTC)", "Category" , "Risk Level", "Expected Value", "Changed to", "Changed by"]
start_filedname = ["Event ID", "Timestamp (UTC)", "Category", "Risk Level", "Target", "Type", "Reason", "Signature Status"]

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

risk_low = ["ai.exe", "aimgr.exe","splwow64.exe"]

# Pattern Dictonary also used for start-up
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
    # shadowcopy in command
    ]

# Paths for where Run applications could be

run_folder = r"Start Menu\Programs\Startup"

# Baseline for the apps that are run at start-up
known_baseline = [
    r"C:\Program Files\Microsoft OneDrive"
    r"C:\Program Files (x86)\Microsoft" 
]

# Paths where safe apps are, as they require admin to be installed there
legitimate_path = [r"\Program Files", r"Program Files (x86)", r"Windows\System32"]

# paths where mallicious applications could be stored in
suspicious_path = [r"\Temp", r"\AppData\Local\Temp", r"\Downloads"]

# Runs code as admin for sysmon
def ensure_admin():
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False
    if not is_admin:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv) , None, 1)
        sys.exit(0)

# Function to check file against RULEBOOK and gives back reason and score
def check_rulebook(text):
    score = 0
    matched_labels = []

    for rule in RULEBOOK:
        if re.search(rule["pattern"], text, re.IGNORECASE):
            score += rule["score"]
            matched_labels.append(rule["label"])
            
    return matched_labels, score

# Checks the location of the path, determines if it is a safe location or not
def location(path):
    if any(location in path for location in suspicious_path):
        return "suspicious"
    if any(location in path for location in legitimate_path):
            return "safe"
    return "unrecognised"

# Checks if a particualr path is signed by a cetified authority
def check_signature(path):
    text = (f"(Get-AuthenticodeSignature -LiteralPath '{path}').Status")
    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        text
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        status = result.stdout.strip()
        return status 
    except Exception:
        return "Could not check"

# Checks where a shortcut links to
def shortcut_path(path):
    # This is a live test, therefore the file may have been deleted before the test was done
    # this returns none.
    if os.path.exists(path) == False:
        return None
    try:    
        shell = win32com.client.Dispatch("Wscript.Shell")
        shortcut = shell.CreateShortCut(path)
        return shortcut.TargetPath
    except Exception:
        return None

# make the hex into a number
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

            parent_name = os.path.basename(parent.group(1))
            image_name = os.path.basename(image.group(1))

            office = parent_name.upper() in office_app 
            if not office:
                continue

            event = event.group(1) if event else "unknown"
            time = time.group(1) + f" " + time.group(2) if time else "unknown"
            cmd = cmdline.group(1) if cmdline else "No command shown"

            child = image_name.lower() in risk_image
            if child:
                risk = "High"
                reason = f"Office app {parent_name} spwaned {image_name}"         
            else:
                low = image_name.lower() in risk_low
                if low:
                    continue
                else:
                    risk = "Medium"
                    reason = f"Office app {parent_name} spwaned {image_name}, not a recognised High risk child process."

            result = {
                "Event ID" : event,
                "Timestamp (UTC)" : time,
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
                "Timestamp (UTC)": time,
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
                "Timestamp (UTC)" : time,
                "Category" : target, 
                "Risk Level" : risk,
                "Expected Value" : safe_value,
                "Changed to" : details,
                "Changed by" : image,
                }
            
            all_results.append(result)

    return all_results

# Checks for any new files in the start up folders
def check_start_folder():

    evtx_file(sys_log_channel,start_log_file,eventID=11)

    all_results = []

    with Evtx(start_log_file) as log:

        for record in log.records():
            start = record.xml()

            event = re.search(r'<EventRecordID>(.*?)</EventRecordID>', start)
            time = re.search(r'<TimeCreated SystemTime="(.*?) (.*?)\..*?"></TimeCreated>', start)
            file= re.search(r'<Data Name="TargetFilename">(.*?)</Data>', start)

            if not file:
                continue


            file = file.group(1)
            # the code will also check temp files that would be created and show them too, 
            # however these temp files are part of creating shortcuts and therefore not needed
            if "tmp" in file.lower() or "new" in file.lower():
                continue

            if run_folder not in file:
                continue

            datetime = time.group(1) + f" " + time.group(2) if time else "unknown"
            event = event.group(1) if event else "unknown"

            reason = []
            score = 0

            if any( d in file for d in known_baseline):
                continue
            # if it is a link,
            shortcut = file.lower().endswith(".lnk")

            if not shortcut:
                target = file
                reason.append("Full script in Start-up")
                score += 4
                shortcut_file = "Direct file"
                sig_status = check_signature(file)
                if sig_status != "Valid":
                    score += 2

            else:
                target = shortcut_path(file)
                shortcut_file = "Shortcut"

                if target is None:
                # creates all the variables to be put in the csv file for not found
                    target = file
                    reason.append("Shortcut target not found, may have been deleted.")
                    score += 2
                    sig_status = "N/A not found"

                else:
                    sig_status = check_signature(target)
                    if sig_status != "Valid":
                        score += 2
                    location_result = location(target)
                    if location_result == "suspicious":
                        reason.append(f"Shortcut points to suspicious location: {target}")
                        score +=3
                    elif location_result == "unrecognised":
                        reason.append(f"Shortcut points to untested location: {target}")
                        score += 1
                    elif location_result == "safe":
                        reason.append("Shortcut is safe, please add to baseline.")
       
            if score >= 4:
                risk = "High"
            else:
                risk = "Medium"

            result = {
                "Event ID": event,
                "Timestamp (UTC)": datetime,
                "Source" : "Startup Folder",
                "Risk Level": risk,
                "Target": target,
                "Type": shortcut_file,
                "Reason": ", ".join(reason),
                "Signature Status": sig_status,
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

# Writes the new results into the csv files                    
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

    # Start up folder check
    start_result = check_start_folder()
    start_log = check_log_id(start_output_file)
    new_start = new_results(start_result,start_log,start_output_file,start_filedname)


    alerts = [
            {"New": len(new_macro),
             "Name":  macro_name,
             "Location": macro_output_file},
    
             {"New": len(new_match),
              "Name":  match_name,
              "Location": match_output_file},
    
             {"New": len(new_pr),
              "Name":  pr_name,
              "Location": pr_output_file},
            
            {"New": len(new_start),
             "Name":  startup_name,
             "Location":  start_output_file},
        ]
    
    notification = []
    where = []

    for alert in alerts:
        if alert["New"] > 0:
            notification.append(f"{alert['New']} {alert['Name']}")
            where.append(f"{alert['Location']}")

    notification_txt = " ".join(notification)
    where_txt = " ".join(where)

    if len(notification) == 0:
        nothing_new = WindowsToaster('Prototype')
        text = Toast()
        text.text_fields = ["No new suspicious commands found!"]
        nothing_new.show_toast(text)

    else:
        Some_found = WindowsToaster("Protype")
        text = Toast()
        text.text_fields = [f"Found {notification_txt} alerts! Full details in {where_txt}"]
        Some_found.show_toast(text)

if __name__ == "__main__":
    ensure_admin()
    main()