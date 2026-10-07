import ctypes
import csv # creating csv file for RISK
from Evtx.Evtx import Evtx # allows us to read the evtx files to check them
import os # used to check if the output file already exists
import re # regular expression for pattern matching
import subprocess # used to run commands in the terminal so user does not have to run them manually
import sys # used to exit the program if there is an error
from windows_toasts import InteractableWindowsToaster, Toast,  ToastButton, WindowsToaster # For notification purposes
import win32com.client

start_log_channel = "Microsoft-Windows-Sysmon/Operational"
start_log_file = "start_up.evtx"  
start_output_file =  "start_up_report.csv"

ms_hour = 60 * 60 * 1000

#fieldnames
start_filedname = ["Event ID", "Timestamp (UTC)", "Source", "Risk Level", "Target", "Type", "Reason", "Signature Status"]

run_registry = [ r"\Run", r"\RunOnce", r"CurrentVersion\Run", r"CurrentVersion\RunOnce"]
run_folder = r"Start Menu\Programs\Startup"

# all the apps that are known that start at start-up
known_baseline = [
    
]

# paths where admin rights are required for instalations
legitimate_path = [r"\Program Files", r"\Program Files (x86)", r"\Windows\System32"]

# paths where mallicious applications could be stored in
suspicious_path = [r"\Temp", r"\AppData\Local\Temp", r"\Downloads"]

RULEBOOK = [    
    {"label": "Command was Encoded",
     "pattern": r"-no-startup-window",
     "score": 4},
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

def check_rulebook(text):
    score = 0
    matched_labels = []

    for rule in RULEBOOK:
        if re.search(rule["pattern"], text, re.IGNORECASE):
            score += rule["score"]
            matched_labels.append(rule["label"])
            
    return matched_labels, score

def location(path):
    if any(location in path for location in suspicious_path):
        return "suspicious"
    if any(location in path for location in legitimate_path):
            return "safe"
    return "unrecognised"

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

def ensure_admin():
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False
    if not is_admin:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv) , None, 1)
        sys.exit(0)

def evtx_file(hours=24,event=None):

    # query takes milisecond argument, default makes 24 hours
    
    milisecond = hours * ms_hour

    query = f"*[System[(EventID={event}) and TimeCreated[timediff(@SystemTime) <= {milisecond}]]]"

    command = [
        "wevtutil",
        "epl",
        start_log_channel,
        start_log_file,
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

def check_registry_run():
    evtx_file(event=13)
    all_results = []
     
    with Evtx(start_log_file) as log:
        for record in log.records():
            
            start = record.xml()
            lnk = re.search(r'<Data Name="TargetObject">(.*?)</Data>', start)
            details = re.search(r'<Data Name="Details">(.*?)</Data>', start)
            event = re.search(r'<EventRecordID>(.*?)</EventRecordID>', start)
            time = re.search(r'<TimeCreated SystemTime="(.*?) (.*?)\..*?"></TimeCreated>', start)
            if not lnk:
                continue

            lnk = lnk.group(1)
            details = details.group(1)
            if not any( l in lnk for l in run_registry):
                continue
            if any( l in lnk for l in known_baseline):
                continue
            
            time = time.group(1) + f" " + time.group(2) if time else "unknown"
            event = event.group(1) if event else "unknown"

            score = 0
            reason = []

            # Other non paths non commands are kept in /Run such as DWORD, but they are not a path so
            # Have to check that it is a path
            if not re.search(r'\.(exe|dll|bat|cmd|com)\b(.*)', lnk, re.IGNORECASE):
                continue

            try:
                path, argument = details.split('" -')
                label, arg_score = check_rulebook(argument)
                reason.append(label)
                score += arg_score
                path_command = "Path followed by command"
            except ValueError:
                path = details

            if any( p in path for p in known_baseline):
                continue

            location_result = location(path.strip('"'))
            if location_result == "suspicious":
                reason.append("Target in Temp/AppData/Downloads")
                score += 4
            elif location_result == "unrecognised":
                reason.append("Not recognised as standard install path")
                score += 2
            else:
                sig_status = check_signature(path)
                result = {
                    "Event ID": event,
                    "Timestamp (UTC)": time,
                    "Source" : "Registry Run",
                    "Risk Level": "Low",
                    "Target": path,
                    "Type": path_command,
                    "Reason": "New safe star-up detected, please add it to baseline",
                    "Signature Status": sig_status,
                }
                all_results.append(result)
                continue

            sig_status = check_signature(path)
            if sig_status != "Valid":
                score += 2

            if score >= 4:
                risk = "High"
            else:
                risk = "Medium"
       

            result = {
                "Event ID": event,
                "Timestamp (UTC)": time,
                "Source" : "Registry Run",
                "Risk Level": risk,
                "Target": path,
                "Type": path_command,
                "Reason": ", ".join(reason),
                "Signature Status": sig_status,
            }

            all_results.append(result)

    return all_results

def check_start_folder():

    evtx_file(event=11)

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
    registry_result = check_registry_run()
    registry_log = check_log_id(start_output_file)
    new_registry = new_results(registry_result,registry_log,start_output_file,start_filedname)

    start_result = check_start_folder()
    start_log = check_log_id(start_output_file)
    new_start = new_results(start_result,start_log,start_output_file,start_filedname)

    alerts = [
        {"New": len(new_registry),
            "Name": "Start-up",
            "Location": start_output_file},
        
        {"New": len(new_start),
            "Name":  "Registry",
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

    if len(notification_txt) == 0:
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