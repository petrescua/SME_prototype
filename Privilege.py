import re # regular expression for pattern matching
import csv # creating csv file for RISK
import subprocess # used to run commands in the terminal so user does not have to run them manually
import ctypes
import sys # used to exit the program if there is an error
import os # used to check if the output file already exists
from Evtx.Evtx import Evtx # allows us to read the evtx files to check them
from windows_toasts import InteractableWindowsToaster, Toast,  ToastButton, WindowsToaster # For notification purposes



pr_log_channel = "Microsoft-Windows-Sysmon/Operational"
pr_log_file = "privilage.evtx"  
pr_output_file =  "privilage.csv"

ms_hour = 60 * 60 * 1000

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

processes = ["powershell.exe", "cmd.exe", "reg.exe", "wmic.exe"]


def ensure_admin():
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False
    if not is_admin:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv) , None, 1)
        sys.exit(0)


def evtx_file(hours=24):

    # query takes milisecond argument, default makes 24 hours
    
    milisecond = hours * ms_hour

    query = f"*[System[(EventID=13) and TimeCreated[timediff(@SystemTime) <= {milisecond}]]]"

    command = [
        "wevtutil",
        "epl",
        pr_log_channel,
        pr_log_file,
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

def hex_int(detail):
    # matches the hex
    match = re.search(r'0x([0-9A-Fa-f]+)', detail)
    if not match:
        return None
    # returns it as a base 10 int from base 16
    return int(match.group(1),16)


def pr_file_reader():

    evtx_file()

    all_results = []

    with Evtx(pr_log_file) as log:

        for record in log.records():

            pr_text = record.xml()

            event = re.search(r'<EventRecordID>(.*?)</EventRecordID>', pr_text)
            target = re.search(r'<Data Name="TargetObject">(.*?)</Data>', pr_text)
            details = re.search(r'<Data Name="Details">(.*?)</Data>', pr_text)
            time = re.search(r'<TimeCreated SystemTime="(.*?) (.*?)\..*?"></TimeCreated>', pr_text)
            image =  re.search(r'<Data Name="Image">(.*?)</Data>', pr_text)

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
                  
            datetime = time.group(1) + f" " + time.group(2) if time else "unknown"
            image = os.path.basename(image.group(1)) if image else "unknown"
            event = event.group(1) if event else "unknown"

            if image in processes:
                risk = "High"
            else:
                risk = "Medium"

            result = {
                "Event ID" : event,
                "Category" : target,
                "Timestamp" : datetime,
                "Risk Level" : risk,
                "Expected Value" : safe_value,
                "Changed Value" : details,
                "Changed By" : image,
                }
            
            all_results.append(result)

    return all_results

def check_log_id():
    already_logged = set()

    if not os.path.exists(pr_output_file):
        return already_logged # no file was done before

    with open(pr_output_file, "r", newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            already_logged.add(row["Event ID"])
    return already_logged



def main():

    all_results = pr_file_reader()
    logged_id = check_log_id()

    new_result = []
    for r in all_results:
        if r["Event ID"] not in logged_id:
            new_result.append(r)

    if len(new_result) == 0:
        nothing_new = WindowsToaster('Privilage Escalation')
        text = Toast()
        text.text_fields = ["No new suspicious alerts found!"]
        nothing_new.show_toast(text)
        sys.exit(0)

    already_csv = os.path.exists(pr_output_file)

    with open(pr_output_file, "a", newline="", encoding="utf-8") as csvfile:
        result_writer =csv.DictWriter(csvfile,
            fieldnames=["Event ID", "Category", "Timestamp", "Risk Level","Expected Value","Changed Value","Changed By"])
        # if the file already exists, we want to keep a record of what has happened before

        if not already_csv:
            result_writer.writeheader()
        result_writer.writerows(new_result)

    Some_found = WindowsToaster('Privilage Escalation')
    text = Toast()
    text.text_fields = [f"Found {len(new_result)} suspicious alerts! Full details in {pr_output_file}"]
    Some_found.show_toast(text)
        
          

if __name__ == "__main__":
    ensure_admin()
    main()
