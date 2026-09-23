import re # string mattching
import csv # create csv file
import os 
import ctypes
import subprocess # to run commands 
import sys # for exit purposes
from Evtx.Evtx import Evtx # read event logs
from windows_toasts import InteractableWindowsToaster, Toast,  ToastButton, WindowsToaster # For notification purposes



macro_log_channel = "Microsoft-Windows-Sysmon/Operational"
macro_log_file = "office_macro.evtx"  
macro_output_file =  "macro_report.csv"

ms_hour = 60 * 60 * 1000

office_app = ["WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE"]

risk_child = [
    "powershell.exe", "cmd.exe", "sc.exe", "misexec.exe",
    "wmic.exe", "wscript.exe", "rundll32.exe", "reg.exe",
    "findstr.exe", "schtask.exe", "csc.exe", "wmic.exe",
    "mshta.exe", "cscript.exe",  "certutil.exe" 
    ]

# Baseline, macros that are used by the office apps 
risk_low = ["ai.exe","splwow64.exe"]
 
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

    query = f"*[System[(EventID=1) and TimeCreated[timediff(@SystemTime) <= {milisecond}]]]"

    command = [
        "wevtutil",
        "epl",
        macro_log_channel,
        macro_log_file,
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


def macro_file_reader():
    
    evtx_file()

    results = []

    with Evtx(macro_log_file) as log:

        for record in log.records():

            macros_text = record.xml()

            # Only checking for Office apps
            parent = re.search(r'<Data Name="ParentImage">(.*?)</Data>', macros_text)          
            image = re.search(r'<Data Name="Image">(.*?)</Data>', macros_text)
            cmdline = re.search(r'<Data Name="CommandLine">(.*?)</Data>', macros_text)
            time = re.search(r'<TimeCreated SystemTime="(.*?) (.*?)\..*?"></TimeCreated>', macros_text, re.DOTALL)
            id_match = re.search(r'<EventRecordID>(.*?)</EventRecordID>', macros_text)

            if not (parent and image):
                continue

            parent_name = os.path.basename(parent.group(1))
            image_name = os.path.basename(image.group(1))

            cmd = cmdline.group(1) if cmdline else "No command shown"

            datetime = time.group(1) + f" " + time.group(2) if time else "unknown"
            
            id_no = id_match.group(1) if id_match else "unknown"

            office_true = parent_name.upper() in office_app

            if not office_true:
                continue

            image_true = image_name.lower() in risk_child

            if image_true:
                risk = "High"
                reason = f"Office app {parent_name} spwaned {image_name}"

            else:
                image_low = image_name.lower() in risk_low
                if image_low:
                    continue
                else:
                    risk = "Medium"
                    reason = f"Office app {parent_name} spwaned {image_name}, not a recognised High risk child process."
            

            results.append({
                "Event ID": id_no,
                "Category": "Macro Processes Spawning",
                "Timestamp": datetime,
                "Risk Level": risk,
                "Reason": reason,
                "Command": cmd,
                })

    return results
           

def check_log_id():
    already_logged = set()

    if not os.path.exists(macro_output_file):
        return already_logged # no file was done before

    with open(macro_output_file, "r", newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            already_logged.add(row["Event ID"])
    return already_logged


def main():

    all_results = macro_file_reader()

    logged_id = check_log_id()

    new_result = []
    for r in all_results:
        if r["Event ID"] not in logged_id:
            new_result.append(r)

    if len(new_result) == 0:
        nothing_new = WindowsToaster('Macro')
        text = Toast()
        text.text_fields = ["No new suspicious commands found!"]
        nothing_new.show_toast(text)
        sys.exit(0)


    macro_csv = os.path.exists(macro_output_file)

    if all_results:
        with open(macro_output_file, "a", newline="", encoding="utf-8") as csvfile:
            result_writer = csv.DictWriter(csvfile,
                            fieldnames = ["Event ID", "Category", "Timestamp", "Risk Level", "Reason", "Command"])

            if not macro_csv:           
                result_writer.writeheader()
            result_writer.writerows(all_results)


        
        macros_found = WindowsToaster('Macros')
        text = Toast()
        text.text_fields = [f"Found {len(all_results)} suspicious macros! Full details in {macro_output_file}"]
        macros_found.show_toast(text)

        

    else:
        
        nothing_found = WindowsToaster('Macros')
        text = Toast()
        text.text_fields = ["No suspicious macros found!"]
        nothing_found.show_toast(text)

        
        

if __name__ == "__main__":
    ensure_admin()
    main()

        
    

            
