import re # regular expression for pattern matching
import csv # creating csv file for RISK
import subprocess # used to run commands in the terminal so user does not have to run them manually
import sys # used to exit the program if there is an error
import os # used to check if the output file already exists
from Evtx.Evtx import Evtx # allows us to read the evtx files to check them
from windows_toasts import InteractableWindowsToaster, Toast,  ToastButton, WindowsToaster # For notification purposes

# First, create variables for creating the files

match_log_channel = "Microsoft-Windows-PowerShell/Operational"
# the log channel

match_log_file = "powershell_operational.evtx"
# the log file name, the files that gets checked

match_output_file = "pattern_matching_report.csv"
# the output file name, where the user can see all the HIGH RISK commands found


# Second, rulebook for pattern matching

RULEBOOK = [    
    {"label": "Command was Encoded",
     "pattern": r"-enc(odedcommand)?\b",
     "score": 4},
    # One way attckers can encode is using -enc
     
    {"label": "Command was Encoded",
     "pattern": r"--encryption",
     "score": 4},

    {"label": "Command downloaded Content from the web",
     "pattern": r"Invoke-WebRequest|wget|curl",
     "score": 3},
    # Downloaded content from commands, not normally done by SMEs without CS knowledge

    {"label": "Command executed text as script",
     "pattern": r"\biex\b|Invoke-Expression",
     "score": 3},

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

# Functions to create .evtx file
# Can give different arguments for event ID and times.

def evtx_file(hours=24):

    # query takes milisecond argument, default makes 24 hours
    
    milisecond = hours * 60 * 60 * 1000

    query = f"*[System[(EventID=4104) and TimeCreated[timediff(@SystemTime) <= {milisecond}]]]"

    command = [
        "wevtutil",
        "epl",
        match_log_channel,
        match_log_file,
        f"/q:{query}",
        "/ow:true"
    ]

    try:
        subprocess.run(command, check=True, capture_output=True, text=True)

    except subprocess.CalledProcessError as e:
        print(f"{e.stderr}")
        sys.exit(1)

    except FileNotFoundError:
        print("Error: File not found.")
        sys.exit(1)


# Function to check file against RULEBOOK and score

def check_rulebook(text):
    score = 0
    matched_labels = []

    for rule in RULEBOOK:
        if re.search(rule["pattern"], text, re.IGNORECASE):
            score += rule["score"]
            matched_labels.append(rule["label"])
            
    return matched_labels, score


# Function for reading the evtx file
def pattern_file_reader():

    evtx_file() 

    all_results = []

    with Evtx(match_log_file) as log:

        for record in log.records():

            # The event data is in xml format
            pattern_text = record.xml()

            # Get exactly only the ScriptBlock text from the xml
            argument_match = re.search(r'<Data Name="ScriptBlockText">(.*?)</Data>', pattern_text re.DOTALL)

            if not argument_match:
                continue

            argument = argument_match.group(1) 

            time_match = re.search(r'<TimeCreated SystemTime="(.*?) (.*?)\..*?"></TimeCreated>', pattern_text, re.DOTALL)

            if not time_match:
                datetime = "unknown"

            else: 
                datetime = time_match.group(1) + f" " + time_match.group(2) 

            id_match = re.search(r'<EventRecordID>(.*?)</EventRecordID>', pattern_text)

            if not id_match:
                id_match = "unknown"

            else:
                id_no = id_match.group(1)

            labels, score = check_rulebook(argument)

            if not labels:
                continue

            if score >= 4:
                risk = "High"
            elif score >= 2:
                risk = "Medium"
            else:
                risk = "Low"

            result = {
                "Event ID": id_no,
                "Label": labels,
                "Timestamp": datetime,
                "Risk Level": risk,
                "Score": score,
                "Full Script Text": argument,

                }

            all_results.append(result)

    return all_results

# function so things dont get logged multiple times
 
def check_log_id():
    already_logged = set()

    if not os.path.exists(match_output_file):
        return already_logged # no file was done before

    with open(match_output_file, "r", newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            already_logged.add(row["Event ID"])
    return already_logged
    

# Main
def main():
    
    all_results = pattern_file_reader()
    logged_id = check_log_id()

    new_result = []
    for r in all_results:
        if r["Event ID"] not in logged_id:
            new_result.append(r)

    if len(new_result) == 0:
        nothing_new = WindowsToaster('Pattern Matching')
        text = Toast()
        text.text_fields = ["No new suspicious commands found!"]
        nothing_new.show_toast(text)
        sys.exit(0)


    # if the csv file already exists
    already_csv = os.path.exists(match_output_file)

    
    with open(match_output_file, "a", newline="", encoding="utf-8") as csvfile:
        result_writer =csv.DictWriter(csvfile,
            fieldnames=["Event ID", "Label", "Timestamp", "Risk Level","Score","Full Script Text"])
        # if the file already exists, we want to keep a record of what has happened before

        if not already_csv:
            result_writer.writeheader()
        result_writer.writerows(new_result)

    Some_found = WindowsToaster('Pattern Matching')
    text = Toast()
    text.text_fields = [f"Found {len(new_result suspicious commands! Full details in {match_output_file}"]
    Some_found.show_toast(text)
        


             

if __name__ == "__main__":
    main()


