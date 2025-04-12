Sheduled Vuln Scanner Tool
Overview
This is an Automated Vulnerability Scanning Tool built to check websites for security issues using OWASP ZAP (a popular security testing tool). It scans a target website, finds vulnerabilities (like SQL Injection or Cross-Site Scripting), saves the results in a database, and generates a PDF report with fixes. The tool can run manually or be scheduled to run automatically.

Purpose:
The purpose of this tool is to help web developers and security professionals identify and fix vulnerabilities in their websites.
-->Saves time by automating the scanning process.
-->Provides clear reports for developers or security teams.

Features:

-->Scans websites using OWASP ZAP.
-->Stores results in an SQLite database for easy tracking.
-->Creates a PDF report with vulnerability details and solutions.
-->Can be scheduled to run daily (optional).

Project Structure:

*scan_script.py: Handles the ZAP scanning process.
*report_generator.py: Creates the PDF report.
*database.py: Saves scan results to a database.
*README.md: This file with all instructions.

Requirements:

+ Python 3.10 or higher.
+ OWASP ZAP: Installed and running (download from OWASP ZAP Website).
+ Libraries: Install these with pip install zapv2 reportlab sqlite3 (sqlite3 is usually included with Python).
+ Git: To manage and upload the code (download from Git Website).
Implementation Steps
+ Option 1: Running Without Scheduler (Manual Mode)

This is the easiest way to run the tool step-by-step.

- Step 1: Set Up Your Computer
Install Python from Python Website.
Install OWASP ZAP and start it (use default settings, port 8080).
Open a terminal (Command Prompt on Windows).
- Step 2: Download the Code

Clone this repository:

git clone https://github.com/master8889/Sheduled_Vuln_Scanner_tool.git
cd Sheduled_Vuln_Scanner_tool
Or download the ZIP file from GitHub and unzip it.
Step 3: Install Libraries

In the terminal, run:

pip install zapv2 reportlab

Step 4: Configure the Target
Open scan_script.py in a text editor (e.g., Notepad).
Find this line: TARGET = 'http://juice-shop.herokuapp.com'.
Change it to the website you want to scan (e.g., TARGET = 'http://yourwebsite.com'). Only scan test sites like http://juice-shop.herokuapp.com unless you have permission.
Step 5: Run the Tool

In the terminal, type:

python scan_script.py

Watch the output—it will show scan progress and save a final_vuln_report.pdf and scan_results.db.

Step 6: Check Results

Open final_vuln_report.pdf to see vulnerabilities and fixes.
Use a tool like DB Browser for SQLite to open scan_results.db and view the data.

(optional)Focusing on Specific Vulnerabilities Before Attack via Scan Policy Manager:
1.Open OWASP ZAP 2.16.1 and ensure your target website (e.g., http://juice-shop.herokuapp.com) is loaded in the "Sites" tab.
2.Go to the top menu, click "Analyze" > "Scan Policy Manager."
3.In the Scan Policy Manager dialog, select the "Default Policy" and click "Modify."
4.In the Scan Policy dialog, expand the categories (e.g., "Injection," "Information Disclosure") to view individual rules.
5.Enable only the rules for the vulnerabilities you want to focus on (e.g., "SQL Injection" or "Cross-Site Scripting (XSS)") by setting their "Threshold" to "Medium" or "High" and "Strength" to "Low" or "Medium" to balance speed and accuracy.
6.Click "Save" to update the Default Policy, then close the dialog.
7.Run the scan with python scan_script.py to target only the selected vulnerabilities.
8.Review the results in the "Alerts" tab and the generated final_vuln_report.pd

Option 2: Running With Scheduler (Automatic Mode)

This sets the tool to run daily without manual effort.

Step 1: Set Up Task Scheduler (Windows)
Press Win + S, type “Task Scheduler,” and open it.

Click “Create Basic Task” on the right.
Name: Enter “Vuln Scanner Task”.
Trigger: Choose “Daily” and set the start time (e.g., 9:00 AM).
Action: Select “Start a Program”.
Program: Browse to python.exe (e.g., C:\Python310\python.exe).
Add Arguments: Type the full path to scan_script.py (e.g., C:\Users\krish\OneDrive\Desktop\Vuln_Scanner_Project\scan_script.py).
Finish: Click through and save. Enter your Windows password if asked.

Step 2: Test the Scheduler
Right-click the task in Task Scheduler and select “Run”.
Check if the PDF and database update.
If it fails, ensure ZAP is running and the file path is correct.

Step 3: Maintain
The tool will run daily at the set time.
Check the PDF and database regularly for new results.

Troubleshooting:

ZAP Not Connecting: Ensure ZAP is open on port 8080. Restart it if needed.

PDF Not Created: Check if reportlab is installed and the script ran fully.

Scheduler Fails: Verify the Python path and script path in Task Scheduler.

Future Enhancements:

Add a web dashboard to view results online.

Support more scanning tools (e.g., Nessus).

Add email notifications for new vulnerabilities.
