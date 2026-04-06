# CertMon
Python scripts used to monitor SSL Certificates Status:due dates, misconfigurations and weaknesses

domain_discovery.py needs a txt file (domains.txt) in input when launched.
Domains.txt must be compiled with a list of TLDs (one for each line) that you want to monitor and check.

python3 domain_discovery.py -i domains.txt

After a while the python script will create 2 files:  discovered_urls.json  discovered_urls.txt

The txt will be used as input for the certmon.py file: python3 certmon.py -i discovered_urls.txt

Once the script has completed the analysis for all the URLs, on the screen will appear a message like this:

2026-04-06 09:43:22,164 [INFO] CSV saved → ssl_report.csv

2026-04-06 09:43:25,836 [INFO] XLSX saved → ssl_report.xlsx  (1518 rows, 764 flagged)

{
  "total_scanned": 1518,
  "expired": 65,
  "warning": 117,
  "ok": 582,
  "no_ssl_errors": 754,
  "csv": "ssl_report.csv",
  "xlsx": "ssl_report.xlsx"
}


Job done. Open ssl_report.xlsx and you'll find all the relevant data related to yours ssl certificates.



# Prerequisites
sudo apt update && sudo apt install -y python3-pip python3-venv python3-full git

pip install requests beautifulsoup4 cryptography openpyxl





