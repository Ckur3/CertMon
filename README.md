# CertMon
Python scripts used to monitor SSL Certificated due dates and weaknesses

domain_discovery.py needs a txt file (domains.txt) in input when launched. 
Domains.txt must be compiled with a list of TLDs (one for each line)

python3 domain_discovery.py -i domains.txt

After a while the python script will create 2 files:  discovered_urls.json  discovered_urls.txt

The txt will be used as input for the certmon.py file: python3 certmon.py -i discovered_urls.txt
After a while, 2 files will appear in the directory: ssl_report.csv  ssl_report.xlsx

Job done. Open the xlsx file and you'll find all the relevant data related to yours ssl certificates

# Prerequisites
sudo apt update && sudo apt install -y python3-pip python3-venv python3-full git
pip install requests beautifulsoup4 cryptography openpyxl





