from importlib import import_module
from tarfile import RECORDSIZE
from urllib import response
from simple_term_menu import TerminalMenu
from dotenv import load_dotenv
import requests
import json 
import time
import pycurl
import re
import hashlib
import os
import signal
#comment
#comment2
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


load_dotenv()

def mailCheck(mail): 
  #haveıbeenpwned legit paid api

  url = "https://haveibeenpwned.com/api/v3/breachedaccount/{0}?truncateResponse=false".format(mail)
  hibp_api_key = os.getenv('hibp_api_key')
  payload={}
  headers = {
    'hibp-api-key': str(hibp_api_key),
    'format': 'application/json',
    'timeout': '2.5',
    'HIBP': str(hibp_api_key),
  }

  response = requests.request("GET", url, headers=headers, data=payload)

  if not response:
      data=""
      print(f"\n {bcolors.OKGREEN} Good news — no pwnage found!{bcolors.ENDC}")
  else:
    data = response.json()
    print(f"\n {bcolors.BOLD}Breach Info for:{bcolors.ENDC} {bcolors.OKGREEN}{mail}{bcolors.ENDC}\n")
  #print(data)
  
  counter=0
  for i in data:
    data[counter].pop('Description')
    print(f"{bcolors.OKBLUE}Date{bcolors.ENDC} : {bcolors.BOLD}{data[counter]['BreachDate']}{bcolors.ENDC}")
    print(f"{bcolors.OKGREEN}Name{bcolors.ENDC} : {bcolors.BOLD}{data[counter]['Name']}{bcolors.ENDC}")
    print(f"{bcolors.HEADER}Domain{bcolors.ENDC} : {bcolors.BOLD}{data[counter]['Domain']}{bcolors.ENDC}")
    print(f"{bcolors.BOLD}--Leaked Info--{bcolors.ENDC}")
    for j in data[counter]['DataClasses']:
      if(j=="Passwords"):
        print(bcolors.FAIL,bcolors.BOLD,j,bcolors.ENDC, sep=' ', end=' ', flush=True )
      else:
        print(bcolors.WARNING,j,bcolors.ENDC, sep=' ', end=' ', flush=True )
    print("\n") 
    counter+=1
 
def unshorten(shortUrl):
  #public api
  url = "https://unshorten.me/json/{0}".format(shortUrl)
  payload={}
  headers = {}
  response = requests.request("GET", url, headers=headers, data=payload)

  if not response:
    data=""
  else:
    data = response.json()
    
  
  if (data["success"] == True):
    return print(f"\n URL --> {bcolors.OKGREEN}{data['resolved_url']}{bcolors.ENDC} {bcolors.WARNING}{bcolors.BOLD}\n Remaining Calls --> {data['remaining_calls']}{bcolors.ENDC}")
  else:
    return print(f"{bcolors.FAIL}{bcolors.BOLD}\n error: ! URL not found !{bcolors.ENDC}")

def ipReputation(ip):
  #IP reputation, geoip and detect VPN in RapidAPI 500 call per month

  url = "https://ip-reputation-geoip-and-detect-vpn.p.rapidapi.com/"

  querystring = {"ip":"{0}".format(ip)}
  
  headers = {
  	"X-RapidAPI-Key": os.getenv('rapidapi'),
  	"X-RapidAPI-Host": "ip-reputation-geoip-and-detect-vpn.p.rapidapi.com"
  }

  response = requests.request("GET", url, headers=headers, params=querystring)

  if not response:
    data=""
  else:
    data = response.json()
  
  
  if data['risk']<=50:
    print(f"\n IP: {bcolors.OKGREEN}{data['ip']}{bcolors.ENDC}")
    print(f" Risk: {bcolors.OKGREEN}%{data['risk']}{bcolors.ENDC}")
    print(f" Risk Level: {bcolors.OKGREEN}{data['risk_level']}{bcolors.ENDC}")
    print(f" Message: {bcolors.OKBLUE}{data['message']}{bcolors.ENDC}")
    print(f" Country: {bcolors.OKBLUE}{data['country']}{bcolors.ENDC}")
    print(f" City: {bcolors.OKBLUE}{data['city']}{bcolors.ENDC}")
    print(f" Organization: {bcolors.OKBLUE}{data['organization']}{bcolors.ENDC}")
    print(f" Domain: {bcolors.OKBLUE}{data['domain']}{bcolors.ENDC}")
    
  elif data['risk']>50:
    print(f"\n IP: {bcolors.FAIL}{data['ip']}{bcolors.ENDC}")
    print(f" Risk: {bcolors.FAIL}%{data['risk']}{bcolors.ENDC}")
    print(f" Risk Level: {bcolors.FAIL}{data['risk_level']}{bcolors.ENDC}")
    print(f" Message: {bcolors.WARNING}{data['message']}{bcolors.ENDC}")
    print(f" Country: {bcolors.WARNING}{data['country']}{bcolors.ENDC}")
    print(f" City: {bcolors.WARNING}{data['city']}{bcolors.ENDC}")
    print(f" Organization: {bcolors.WARNING}{data['organization']}{bcolors.ENDC}")
    print(f" Domain: {bcolors.WARNING}{data['domain']}{bcolors.ENDC}")
  
  print(f" Anonymizer: {bcolors.HEADER}{data['anonymizer']}{bcolors.ENDC}")
  print(f" VPN Proxy: {bcolors.HEADER}{data['is_vpn_proxy']}{bcolors.ENDC}")
  print(f" Malicious: {bcolors.HEADER}{data['is_malicious']}{bcolors.ENDC}")
  print(f" Abusive: {bcolors.HEADER}{data['is_abusive']}{bcolors.ENDC}")
  print(f" Tor: {bcolors.HEADER}{data['is_tor']}{bcolors.ENDC}")
  
  return

def dns(domain):
#Whois Lookup Domain Information 500 call per month
  url = "https://zozor54-whois-lookup-v1.p.rapidapi.com/"

  querystring = {"domain": domain,"format":"json"}

  headers = {
  	"X-RapidAPI-Key": os.getenv('rapidapi'),
  	"X-RapidAPI-Host": "zozor54-whois-lookup-v1.p.rapidapi.com"
  }

  response = requests.request("GET", url, headers=headers, params=querystring)

  if not response:
    data=""
  else:
    data = response.json()
    data.pop("rawdata")
    data.pop("contacts")
  
  
  for i in data:
    if type(data[i]) == str :
      print(f"{bcolors.OKBLUE}{i}{bcolors.ENDC} : {bcolors.BOLD}{data[i]}{bcolors.ENDC}")
    
def nslookup(domain):
  #DNS Lookup 500 call per month

  url = "https://dns-lookup5.p.rapidapi.com/simple"

  querystring = {"domain": domain,"recordType":"NS"}

  headers = {
  	"X-RapidAPI-Key": os.getenv('rapidapi'),
  	"X-RapidAPI-Host": "dns-lookup5.p.rapidapi.com"
  }

  response = requests.request("GET", url, headers=headers, params=querystring)

  if not response:
    data=""
  else:
    data = response.json()
  
  for i in range(len(data["records"])):
    print(f"{bcolors.HEADER}NS{bcolors.ENDC}  : {bcolors.BOLD}{data['records'][i]['data']}{bcolors.ENDC}")
  
  time.sleep(1)
  url = "https://dns-lookup5.p.rapidapi.com/simple"

  querystring = {"domain": domain,"recordType":"A"}

  headers = {
  	"X-RapidAPI-Key": os.getenv('rapidapi'),
  	"X-RapidAPI-Host": "dns-lookup5.p.rapidapi.com"
  }

  response2 = requests.request("GET", url, headers=headers, params=querystring)

  if not response:
    data2=""
  else:
    data2 = response2.json()


  for i in range(len(data2["records"])):
    print(f"{bcolors.OKGREEN}A{bcolors.ENDC}   : {bcolors.BOLD}{data2['records'][i]['data']}{bcolors.ENDC}")

  time.sleep(1)
  url = "https://dns-lookup5.p.rapidapi.com/simple"

  querystring = {"domain": domain,"recordType":"AAAA"}

  headers = {
  	"X-RapidAPI-Key": os.getenv('rapidapi'),
  	"X-RapidAPI-Host": "dns-lookup5.p.rapidapi.com"
  }

  response3 = requests.request("GET", url, headers=headers, params=querystring)

  if not response3:
    data3=""
  else:
    data3 = response3.json()

  for i in range(len(data3["records"])):
    print(f"{bcolors.OKCYAN}AAAA{bcolors.ENDC}: {bcolors.BOLD}{data3['records'][i]['data']}{bcolors.ENDC}")

  time.sleep(1)
  url = "https://dns-lookup5.p.rapidapi.com/simple"

  querystring = {"domain": domain,"recordType":"MX"}

  headers = {
  	"X-RapidAPI-Key": os.getenv('rapidapi'),
  	"X-RapidAPI-Host": "dns-lookup5.p.rapidapi.com"
  }

  response4 = requests.request("GET", url, headers=headers, params=querystring)

  if not response4:
    data4=""
  else:
    data4 = response4.json()

  
  for i in range(len(data4["records"])):
    print(f"{bcolors.WARNING}MX{bcolors.ENDC}  : {bcolors.BOLD}{data4['records'][i]['data']}{bcolors.ENDC}")

  
  return

def urlScan(url):
  #urlscan.io 5000 per day
  headers = {'API-Key': os.getenv('urlscan_io'),'Content-Type':'application/json'}
  data = {"url":url, "visibility": "public"}
  response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
  time.sleep(10)
  
  if not response:
    data2=''
  else:
    data2=response.json()
    result=data2['uuid']
 
  time.sleep(10)
  res= requests.get("https://urlscan.io/api/v1/result/{0}".format(result))
  
  output=res.json()
  
  lists_ips=output["lists"]["ips"]
  lists_domains=output["lists"]["domains"]
  verdicts_overall=output["verdicts"]["overall"]
  
  print(f'\n {bcolors.BOLD}IP:{bcolors.ENDC}')
  for item in lists_ips:
    print(f"{bcolors.OKGREEN}{item}{bcolors.ENDC}")

  print(f'\n {bcolors.BOLD}DOMAIN:{bcolors.ENDC}')
  for i in lists_domains:
    print(f"{bcolors.OKCYAN}{i}{bcolors.ENDC}")

  print(f'\n {bcolors.BOLD}Overall:{bcolors.ENDC}')
  for i in verdicts_overall:
    print(f'{bcolors.WARNING}{i}:{verdicts_overall[i]}{bcolors.ENDC}')
  if (verdicts_overall['hasVerdicts'] == False):
    print(f'\n {bcolors.HEADER}-----Looks Okey-----{bcolors.ENDC}')
  else:
    print(f'\n {bcolors.HEADER}-!-!-Looks Suspicious-!-!-{bcolors.ENDC}')
  

  return

def hashFile(path):
    
    sha256_hash = hashlib.sha256()
    with open(path,"rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
        

def hashScanMalware(file_sha256):

  #virus total api legit e-mail 

  url = 'https://www.virustotal.com/vtapi/v2/file/report'
  
  params = {'apikey': os.getenv('virus_total'), 'resource': file_sha256}
  
  response = requests.get(url, params=params)
  data=response.json()

  if (data["response_code"]==0):
     return print(f'\n {bcolors.OKGREEN}---No security vendors flagged this file as malicious---{bcolors.ENDC}')
  elif (data["response_code"]==1):
    count=0  
    for i in data['scans']:
      if (data['scans'][i]["detected"]==True):

        print(f'Database Name: {bcolors.HEADER}{i}{bcolors.ENDC}')
        print(f"Version: {bcolors.OKCYAN}{data['scans'][i]['version']}{bcolors.ENDC}")
        print(f"Result: {bcolors.FAIL}{bcolors.BOLD}{data['scans'][i]['result']}{bcolors.ENDC}")
        print(f"Update: {bcolors.WARNING}{data['scans'][i]['update']}{bcolors.ENDC}")
        print('\n')
        count+=1
  
    
  return print(f'{bcolors.WARNING}{bcolors.UNDERLINE}{bcolors.BOLD}{data["positives"]}/{data["total"]} Security vendors flagged this file as malicious !{bcolors.ENDC}')

 

#input validation

def validate_ip_address(address):
    parts = address.split(".")

    if len(parts) != 4:
        return False
    for part in parts:
        if not isinstance(int(part), int):
            return False
        if int(part) < 0 or int(part) > 255:
            return False
    return True 

def validate_mail_address(s):
   pat = "^[a-zA-Z0-9-_]+@[a-zA-Z0-9]+\.[a-z]{1,3}$"
   if re.match(pat,s):
      return True
   return False

def valid_Domain(str):
 
    # Regex to check valid
    # domain name. 
    regex = "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z]{2,6}"
    p = re.compile(regex)
    if (str == None):
        return False
 
    if(re.search(p, str)):
        return True
    else:
        return False

def validate_url(str):
  regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
  
  if (str == None):
        return False

  if(re.search(regex, str)):
      return True
  else:
      return False


#--------------------------terminal menu-----------------------------
def handler(signum, frame): #ctrl+c
    exit(1)

options=['[m] Mail Breach Check','[i] IP Reputation','[d] DNS Record Check','[u] URL Actions','[f] File Hash Malware Scan','[q] quit']
suboptions=['[1] Unshorten','[2] Phishing Check']
returnoptions=['[r] Return Main Menü','[q] quit'] #menu used to return to the main menu

mainMenu= TerminalMenu(options, title='\n       ---SOC Tool---\n')
subMenu= TerminalMenu(suboptions, title='\n       ---[u] URL Actions---\n')
returnMenu= TerminalMenu(returnoptions)
quitting = False


while quitting== False:
    signal.signal(signal.SIGINT, handler) #ctrl+c
    optionsIndex = mainMenu.show()
    optionsChoice = options[optionsIndex]
    
    if (optionsChoice == '[q] quit'):
      quitting = True
      

    elif(optionsChoice == '[m] Mail Breach Check'):
      mail=input(f'{bcolors.OKCYAN}\n Enter Mail Address --> {bcolors.ENDC}')
      
      if (validate_mail_address(mail)==True):
        mailCheck(mail)
        print('\n')
        returnIndex = returnMenu.show()
        returnchoise = returnoptions[returnIndex]
        if (returnchoise=='[r] Return Main Menü'):
          os.system('clear')
        elif(returnchoise=='[q] quit'):
          quitting=True
      else:
        print(f'{bcolors.FAIL}{bcolors.BOLD}\n error: invalid Mail address!{bcolors.ENDC}')
        print('\n')
        returnIndex = returnMenu.show()
        returnchoise = returnoptions[returnIndex]
        if (returnchoise=='[r] Return Main Menü'):
          os.system('clear')
        elif(returnchoise=='[q] quit'):
          quitting=True

    elif(optionsChoice == '[i] IP Reputation'):
      ip=input(f'{bcolors.OKCYAN}\n Enter IP Address --> {bcolors.ENDC}')
      if (validate_ip_address(ip)==True):
        ipReputation(ip)
        print('\n')
        returnIndex = returnMenu.show()
        returnchoise = returnoptions[returnIndex]
        if (returnchoise=='[r] Return Main Menü'):
          os.system('clear')
        elif(returnchoise=='[q] quit'):
          quitting=True
      else:
        print(f'{bcolors.FAIL}{bcolors.BOLD}\n error: invalid IP address!{bcolors.ENDC}')
        print('\n')
        returnIndex = returnMenu.show()
        returnchoise = returnoptions[returnIndex]
        if (returnchoise=='[r] Return Main Menü'):
          os.system('clear')
        elif(returnchoise=='[q] quit'):
          quitting=True
      

    elif(optionsChoice == '[d] DNS Record Check'):
      domain=input(f'{bcolors.OKCYAN}\n Enter Domain Name --> {bcolors.ENDC}')
      if (valid_Domain(domain)==True):
        dns(domain)
        nslookup(domain)
        print('\n')
        returnIndex = returnMenu.show()
        returnchoise = returnoptions[returnIndex]
        if (returnchoise=='[r] Return Main Menü'):
          os.system('clear')
        elif(returnchoise=='[q] quit'):
          quitting=True

      else:
        print(f'{bcolors.FAIL}{bcolors.BOLD}\n error: invalid domain name!{bcolors.ENDC}')
        print('\n')
        returnIndex = returnMenu.show()
        returnchoise = returnoptions[returnIndex]
        if (returnchoise=='[r] Return Main Menü'):
          os.system('clear')
        elif(returnchoise=='[q] quit'):
          quitting=True

    elif(optionsChoice == '[u] URL Actions'):
      suboptionsIndex = subMenu.show()
      suboptionsChoice = suboptions[suboptionsIndex]
      if(suboptionsChoice == '[1] Unshorten'):
        url=input(f'{bcolors.OKCYAN}\n Enter URL --> {bcolors.ENDC}')
        unshorten(url)
        print('\n')
        returnIndex = returnMenu.show()
        returnchoise = returnoptions[returnIndex]
        if (returnchoise=='[r] Return Main Menü'):
          os.system('clear')
        elif(returnchoise=='[q] quit'):
          quitting=True

      elif(suboptionsChoice == '[2] Phishing Check'):
        url=input(f'{bcolors.OKCYAN}\n Enter URL --> {bcolors.ENDC}')
        if(validate_url(url)==True):
          urlScan(url)
          print('\n')
          returnIndex = returnMenu.show()
          returnchoise = returnoptions[returnIndex]
          if (returnchoise=='[r] Return Main Menü'):
            os.system('clear')
          elif(returnchoise=='[q] quit'):
            quitting=True

        else:
          print(f'{bcolors.FAIL}{bcolors.BOLD}\n error: invalid URL!{bcolors.ENDC}')
          print('\n')
          returnIndex = returnMenu.show()
          returnchoise = returnoptions[returnIndex]
          if (returnchoise=='[r] Return Main Menü'):
            os.system('clear')
          elif(returnchoise=='[q] quit'):
            quitting=True

    
    elif(optionsChoice == '[f] File Hash Malware Scan'):
      filePath=input(f'{bcolors.OKCYAN}\n Enter File Path --> {bcolors.ENDC}')
      if(os.path.exists(filePath)):

        sha256Hash=hashFile(filePath)
        hashScanMalware(sha256Hash)
        print('\n')
        returnIndex = returnMenu.show()
        returnchoise = returnoptions[returnIndex]
        if (returnchoise=='[r] Return Main Menü'):
          os.system('clear')
        elif(returnchoise=='[q] quit'):
          quitting=True
      else:
        print(f'{bcolors.FAIL}{bcolors.BOLD}\n error: invalid file path!{bcolors.ENDC}')
        print('\n')
        returnIndex = returnMenu.show()
        returnchoise = returnoptions[returnIndex]
        if (returnchoise=='[r] Return Main Menü'): 
          os.system('clear')
        elif(returnchoise=='[q] quit'):
          quitting=True
