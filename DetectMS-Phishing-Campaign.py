#===================================================
# Author  : 34zY
# Date    : 12/04/2023
# Details : This script is dedicated to detect if a 
# domain used in a phishing mail is part or not of 
# the Microsoft Phishing Module to test users. 
# Microsoft Phishing simulation :
# https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/attack-simulation-training-get-started?view=o365-worldwide#simulations
# Github  : https://github.com/34zY
#==================================================
import sys,time

class style():
	BLACK_BG = "\033[40m"
	RED_BG = "\033[41m"
	GREEN_BG = "\033[42m"
	YELLOW_BG = "\033[43m"
	BLUE_BG = "\033[44m"
	MAGENTA_BG = "\033[45m"
	CYAN_BG = "\033[46m"
	WHITE_BG = "\033[47m"
	BLACK = '\033[30m'
	RED = '\033[31m'
	GREEN = '\033[32m'
	YELLOW = '\033[33m'
	BLUE = '\033[34m'
	MAGENTA = '\033[35m'
	CYAN = '\033[36m'
	WHITE = '\033[37m'
	UNDERLINE = '\033[4m'
	RESET = '\033[0m'
	BOLD = '\033[1m'


def banner():
	return style.GREEN + """
______                    """ +style.BLUE + """___  ___ ___________ _     _     """ +style.RESET+style.GREEN + """
| ___ \     """+style.UNDERLINE+"""@34zY"""+style.RESET+ """         """ +style.BLUE +  """|  \/  |/  ___|  ___(_)   | |    """ +style.RESET+style.GREEN + """
| |_/ /___  ___ ___  _ __ """ +style.BLUE + """| .  . |\ `--.| |_   _ ___| |__  """ +style.RESET+style.GREEN + """
|    // _ \/ __/ _ \| '_ \\""" +style.BLUE + """| |\/| | `--. \  _| | / __| '_ \ """ +style.RESET+style.GREEN + """
| |\ \  __/ (_| (_) | | | """ +style.BLUE + """| |  | |/\__/ / |   | \__ \ | | |""" +style.RESET+style.GREEN + """
\_| \_\___|\___\___/|_| |_""" +style.BLUE + """\_|  |_/\____/\_|   |_|___/_| |_|""" +style.RESET+style.GREEN + """
                                                                                                                      
""" + style.RESET + style.RED_BG + style.YELLOW + """/ ! \ """ +"""Tool dedicated to detect MS Phishing Campaign Simulation"""+style.RESET+""" 
            """+style.RESET+"""   ( """+style.GREEN+"""-h"""+style.RESET+""" or """+style.GREEN+"""-help"""+style.RESET+""" for more details ) 

               """ + style.RESET

def check_url(insert_url):

	print(style.CYAN + '[*]'+ style.RESET + style.BOLD +f' Checking url "{insert_url}" ... ' +style.RESET)
	f = open("ms-urls.txt")
	urls = f.read()
	f.close()

	try:
		bloc = urls.split("\n")
		#print(bloc)

		for url in bloc:
			#print(url)
			if insert_url == url:
				return True # successfully recognzied MS domain
		return False

	except:
		return False # MS domain not recognized

def Is_Domain_MS(result):
	if result == True:
		return style.GREEN + "[+]"+ style.RESET + style.BOLD +" Domain is recognized as MS Phishing Attack Simulation." + style.RESET
	if result == False:
		return style.RED + "[!]"+ style.RESET + style.BOLD +" Domain is not recognized as MS Phishing Attack Simulation." + style.RESET

def main():
	print(banner())

	try:

		count = 0
		for args in sys.argv:
			count +=1
	
		if count == 2:

			if sys.argv[1] == "-help" or sys.argv[1] == "-h":
				print(style.YELLOW +"[?]" + style.RESET + " """+style.RED+"""Usage"""+style.RESET+""": python DetectMS-Phishing-Campaign.py """+style.GREEN+"""<url> """+style.RESET+"""or"""+style.GREEN+""" <domain>\n""" + style.RESET)
				print("""    """+style.RED+"""Example"""+style.RESET+""": python DetectMS-Phishing-Campaign.py"""+style.GREEN+""" evil-MS.com """+style.RESET+"""
    
    """+style.RED+"""Description"""+style.RESET+""": This script is dedicated to detect if a 
    domain used in a phishing mail is part or not of 
    the Microsoft Phishing Simulation Module from O365
    suite to test users.

    """+style.RED+"""Author"""+style.RESET+""": 34zY
    """+style.RED+"""Release date"""+style.RESET+""": 12/04/2023
    """+style.RED+"""Github"""+style.RESET+""": https://github.com/34zY"""+style.RESET)
			else:

				insert_url = sys.argv[1]
				
				if "https://" not in insert_url and "www." not in insert_url:
					insert_url = "https://www." + insert_url
	
				if "www." not in insert_url:
					insert_url = insert_url.replace("https://","https://www.")		
				
				result = check_url(insert_url)
				time.sleep(1)
				#print(result)

				print(Is_Domain_MS(result))

		else:
			print(style.YELLOW + "[?]"+ style.RESET + " Usage: python DetectMS-Phishing-Campaign.py <url>/<domain>")
	
	except:
		print(style.YELLOW +"[?]" + style.RESET +" Usage: python DetectMS-Phishing-Campaign.py <url>/<domain>")

if __name__ == '__main__':
	main()