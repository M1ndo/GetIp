#!/usr/bin/python
#Coded By ybenel
#Twitter @_ybenel

# IMPORT LIBRARIES #

try:

   import socket,dns.resolver,optparse,subprocess,multiprocessing
   from json import load; from urllib2 import urlopen; from copy import copy; from os import devnull,popen,system as sy; from time import sleep as se; from sys import platform as useros
except KeyboardInterrupt:
        print("[!] Something Went Wrong!\n[>] Please Try Again :)")
        exit(1)
except ImportError, e:
     e = e[0][16:]
     if e =="json":
		e = "simplejson"
     elif e=="dns.resolver":
	e = "dnspython"
		
     print("[!] Error: ["+e+"] Module Is Missing !!!\n[*] Please Install It Using This Command: pip install "+e)
     exit(1)
sy("cls||clear")
from example import *
## Check Internet Connection.....
server = "www.google.com"
def check():
  try:
    ip = socket.gethostbyname(server)
    con = socket.create_connection
    return True
  except KeyboardInterrupt:
        print("[!] Something Went Wrong!\n[>] Please Try Aagain :)")
        exit(1)
  except:
	pass
  return False
check = check()

#1: Find User Local IP address
def locip():
	locip = ''.join(socket.gethostbyname_ex(socket.gethostname())[2])
	if locip !="127.0.0.1":
		return locip
	else:
		return False
	
#2: Find User Puplic IP Address
def pupip():
 if check == True:
  pupip = urlopen('http://ip.42.pl/raw').read()
  print("[P] Puplic IP: "+str(pupip))
 else:
   print("[!] Error: Your Not Connect To Internet !!!\n[!] Please Check Your Internet Connection!")
   exit(1)
#3: Find Network Hosts
if useros in ["linux", "linux2"]:
 def pinger(job_q, results_q):
    DEVNULL = open(devnull, 'w')
    while True:

        ip = job_q.get()

        if ip is None:
            break

        try:
            subprocess.check_call(['ping', '-c1', ip],
                                  stdout=DEVNULL)
            results_q.put(ip)
        except:
            pass
 def map_network(pool_size=255):
  print("Mapping...")
  try:
    ip_list = list()

    # get my IP and compose a base like 192.168.1.xxx
    if locip() !=False:
	ip_parts = locip().split('.')
    else:
	print("\n[!] Error Your Not Connect To Any Network !!!\n[!] Please Check Your Connection!")
	exit(1)

    base_ip = ip_parts[0] + '.' + ip_parts[1] + '.' + ip_parts[2] + '.'

    # prepare the jobs queue
    jobs = multiprocessing.Queue()
    results = multiprocessing.Queue()

    pool = [multiprocessing.Process(target=pinger, args=(jobs, results)) for i in range(pool_size)]

    for p in pool:
        p.start()

    # cue hte ping processes
    for i in range(1, 255):
        jobs.put(base_ip + '{0}'.format(i))

    for p in pool:
        jobs.put(None)

    for p in pool:
        p.join()

    # collect he results
    while not results.empty():
        ip = results.get()
        ip_list.append(ip)

    return ip_list

  except Exception, e:
    return False
elif useros in ["win32","win64"]:
	def map_network():
		locip = ''.join(socket.gethostbyname_ex(socket.gethostname())[2])
		if locip !="127.0.0.1":
			gtw = locip[:-2]
			ip_list = []
			print("Mapping...")
			try:
                           for i in range(1,255):
                              data = popen('ping -n 1 {}.{} |findstr "Reply from"'.format(gtw,i)).read()
                              if "Reply from" in data and "Destination host unreachable." not in data:
                                 ip_list.append(gtw+"."+str(i))
                           return ip_list
                        except KeyboardInterrupt:
                           return ip_list
		else:
			return False

########################

# Know Server Name From He Port Or Know Server Port From Server Name Service :)
def serpor(x):
  try:
     try:
	sname = socket.getservbyport(int(x))
	print('\n[~] Server Name Is: {} '.format(sname))
     except:
        sport = socket.getservbyname(x)
        print('\n[~] Server Port Is: {} '.format(str(sport)))
  except:
	print("\n[!] Unknown This ==> {}".format(str(x)))
##########################################
Green="\033[1;33m"
Blue="\033[1;34m"
Grey="\033[1;30m"
Reset="\033[0m"
yellow="\033[1;36m"
Red="\033[1;31m"
purple="\033[5;35m"
cyan="\033[96m"
stong="\033[41m"
##########################################


print("        "+Green+"MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM")
print("        "+Green+"MMMMMMMMMMNKWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM")
print("        "+Green+"MMMMMMMMMNc.dWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM")
print("        "+Blue+"MMMMMMMMWd. .kWMMMMMMMMMMMMMMMMMMMMMMW0KMMMMMMMMMM")
print("        "+Blue+"MMMMMMMMk:;. 'OMMMMMMMMMMMMMMMMMMMMMWx.,0MMMMMMMMM")
print("        "+Blue+"MMMMMMMK:ok.  ,0MMMMMMMMMMMMMMMMMMMWO. .cXMMMMMMMM")
print("        "+Blue+"MMMMMMNl:KO.   ;KWNXK00O0000KXNWMMWO' .c;dWMMMMMMM")
print("        "+Blue+"MMMMMMx,xNk.    .;'...    ....';:l:.  ,0l,0MMMMMMM")
print("        "+Blue+"MMMMMK;,l;. .,:cc:;.                  .dx,lWMMMMMM")
print("        "+Blue+"MMMMWo    ,dKWMMMMWXk:.      .cdkOOxo,. ...OMMMMMM")
print("        "+Blue+"MMMM0'   cXMMWKxood0WWk.   .lkONMMNOOXO,   lWMMMMM")
print("        "+Blue+"MMMWl   ;XMMNo.    .lXWd. .dWk;;dd;;kWM0'  '0MMMMM")
print("        "+Blue+"kxko.   lWMMO.      .kMO. .OMMK;  .kMMMNc   oWMMMM")
print("        "+Blue+"X0k:.   ;KMMXc      :XWo  .dW0c,lo;;xNMK,   'xkkk0")
print("        "+Blue+"kko'     :KMMNkl::lkNNd.   .dkdKWMNOkXO,    .lOKNW")
print("        "+Blue+"0Kk:.     .lOXWMMWN0d,       'lxO0Oko;.     .ckkOO")
print("        "+Blue+"kkkdodo;.    .,;;;'.  .:ooc.     .        ...ck0XN")
print("        "+Blue+"0XWMMMMWKxc'.          ;dxc.          .,cxKK0OkkOO")
print("        "+Blue+"MMMMMMMMMMMN0d:'.  .'        .l'  .;lxKWMMMMMMMMMN")
print("        "+Blue+"MMMMMMMMMMMMMMMN0xo0O:,;;;;;;xN0xOXWMMMMMMMMMMMMMM")
print("        "+Green+"MMMMMMMMMMMMMMMMMMMMMMWWWWWMMMMMMMMMMMMMMMMMMMMMMM")
print("        "+Green+"MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM")
print("        "+Green+"MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM")
print("        "+Green+"MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM")
print("        "+Green+"MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM")
print("        "+Blue+"                   "+Green+"["+Red+"GetIp"+Green+"]"+Blue+"         ")
print("     "+purple+"          "+yellow+"["+purple+"   Created By ybenel"+yellow+"]"+yellow+"    "+Reset+"\n")
parse = optparse.OptionParser("""\
\033[96m
Usage:
     python GetIp.py [OPTIONS...]
=================================
IPs  OPTIONS:
------------
       -t --target         >>  Get Target Website Server IPs
       -a --all            >>  Scan For All Servers On Wbsites
       -f --found-me       >>  Found Your Local IP And Your Puplic IP
       -n --network        >>  scan network and Found IPs Of Hosts
==============
Other Options:
--------------
       -c --check 	   >>  Know Server Name From Port OR Know Server Port From Name
       -e --examples       >>  Show Examples
       -v --version	   >>  Show Script Version""",version='\n[>] Version>> 1.0\nWait New Version Soon :)')
def main():
  parse.add_option('-t','-T','--TARGET','--target',dest="target",type="string")
  parse.add_option("-a","-A","--ALL",'--all',action='store_true',dest="all",default=False)
  parse.add_option("-f","-F","--FOUND-ME",'--found-me',action='store_true',dest="fme",default=False)
  parse.add_option("-n","-N","--NETWORK",'--network',action='store_true',dest="network",default=False)
  parse.add_option('-c','-C','--CHECK','--check',dest="check",type="string")
  parse.add_option("-e","-E","--EXAMPLES",'--examples',action='store_true',dest="ex",default=False)
  parse.add_option("-v","-V","--VERSION",action='store_true',dest="ve",default=False)
  (options,args) = parse.parse_args()
  if options.target !=None and not options.all:
	target = options.target
	try:
           test = open(target, 'r')
	   res = True
	except:
 	   res = False
	if res == False:
 	 if target[:8] == "https://":
             host = target[8:]
	 elif target[:7] == "http://":
             host = target[7:]
	 else:
            host = target
	 target = host
         def GetIp(target):
             if check ==True:
              if ',' in target:
	         targets = target.split(',')
                 print("[@] Scanning [ {} ] Sites...".format(str(len(targets))))
                 for i in targets:
                  try:
                    ip = socket.gethostbyname(i)
                    print("[*] TARGET> {}\n[*] IP> {}\n========".format(i,ip))
                  except socket.error:
	            print("[*] TARGET> {}\n[!] IP> Cod404: Server Not Found !!!".format(i))
		  except KeyboardInterrupt:
			  print(" ")
			  break
              else:
		  print("[~] Connecting....{}\n".format(target))
		  try:
		     ip = socket.gethostbyname(target)
                     print("[*] TARGET> {}\n[*] IP> {}\n========".format(target,ip))
		  except socket.error:
			print("[~] TARGET> {}\n[!] IP> Cod404: Server Not Found !!!".format(target))
		  except KeyboardInterrupt:
			  pass
			  exit(1)
             else:
		 print("[!] Please Check Your Internet Connection !!!")
		 exit(1)
	 GetIp(target)
	else:
		targets = open(target, 'r')
                for t in targets:
		   t = t.strip()
                   def checker():
	            try:
	               if t[:8] == "https://":
		             host = t[8:]
	               elif t[:7] == "http://":
		             host = t[7:]
	               else:
		            host = t

	               ip = socket.gethostbyname(host)
		       run = socket.create_connection((ip, 80), 2)
		       return True
                    except:
	                   pass
                    return False
                   if checker() == True:
                        if t[:8] == "https://":
                             host = t[8:]
                        elif t[:7] == "http://":
                             host = t[7:]
                        else:
                             host = t
			try:
                           ip = socket.gethostbyname(host)
                           print("[*] TARGET> {}\n[*] IP> {}\n========".format(t,ip))
			except socket.error:
	               			pass
			except KeyboardInterrupt:
				pass

  elif options.target !=None and options.all:
   target = options.target
   if check ==True:
	 try:
	    test = open(target, 'r')
	    res = True
	 except:
	    res = False
	 if res ==True:
	     targets = open(target, 'r').readlines()
	     for t in targets:
		   t = t.strip()
                   def checker():
	            try:
	               if t[:8] == "https://":
		             host = t[8:]
	               elif t[:7] == "http://":
		             host = t[7:]
	               else:
		            host = t

	               ip = socket.gethostbyname(host)
		       run = socket.create_connection((ip, 80), 2)
		       return True
                    except:
	                   pass
                    return False
                   if checker() == True:
                        if t[:8] == "https://":
                             host = t[8:]
                        elif t[:7] == "http://":
                             host = t[7:]
                        else:
                             host = t
		        found = []
		        for address_type in ['A', 'AAAA']:
		           try:
		              answers = dns.resolver.query(host, address_type)
		              for rdata in answers:
			        found.append(rdata)
		           except dns.resolver.NoAnswer:
			           pass
		        le = len(found)
		        if len(found) > 0:
			 print("\n[~]> Target[ {} ]".format(t))
			 print("[+] Servers Found({}):".format(str(le)))
			 loop = 1
			 for i in found:
			   print("\tSERVER[{}]   >   {}".format(loop,i))
			   loop +=1
			 print("======================\n")
		        else:
		           print("\n[!] No Servers Found !!!")
		           exit(1)
                   else:
	               pass
	 elif ',' in target:
		targets = target.split(',')
                for t in targets:
                   def checker():
	            try:
	               if t[:8] == "https://":
		             host = t[8:]
	               elif t[:7] == "http://":
		             host = t[7:]
	               else:
		            host = t

	               ip = socket.gethostbyname(host)
		       run = socket.create_connection((ip, 80), 2)
		       return True
                    except:
	                   pass
                    return False
                   if checker() == True:
                        if t[:8] == "https://":
                             host = t[8:]
                        elif t[:7] == "http://":
                             host = t[7:]
                        else:
                             host = t
		        found = []
		        for address_type in ['A', 'AAAA']:
		           try:
		              answers = dns.resolver.query(host, address_type)
		              for rdata in answers:
			        found.append(rdata)
		           except dns.resolver.NoAnswer:
			           pass
		        le = len(found)
		        if len(found) > 0:
			 print("\n[~]> Target[ {} ]".format(t))
			 print("[+] Servers Found({}):".format(str(le)))
			 loop = 1
			 for i in found:
			   print("\tSERVER[{}]   >   {}".format(loop,i))
			   loop +=1
			 print("======================\n")
		        else:
		           print("\n[!] No Servers Found !!!")
		           exit(1)
                   else:
		       pass
         else:	 
           def checker():
	     try:
	        if target[:8] == "https://":
		  host = target[8:]
	        elif target[:7] == "http://":
		   host = target[7:]
	        else:
		     host = target

	        ip = socket.gethostbyname(host)
		run = socket.create_connection((ip, 80), 2)
		return True
             except:
	          pass
             return False
           if checker() == True:
                if target[:8] == "https://":
                  host = target[8:]
                elif target[:7] == "http://":
                   host = target[7:]
                else:
                     host = target
		found = []
		print("[#]~[Finding Servers IP Of TARGET[ {} ].....\n".format(target))
		for address_type in ['A', 'AAAA']:
		  try:
		     answers = dns.resolver.query(host, address_type)
		     for rdata in answers:
			found.append(rdata)
		  except dns.resolver.NoAnswer:
			pass
		le = len(found)
		if len(found) > 0:
			print("[@]~[Found [ {} ] Server(s) Status> UP ".format(str(le)))
			print("[+] Servers:\n")
			loop = 1
			for i in found:
			  print("SERVER[{}]   >   {}".format(loop,i))
			  loop +=1
		else:
		    print("\n[!] No Servers Found !!!")
		    exit(1)
           else:
	       print("\n[!] CodeError:404 >> No Server Found !!!")
	       exit(1)
   else:
        print("[!] Please Check Your Internet Connection !!!")
	exit(1)

  elif options.fme:
	print("\n[@]~[Finding Your IPs....\n")
	locipe = locip()
	if locipe !="[!] Error Your Not Connect To Any Network !!!\n[!] Please Check Your Connection!":
	 print("[L] Local IP: {}".format(locipe))
	else:
	  print(" ")
	  print(locipe)
	  exit(1)
	pupip()
  elif options.network:
	ips_list = map_network()
	if ips_list !=False:
	  se(1)
          loop = 1
          up = "UP"
          
          print("======================================")
          print("ID\t\tIP\t\tSTATUS")
          print("==\t\t==\t\t======")
          for ip in ips_list:
            print("{}\t   {}    \t  {}".format(loop,ip,copy(up)))
            loop +=1
            
          result = loop -1
          print("\nI Found <{}> Device In Network !".format(result))
        else:
	  print("[!] Error Your Not Connect To Any Network !!!\n[!] Please Check Your Connection!")
	  exit(1)

  elif options.ve:
	print("\n[>] Version>> 1.0\nWait New Version Soon :)")
	exit(1)
  elif options.ex:
        sy("printf '\e[8;70;180;t' || mode 800")
        sy("clear || cls")
	examp()
	exit(1)
  elif options.check !=None:
	sp = options.check
	serpor(sp)
	exit(1)
  else:
      print(parse.usage)
      exit(1)

if __name__=="__main__":
	main()
##'-'!!
