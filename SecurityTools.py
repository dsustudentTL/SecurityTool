import sqlite3
import psutil
import os
import time
import sys
import time
from datetime import datetime, timedelta
import os
import datetime
import pythonwhois
from ipwhois import IPWhois
import socket
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM

#------Helper database functions------------

#run db command ex: update, delete, insert
def runCommand(db, query):
    try:
        conn = sqlite3.connect(db)
        conn.execute(query)
        conn.commit()
        print "Total number of rows affected :", conn.total_changes
        conn.close()
    except:
        print "Error run command"

#get single string return from DB
def selectFromDBReturnSingleString(db,query):
    try:
        conn = sqlite3.connect(db);
        cursor = conn.execute(query);
        data="";
        for row in cursor:
           data= row[0];
        conn.close();
        return data;
    except:
        return "";

# check to see if database exists    
def validateDB(db):
    try:
        conn = sqlite3.connect(db)
        print "Opened database successfully";
        conn.close();
        return 1;
    except:
        return 0;

#convert size
def convert_bytes(n):
    symbols = ('K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y')
    prefix = {}
    for i, s in enumerate(symbols):
        prefix[s] = 1 << (i+1)*10
    for s in reversed(symbols):
        if n >= prefix[s]:
            value = float(n) / prefix[s]
            return '%.1f%s' % (value, s)
    return "%sB" % n
 
#custom display print out  
def print_(a, b):
    if sys.stdout.isatty() and os.name == 'posix':
        fmt = '\x1b[1;32m%-17s\x1b[0m %s' %(a, b)
    else:
        fmt = '%-15s %s' %(a, b)
    sys.stdout.write(fmt + '\n')
    sys.stdout.flush()

def secs2hours(secs):
    mm, ss = divmod(secs, 60)
    hh, mm = divmod(mm, 60)
    return "%d:%02d:%02d" % (hh, mm, ss)

#------End Helper database functions----------

#-------SYSTEM INFORMATION----------

def whoislookup():
    data = raw_input("Enter a domain or IP: ");
    whois_result = pythonwhois.get_whois(data)
    if "raw" in whois_result:
        if "No match" in str(whois_result["raw"][0]):
            print ""
        else:
            print str(whois_result) 
    else:
        print ""
    try:
        from warnings import filterwarnings
        filterwarnings( action="ignore")
        from ipwhois import IPWhois
        from pprint import pprint
        obj = IPWhois(data)
        results = obj.lookup_whois(inc_nir=True)
        pprint(results)
    except:
        print ""
#get process list
def GetProcessList():
    option= raw_input("Display childen processes? ('1' for no, '2' for yes, '3' for yes and recursively)>>  ");
    for proc in psutil.process_iter():
        try:
            pinfo = proc.as_dict();
            pid=pinfo['pid']
            name=pinfo['name']
            exe=pinfo['exe']
            try:
                cmdline=''.join(pinfo['cmdline'])
            except:
                cmdline=""
            status=pinfo['status'];
            user= pinfo['username'];
            create_time=datetime.datetime.fromtimestamp(proc.create_time()).strftime("%Y-%m-%d %H:%M:%S")
            print pid,"  ",name,"  ",status,"  ",create_time,"  ",cmdline,"  ",exe
            if(option=="2" or option =="3"):
                if(option=="3"):
                    children = proc.children(recursive=True)
                else:
                    children = proc.children(recursive=False)
                for child in children:
                    try:
                       pinfo = child.as_dict();
                       pid=pinfo['pid']
                       name=pinfo['name']
                       exe=str(pinfo['exe']).replace("None","")
                       try:
                            cmdline=''.join(pinfo['cmdline'])
                       except:
                            cmdline=""
                       status=pinfo['status'];
                       user= pinfo['username'];
                       if cmdline=="None" or cmdline=="":
                            cmdline=exe
                       create_time=datetime.datetime.fromtimestamp(child.create_time()).strftime("%Y-%m-%d %H:%M:%S")
                       print "      Child: ",pid,"  ",name,"  ",status,"  ",create_time,"  ",cmdline
                    except psutil.NoSuchProcess:
                        pass
        except psutil.NoSuchProcess:
            pass

def GetCurrentSystemConnections():
    AD = "-" 
    AF_INET6 = getattr(socket, 'AF_INET6', object()) 
    proto_map = { (AF_INET, SOCK_STREAM): 'tcp', (AF_INET6, SOCK_STREAM): 'tcp6', (AF_INET, SOCK_DGRAM): 'udp', (AF_INET6, SOCK_DGRAM): 'udp6'} 

    templ = "%-5s %-30s %-30s %-13s %-6s %s"
    proc_names = {}
    for p in psutil.process_iter():
        try:
            proc_names[p.pid] = p.name()
        except psutil.Error:
            pass
    for c in psutil.net_connections(kind='all'):
        laddr = "%s:%s" % (c.laddr)
        raddr = ""
        if c.raddr:
            raddr = "%s:%s" % (c.raddr)
        print(templ % (
            proto_map[(c.family, c.type)],
            laddr,
            raddr or AD,
            c.status,
            c.pid or AD,
            proc_names.get(c.pid, '?')[:15],
        )) 

#search for a process and display detail information about a process  
def processSearch():
    pidstr= raw_input("Get detail information from PID or name. Type \"exit\" to end search.>>  ");
    try:
        pid=int(pidstr);
    except:
        pid=-1;
    ACCESS_DENIED = ''
    while (pidstr.lower() !="exit"):
        print "\n",80 * "-"
        for p in psutil.process_iter():
            curentpid=p.pid;
            processname=p.name();
            if curentpid==pid or processname.lower() ==pidstr.lower()  or  pidstr.lower()  in processname.lower() :
                pinfo = p.as_dict();
                started = datetime.datetime.fromtimestamp(pinfo['create_time']).strftime('%Y-%M-%d %H:%M')
                io = pinfo.get('io_counters', None)
                mem = '%s%% (resident=%s, virtual=%s) ' % (round(pinfo['memory_percent'], 1),convert_bytes(pinfo['memory_info'].rss),convert_bytes(pinfo['memory_info'].vms))
                print_('pid:', pinfo['pid'])
                print_('name:', pinfo['name'])
                print_('exe:', pinfo['exe'])
                try:
                    print_('cmdline:', ''.join(pinfo['cmdline']))
                except:
                    print_('cmdline:', ' ')
                print_('started:', started)
                print_('user:', pinfo['username'])
                if os.name == 'posix':
                    print_('uids:', 'real=%s, effective=%s, saved=%s' % pinfo['uids'])
                    print_('gids:', 'real=%s, effective=%s, saved=%s' % pinfo['gids'])
                    print_('terminal:', pinfo['terminal'] or '')
                if hasattr(p, 'getcwd'):
                    print_('cwd:', pinfo['cwd'])
                print_('memory:', mem)
                print_('cpu:', '%s%% (user=%s, system=%s)' % (pinfo['cpu_percent'], pinfo['cpu_times'].user, pinfo['cpu_times'].system))
                print_('status:', pinfo['status'])
                print_('niceness:', pinfo['nice'])
                print_('num threads:', pinfo['num_threads'])
                if io != ACCESS_DENIED:
                    print_('I/O:', 'bytes-read=%s, bytes-written=%s' %  (convert_bytes(io.read_bytes), convert_bytes(io.write_bytes)))
            
                #get parent of the process
                try:
                    parent=p.parent();
                    ppinfo = parent.as_dict();
                    pid=ppinfo['pid']
                    name=ppinfo['name']
                    exe=str(ppinfo['exe']).replace("None","")
                    try:
                        cmdline=''.join(ppinfo['cmdline'])
                    except:
                        cmdline=""
                    status=ppinfo['status'];
                    user= ppinfo['username'];
                    create_time=datetime.datetime.fromtimestamp(parent.create_time()).strftime("%Y-%m-%d %H:%M:%S")
                    print "Parent: ",pid,"  ",name,"  ",status,"  ",create_time,"  ",cmdline,"  ",exe
                except:
                    print ""

                #get all children of the process
                print_('Children processes:', '\n')
                children = p.children(recursive=True)
                for child in children:
                    try:
                       cpinfo = child.as_dict();
                       pid=cpinfo['pid']
                       name=cpinfo['name']
                       exe=str(cpinfo['exe']).replace("None","")
                       try:
                            cmdline=''.join(cpinfo['cmdline'])
                       except:
                            cmdline=""
                       status=cpinfo['status'];
                       user= cpinfo['username'];
                       create_time=datetime.datetime.fromtimestamp(child.create_time()).strftime("%Y-%m-%d %H:%M:%S")
                       print "      Child: ",pid,"  ",name,"  ",status,"  ",create_time,"  ",cmdline,"  ",exe
                    except psutil.NoSuchProcess:
                        pass

                #get all open files
                if pinfo['open_files'] != ACCESS_DENIED:
                    print_('Open files:', ' ')
                    try:
                        for file in pinfo['open_files']:
                            try:
                                print_('',  'fd=%s %s ' % (file.fd, file.path))
                            except:
                                print "" 
                    except:
                        print "" 

                #get all running threads
                if pinfo['threads']:
                    print_('Running threads:', ' ')
                    try:
                        for thread in pinfo['threads']:
                            try:
                                print_('',  'id=%s, user-time=%s, sys-time=%s' % (thread.id, thread.user_time, thread.system_time))
                            except:
                                print ""
                    except:
                        print "" 

                #get all open running threads
                if pinfo['connections'] != ACCESS_DENIED:
                    print_('Open running threads:', ' ')
                    try: 
                        for conn in pinfo['connections']:
                            try:
                                if conn.type == socket.SOCK_STREAM:
                                    type = 'TCP'
                                elif conn.type == socket.SOCK_DGRAM:
                                    type = 'UDP'
                                else:
                                    type = 'UNIX'
                                lip, lport = conn.local_address
                                if not conn.remote_address:
                                    rip, rport = '*', '*'
                                else:
                                    rip, rport = conn.remote_address
                                print_('',  '%s:%s -> %s:%s type=%s status=%s' % (lip, lport, rip, rport, type, conn.status))
                            except:
                                print ""   
                    except:
                        print ""

                #get connections
                print_('Open connections:', ' ')
                AF_INET6 = getattr(socket, 'AF_INET6', object())
                AD = "-"
                proto_map = {(AF_INET, SOCK_STREAM)  : 'tcp', (AF_INET6, SOCK_STREAM) : 'tcp6', (AF_INET, SOCK_DGRAM)   : 'udp', (AF_INET6, SOCK_DGRAM)  : 'udp6'}
                templ = "%-5s %-30s %-30s %-13s" 
                print(templ % ("Proto", "Local address", "Remote address", "Status"))
                try:
                    conns = p.get_connections(kind="all")
                except:
                    conns = p.connections(kind="all")
                for c in conns:
                    laddr = "%s:%s" % (c.laddr)
                    raddr = ""  
                    if c.raddr:  
                        raddr = "%s:%s" % (c.raddr)  
                    print(templ % (proto_map[(c.family, c.type)], laddr, raddr or AD, c.status))
                print "\n",80 * "-"
        pidstr= raw_input("Get detail information from PID or name. Type \"exit\" to end search.>>  ");
        try:
            pid=int(pidstr);
        except:
            pid=-1;
        ACCESS_DENIED = ''               

#-------End System Information------

def computerInformation():
    try:
        print "System CPU times" , 30 * "-","\n"
        print psutil.cpu_times()
    except:
        print ""
    try:
        print "Number of logical CPUs in the system" , 30 * "-","\n" 
        print psutil.cpu_count()
    except:
        print ""
    try:        
        print "Number of usable CPUs" , 30 * "-","\n"
        print len(psutil.Process().cpu_affinity())
    except:
        print ""
    try:          
        print "CPU statistics" , 30 * "-","\n" 
        print psutil.cpu_stats()
    except:
        print ""
    try:          
        print "CPU frequency" , 30 * "-","\n" 
        print psutil.cpu_freq()
    except:
        print ""
    try:          
        print "Statistics about system memory" , 30 * "-","\n"
        print psutil.virtual_memory()
    except:
        print ""
    try:           
        print "System swap memory statistics" , 30 * "-","\n" 
        print psutil.swap_memory()
    except:
        print ""
    try:           
        print "Mounted disk partitions" , 30 * "-","\n" 
        print psutil.disk_partitions()
    except:
        print ""
    try:            
        print "Disk usage statistics" , 30 * "-","\n" 
        print psutil.disk_usage('/')
    except:
        print ""
    try:           
        print "System-wide disk I/O statistics" , 30 * "-","\n" 
        print psutil.disk_io_counters()
    except:
        print ""
    try:            
        print "System-wide network I/O statistics" , 30 * "-","\n" 
        print psutil.net_io_counters()
    except:
        print ""
    try:            
        print "System-wide socket connections" , 30 * "-","\n" 
        print psutil.net_connections()
    except:
        print ""
    try:           
        print "The addresses associated to each NIC" , 30 * "-","\n" 
        print psutil.net_if_addrs()
    except:
        print ""
    try:           
        print "Information about each NIC" , 30 * "-","\n" 
        print psutil.net_if_stats()
    except:
        print ""
    try:            
        print "Hardware temperatures" , 30 * "-","\n"
        print psutil.sensors_temperatures()
    except:
        print ""
    try:           
        print "Hardware fans speed" , 30 * "-","\n"
        print psutil.sensors_fans()
    except:
        print ""
    try:           
        print "Battery status information" , 30 * "-","\n" 
        battery = psutil.sensors_battery()
        print battery
        print("charge = %s%%, time left = %s" % (battery.percent, secs2hours(battery.secsleft)))
    except:
        print ""
    try:            
        print "System boot time" , 30 * "-","\n" 
        print psutil.boot_time()
    except:
        print ""
    try:            
        print "Users currently connected on the system" , 30 * "-","\n" 
        print psutil.users()
    except:
        print ""
    try:           
        print "Current running PIDs" , 30 * "-","\n"
        print psutil.pids()
    except:
        print ""
  
#menu options display and selection
def menu(db,type):
    
    conn = sqlite3.connect(db)
    cursor = conn.execute("SELECT text, value from MenuOptions where type= '"+type+"' order by DisplayOrder")
    print 30 * "-" , type , 30 * "-"
    for row in cursor:
       print row[1],".  ", row[0], "\n"
    print 80 * "-"
    conn.close()

    option = raw_input("Please enter your selection: >>  ")
    query="SELECT text from MenuOptions where type= '"+type+"' and value='"+option+"' order by DisplayOrder"
    try:
        selection=selectFromDBReturnSingleString(db,query);
    except:
        selection=""
    while selection=="":
        print "Invalid selection!"
        option = raw_input("Please enter your selection: >>  ")
        query="SELECT text from MenuOptions where type= '"+type+"' and value='"+option+"' order by DisplayOrder"
        try:
            selection=selectFromDBReturnSingleString(db,query);
        except:
            selection=""   
    if(selection=="MAIN MENU" or selection=="COMPUTER INFORMATION"):
        if(selection=="MAIN MENU"):
            os.system('cls')
        menu(db,selection);
    elif(selection=="LIST RUNNING PROCESSES"):
        GetProcessList();
        menu(db,"COMPUTER INFORMATION");
    elif(selection=="SEARCH FOR A PROCESS"):
        processSearch();
        menu(db,"COMPUTER INFORMATION");
    elif(selection=="SYSTEM INFORMATION"):
        computerInformation();
        menu(db,"COMPUTER INFORMATION");
    elif(selection=="SYSTEM CONNECTIONS"):
        GetCurrentSystemConnections();
        menu(db,"COMPUTER INFORMATION");
    elif(selection=="WHO IS LOOKUP"):
        whoislookup();
        menu(db,"COMPUTER INFORMATION");
    elif(selection=="SYSTEM SCAN"):
        getCurrentSystemNetwork();
        menu(db,"COMPUTER INFORMATION");
    elif(selection=="EXIT"):
        print "Thank you for using my program. Have a great day!";

# main prompt for database connection 
if __name__ == '__main__':
    db = raw_input("Please enter database location (blank for default) >>  ")
    if(db==""):
        db = "C:\Python27\SecurityTool.db"
    validDB=validateDB(db)
    while validDB==0:
        db = raw_input("Please enter database location (blank for default) >>  ")
        if(db==""):
            db = "C:\Python27\SecurityTool.db"
        validDB=validateDB(db)
    menu(db,"MAIN MENU")


