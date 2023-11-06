try:
    import time,threading,subprocess,argparse
    from alive_progress import alive_bar
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', action='store_true')
    parser.add_argument('-debug', action='store_true')
    args=parser.parse_args()

    ip_with_open_port=[]
    def cls():
        print ("\033c")

    def wait(x):
        time.sleep(x)

    def scanning(hostname,portnumber,all_ports):
        try:
            global ip_with_open_port
            cmd = ["nc", "-zv", "-w", "1", hostname, portnumber]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
            if result.returncode == 0:
                if args.d or args.debug:
                    print(f"{hostname} is up!")
                    ip_with_open_port.append(hostname + ":" + portnumber)
                else:
                    print(f"{hostname}:{portnumber} is up!")
                    ip_with_open_port.append(hostname + ":" + portnumber)
            else:
                if args.d or args.debug:
                    if all_ports:
                        print(f"{hostname}:{portnumber} is down!")
                    else:
                        print(f"{hostname} is down!")
                pass
        except subprocess.TimeoutExpired:
            if args.d or args.debug:
                print(f"{hostname}:{portnumber} timeout: The command took too long to complete.")
            pass
        except Exception as e:
            if args.d or args.debug:
                print(f"An error occurred for {hostname} {str(e)}")
            pass

    def ip_check(ip_split, subnet_split, question1):
        global Full_store_hostname
        Full_store_hostname=[]
        store_hostname=[]
        Allowed_ranged=str(list(range(256)))
        Allowed_ranged2=(list(range(256)))
        Allowed_ranged_ip=str(list(range(16,32)))
        Allowed_ranged_ip2=(list(range(16,32)))
        if subnet_split[0] == "255" and subnet_split[1] in Allowed_ranged and subnet_split[2] in Allowed_ranged and subnet_split[3] in Allowed_ranged:
            if ip_split[0] == "10" and ip_split[1] in Allowed_ranged and ip_split[2] in Allowed_ranged and ip_split[3] in Allowed_ranged:
                if question1=="yes" or question1=="y":
                    for i in Allowed_ranged2:
                        for b in Allowed_ranged2:
                            so=str(i)
                            bo=str(b)
                            ip="10."+so+bo
                            store_hostname.append(ip)
                    for z in store_hostname:
                        for b in Allowed_ranged2:
                            bo=str(b)
                            ip=z+"."+bo
                            Full_store_hostname.append(ip)
                elif question1=="no" or question1=="n" or question1=="":
                    for i in Allowed_ranged2:
                        so=str(i)
                        ip="10."+ip_split[1]+"."+ip_split[2]+"."+so
                        Full_store_hostname.append(ip)
                return True
        if subnet_split[0] == "255" and subnet_split[1] == "255" and subnet_split[2] in Allowed_ranged and subnet_split[3] in Allowed_ranged:
            if ip_split[0] == "172" and ip_split[1] in Allowed_ranged_ip and ip_split[2] in Allowed_ranged and ip_split[3] in Allowed_ranged:
                if question1=="yes" or question1=="y":
                    for i in Allowed_ranged_ip2:
                        for b in Allowed_ranged2:
                            so=str(i)
                            bo=str(b)
                            ip="172."+so+bo
                            store_hostname.append(ip)
                    for z in store_hostname:
                        for b in Allowed_ranged2:
                            bo=str(b)
                            ip=z+"."+bo
                            Full_store_hostname.append(ip)
                elif question1=="no" or question1=="n" or question1=="":
                    for i in Allowed_ranged2:
                        so=str(i)
                        ip="172."+ip_split[1]+"."+ip_split[2]+"."+so
                        Full_store_hostname.append(ip)
                return True
        if subnet_split[0] == "255" and subnet_split[1] == "255" and subnet_split[2] == "255" and subnet_split[3] in Allowed_ranged:
            if ip_split[0] == "192" and ip_split[1] == "168" and ip_split[2] in Allowed_ranged and ip_split[3] in Allowed_ranged:
                if question1=="yes" or question1=="y":
                    for i in Allowed_ranged2:
                        so=str(i)
                        ip="192.168."+so
                        store_hostname.append(ip)
                    for z in store_hostname:
                        for b in Allowed_ranged2:
                            bo=str(b)
                            ip=z+"."+bo
                            Full_store_hostname.append(ip)
                elif question1=="no" or question1=="n" or question1=="":
                    for i in Allowed_ranged2:
                        so=str(i)
                        ip="192.168."+ip_split[2]+"."+so
                        Full_store_hostname.append(ip)
                return True
            
    def Start_scan(hostname,port,QCommon_port,all_ports):
        Allowed_port_range=(list(range(65536)))
        well_known_ports = ["7", "20", "21", "22", "23", "25", "53", "67","68", "69", "80", "110", "119", "123", "143", "161","162", "443", "465", "514", "546","547", "587", "636", "993", "995", "1433", "1521", "3306", "3389", "5432", "5900", "8080"]
        validlogin={}
        for i in hostname:
            if all_ports:
                for b in Allowed_port_range:
                    portnumber=str(b)
                    validlogin.setdefault(i, []).append(portnumber)
            elif QCommon_port:
                for b in well_known_ports:
                    portnumber=str(b)
                    validlogin.setdefault(i, []).append(portnumber)
            else:
                portnumber=str(port)
                validlogin[i]=portnumber

        if all_ports or QCommon_port:
            if all_ports:
                barlen=len(validlogin)*len(Allowed_port_range)
            if QCommon_port:
                barlen=len(validlogin)*len(well_known_ports)
            with alive_bar(barlen) as bar: 
                for m,n in validlogin.items():
                    for value in n:
                        t=threading.Thread (target=scanning, args=(m,value,all_ports))
                        t.start()
                        bar()               
        else:
            barlen=len(hostname)+len(port)
            with alive_bar(barlen) as bar: 
                for i in hostname:
                    t=threading.Thread (target=scanning, args=(i,port,all_ports))
                    t.start()
                    bar() 

    def port_scan():
        Allowed_port=str(list(range(65536)))
        valid_ip=False
        valid_port=False
        Qports=False
        QCommon_port=False
        all_ports=False
        port=0
        while not Qports:
            common_ports=input("Do you want to scan for all common ports?(y or n): ")
            if common_ports == "y" or common_ports == "yes" or common_ports == "":
                ports_confirm=input("Do you also want to scan the full range ports?(y or n): ")
                if ports_confirm == "y" or ports_confirm == "yes":
                    all_ports=True
                    Qports=True
                elif ports_confirm == "n" or ports_confirm == "no" or ports_confirm == "":
                    QCommon_port=True
                    Qports=True
            elif common_ports == "n" or common_ports == "no":
                while not valid_port:
                    port=str(input("Enter port number (default: 22): "))
                    if port=="":
                        port=str(22)
                    if port in Allowed_port:
                        valid_port=True
                        Qports=True
                    else:
                        print("Invalid option")
            else:
                print("Invalid option")
        while not valid_ip:
            ip=input("Please enter your net id (default: 192.168.0.0): ")
            question1=input("Do you want scan for diffirent networks?(y or n): ")
            subnet=input("Please enter your subnetmask (default: 255.255.255.0): ")
            ip_split=ip.split('.')
            subnet_split=subnet.split('.')
            if ip=="":
                ip="192.168.0.0"
            if subnet=="":
                subnet="255.255.255.0"
            ip_split=ip.split('.')
            subnet_split=subnet.split('.')
            if ip_check(ip_split, subnet_split, question1):
                valid_ip=True
            else:
                print("Invalid input")
        hostname=Full_store_hostname
        Start_scan(hostname,port,QCommon_port,all_ports)
        return ip_with_open_port

    if __name__ == '__main__':
        ip_port_dict={}
        cls()
        print ("Port scanner")
        wait(2)
        print_ips=port_scan()
        wait(2)
        cls()
    for item in print_ips:
        ip, port = item.split(":")
        if ip in ip_port_dict:
            if port != ip_port_dict[ip]:
                ip_port_dict[ip] += ", " + port
        else:
            ip_port_dict[ip] = port
    for ip, port in ip_port_dict.items():
        print(f"IP: {ip}, Ports: {port}")
except Exception as e:
    print("You've got an error, please make sure these modules are installed: alive_progress","\n","error code: ",e)