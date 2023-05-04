import os
def main():
    try:
        if os.geteuid() == 0:
            pass
        else:
            raise PermissionError("[#]This program must be run as root!")
    except PermissionError as e:
        print(e)
        exit()
    print("""
    
                                                |>>>
                                                |
                                            _  _|_  _
        ╔╗ ┌─┐┌─┐┌┬┐┬┌─┐┌┐┌                |;|_|;|_|;|
        ╠╩╗├─┤└─┐ │ ││ ││││                \\\\.    .  /
        ╚═╝┴ ┴└─┘ ┴ ┴└─┘┘└┘                 \\\\:  .  /
                                             ||:   |
                                             ||:.  |
                                             ||:  .|
                                             ||:   |       \,/
                                             ||: , |            /`\\
                                             ||:   |
                                             ||: . |
              __                            _||_   |
     ____--`~    '--~~__            __ ----~    ~`---,              
-~--~                   ~---__ ,--~'                  ~~----_____""")
    print("""Bastion is a command-line tool for securing a Linux server. 
It provides a user-friendly interface for automating the installation and 
configuration of various security-related services such as SSH, Firewall, and Samba. 
The program offers easy-to-use menus and prompts to guide users through the setup process,
making it ideal for Linux beginners or users who want to quickly secure their server without 
going through the hassle of manual configuration.""")
    
    input("Press Enter to continue...")
    
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')    
        print("""[#]Available modules
    1.System update
    2.System upgrade
    3.Installation and configuration SSH
    4.Installation and configuration FTP
    5.Installation and configuration SMB
    6.Installation and configuration MySQL
    7.Installation and configuration Apache
    8.Installation and configuration OpenVPN
    9.Installation and configuration Fail2Ban
    10.Installation and configuration UFW
    11.Installation and configuration ClamAV
    0. Exit""")
        module = input("[#]Choose a module: ")
        
        if module == '1':
            print("[#]Executing command apt-get update")
            os.sytem("apt-get update -y > /dev/null")
            print("[#]Update completed!")
        elif module == '2':
            print("[#]Executing command apt-get upgrade ")
            os.system("apt -get upgrade -y /dev/null")
            print("[#]Upgrade completed!")
        elif module == '3':
            os.system("apt-get install openssh-server -y > /dev/null")  
            ssh_config = open('/etc/ssh/sshd_config', 'a')  
            print("[#]Which security settings do you want to apply?")
            print("1. Disable password authentication")
            print("2. Disable root login")
            print("3. Restrict SSH access to specific users")
            print("4. Disable X11 forwarding")
            print("5. Disable PAM authentication")
            print("6. Change SSH port")
            print("[#]Enter the numbers of the settings you want to apply, separated by spaces:")
            settings = list(map(int, input().split()))
            if 1 in settings:
                ssh_config.write("PasswordAuthentication no\n")
            if 2 in settings:
                ssh_config.write("PermitRootLogin no\n")
            if 3 in settings:
                allowed_users = input("[#]Enter the usernames of the users allowed to access SSH, separated by spaces: ")
                ssh_config.write("AllowUsers " + allowed_users + "\n")
            if 4 in settings:
                ssh_config.write("X11Forwarding no\n")
            if 5 in settings:
                ssh_config.write("UsePAM no\n")
            if 6 in settings:
                new_port = input("[#]Enter the new SSH port number: ")
                ssh_config.write("Port " + new_port + "\n")
            ssh_config.close()
            os.system("systemctl restart ssh -y > /dev/null")  
            print("[#]Configuring SSH finished!")
        elif module == '4':
            os.system("apt-get install vsftpd -y > /dev/null")
            ftp_config = open('/etc/vsftpd.conf', 'a')
            print("[#]Which security settings do you want to apply?")
            print("1. Disable anonymous FTP access")
            print("2. Restrict FTP access to local users only")
            print("3. Enable userlist file")
            print("4. Enable write access for local users")
            print("5. Allow FTP access from specific IP addresses")
            print("[#]Enter the numbers of the settings you want to apply, separated by spaces:")
            settings = list(map(int, input().split()))
            if 1 in settings:
                ftp_config.write("anonymous_enable=NO\n")
            if 2 in settings:
                ftp_config.write("chroot_local_user=YES\n")
            if 3 in settings:
                ftp_config.write("userlist_enable=YES\n")
            if 4 in settings:
                ftp_config.write("write_enable=YES\n")
            if 5 in settings:
                allowed_ips = input("[#]Enter the IP addresses allowed to access FTP, separated by spaces: ")
                ftp_config.write("tcp_wrappers=YES\n")
                ftp_config.write("allow_file=/etc/vsftpd.allowed_ips\n")
                allowed_ips_file = open('/etc/vsftpd.allowed_ips', 'w')
                allowed_ips_file.write(allowed_ips)
                allowed_ips_file.close() 
            ftp_config.close()
            os.system("systemctl restart vsftpd -y > /dev/null")
            print("[#]Configuring FTP finished!")
        elif module == '5':
            os.system("apt-get install samba -y > /dev/null")
            samba_config = open('/etc/samba/smb.conf', 'a')
            print("[#W]hich security settings do you want to apply?")
            print("1. Encrypt passwords")
            print("2. Restrict anonymous access")
            print("3. Limit access to specific users")
            print("4. Limit access to specific IP addresses")
            print("5. Require SMB signing")
            print("[#]Enter the numbers of the settings you want to apply, separated by spaces:")
            settings = list(map(int, input().split()))
            if 1 in settings:
                samba_config.write("encrypt passwords = yes\n")
            if 2 in settings:
                samba_config.write("restrict anonymous = 2\n")
            if 3 in settings:
                users = input("[#]Enter the usernames of the users who should have access, separated by spaces: ")
                samba_config.write("valid users = " + users + "\n")
            if 4 in settings:
                ips = input("[#]Enter the IP addresses of the machines that should have access, separated by spaces: ")
                samba_config.write("hosts allow = " + ips + "\n")
            if 5 in settings:
                samba_config.write("server signing = mandatory\n")
                samba_config.write("client signing = mandatory\n")
            samba_config.close()
            os.system("systemctl restart smb -y > /dev/null")
            print("[#]Configuring SMB finished!")
        elif module == '6':
            print("[#]Which security settings do you want to apply?")
            print("1. Bind to localhost")
            print("2. Disable networking")
            print("3. Increase max connections and thread cache size")
            print("4. Enable query caching")
            print("5. Enable event scheduler")
            print("[#]Enter the numbers of the settings you want to apply, separated by spaces:")
            settings = list(map(int, input().split()))
            os.system("apt-get install mysql-server")
            os.system("mysql_secure_installation")
            mysql_config = open('/etc/mysql/mysql.conf.d/mysqld.cnf', 'a')
            mysql_config.write("# MySQL security settings\n")
            if 1 in settings:
                mysql_config.write("bind-address = 127.0.0.1\n")
            if 2 in settings:
                mysql_config.write("skip-networking\n")
            if 3 in settings:
                mysql_config.write("max_connections = 500\n")
                mysql_config.write("thread_cache_size = 50\n")
            if 4 in settings:
                mysql_config.write("query_cache_limit = 1M\n")
                mysql_config.write("query_cache_size = 16M\n")
            if 5 in settings:
                mysql_config.write("event_scheduler = ON\n")
            mysql_config.close()
            os.system("systemctl restart mysql")
            print("[#]Configuring Apache finished!")
        elif module == "7":
            print("[#]Which security settings do you want to apply?")
            print("1. Disable directory listing")
            print("2. Disable server status")
            print("3. Enable HTTP headers")
            print("4. Enable URL rewriting")
            print("[#]Enter the numbers of the settings you want to apply, separated by spaces:")
            settings = list(map(int, input().split()))    
            if settings == "1":
                os.system("a2dismod -f autoindex")
            elif settings == "2":
                os.system("a2dismod -f status")
            elif settings == "3":
                os.system("a2enmod -f headers")
            elif settings == "4":
                os.system("a2enmod -f rewrite")
            os.system("systemctl restart apache2")
            print("[#]Configuring Apache finished!")
        elif module == "8":
            os.system("apt-get install openvpn")
            os.system("openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj \"/C=US/ST=New York/L=New York/O=Company/OU=IT Department/CN=vpn.example.com\" -keyout /etc/openvpn/server.key -out /etc/openvpn/server.crt")
            openvpn_config = open('/etc/openvpn/server.conf', 'a')
            print("[#]Which OpenVPN security settings would you like to apply?")
            print("1. Basic (recommended for most users)")
            print("2. Advanced (recommended for experienced users)")
            choice = input("[#]Enter your choice (1 or 2): ")
            if choice == "1":
                openvpn_config.write("# OpenVPN Basic Security Settings\n")
                openvpn_config.write("user nobody\n")
                openvpn_config.write("group nogroup\n")
                openvpn_config.write("cipher AES-256-CBC\n")
                openvpn_config.write("auth SHA256\n")
                openvpn_config.write("tls-version-min 1.2\n")
                openvpn_config.write("keepalive 10 120\n")
                openvpn_config.write("persist-key\n")
                openvpn_config.write("persist-tun\n")
                openvpn_config.write("status /var/log/openvpn-status.log\n")
                openvpn_config.write("log-append /var/log/openvpn.log\n")
                print("[#]Configuring OpenVPN finished!")
            elif choice == "2":
                openvpn_config.write("# OpenVPN Advanced Security Settings\n")
                openvpn_config.write("user nobody\n")
                openvpn_config.write("group nogroup\n")
                openvpn_config.write("cipher AES-256-CBC\n")
                openvpn_config.write("auth SHA512\n")
                openvpn_config.write("tls-cipher TLS-DHE-RSA-WITH-AES-256-CBC-SHA:TLS-DHE-DSS-WITH-AES-256-CBC-SHA:TLS-RSA-WITH-AES-256-CBC-SHA\n")
                openvpn_config.write("tls-version-min 1.2\n")
                openvpn_config.write("tls-auth /etc/openvpn/ta.key 0\n")
                openvpn_config.write("key-direction 0\n")
                openvpn_config.write("keepalive 10 120\n")
                openvpn_config.write("persist-key\n")
                openvpn_config.write("persist-tun\n")
                openvpn_config.write("status /var/log/openvpn-status.log\n")
                openvpn_config.write("log-append /var/log/openvpn.log\n")
                print("[#]Configuring OpenVPN finished!")
            else:
                print("Invalid choice. Please enter 1 or 2.")
                return
            openvpn_config.close()
            os.system("openvpn --genkey --secret /etc/openvpn/ta.key")
            os.system("systemctl enable openvpn-server@server.service")
            os.system("systemctl start openvpn-server@server.service")
        elif module == "9":
            os.system("apt-get install fail2ban")
            jail_local_config = open('/etc/fail2ban/jail.local', 'a')
            jail_local_config.write("[sshd]\n")
            jail_local_config.write("enabled = true\n")
            jail_local_config.write("port = ssh\n")
            jail_local_config.write("filter = sshd\n")
            jail_local_config.write("logpath = /var/log/auth.log\n")
            jail_local_config.write("maxretry = 5\n")
            jail_local_config.write("findtime = 1d\n")
            jail_local_config.write("bantime = 1d\n")
            jail_local_config.close()
            os.system("systemctl enable fail2ban")
            os.system("systemctl start fail2ban")
            print("[#]Configuring Fail2Ban finished!")
        elif module == "10":
            os.system("apt-get install ufw")
            os.system("ufw enable")
            os.system("ufw default deny incoming")
            os.system("ufw default allow outgoing")
            os.system("ufw allow ssh")
            os.system("ufw allow http")
            os.system("ufw allow https")
            os.system("systemctl enable ufw")
            os.system("systemctl start ufw")
            print("[#]Configuring UFW finished!")
        elif module == "11":
            os.system("apt-get install clamav")
            clamd_local_config = open('/etc/clamav/clamd.conf', 'a')
            clamd_local_config.write("LocalSocket /var/run/clamav/clamd.ctl\n")
            clamd_local_config.write("LogFile /var/log/clamav/clamav.log\n")
            clamd_local_config.write("LogSyslog false\n")
            clamd_local_config.write("LogRotate true\n")
            clamd_local_config.write("LogFacility LOG_LOCAL6\n")
            clamd_local_config.write("User clamav\n")
            clamd_local_config.write("TCPSocket 3310\n")
            clamd_local_config.close()
            os.system("freshclam")
            os.system("systemctl enable clamav-daemon")
            os.system("systemctl start clamav-daemon")
            print("[#]Configuring ClamAV finished!")
        elif module == '0':
            print("[#]Goodbye!")
            break
        else:
            print("[#]Wrong module chosen.")

if __name__ == "__main__":
    main()
