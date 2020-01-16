# roger-skyline-1
42 roger-skyline-1 project let you start your own web server. 

## #Contents

- [Introduction](#introduction)
- [Debian VM Installation](#VMinstall)
- [Updating OS Packages](#OSupdate)
- [Creating Nonroot User](#adduser)
- [Configure a Static IP](#staticIP)
- [Change the SSH Default Port](#sshPort)
- [Setup SSH Access With Publickeys](#sshPubkey)
- [Firewall Setup With UFW](#ufw)
- [DOS (Denial Of Service Attack) protection](#DOS)
- [Protection Against Port Scans](#scanSecure)
- [Disable the Services We Don’t Need](#DisableServices)
- [Update Packages Script](#updateScript)
- [Monitor Crontab Changes Script](#cronScript)
- [Self-signed SSL and Debloyment](#apache)
- [Deployment Automation](#automation)

## #Introduction <a id="introduction"></a>
roger-skyline-1 let you install a Virtual Machine, discover the
basics about system and network administration as well as a lots of services used on a
server machine.

## #Debian VM Installation <a id="VMinstall"></a>
1. Install Debian 10.2 VM with Oracle Virtual Box
2. Creating one primary partition (4.2GB) mounted on / and other one logical on /home
3. Not installing desktop environment

## #Updating OS Packages <a id="OSupdate"></a>
1. First installing sudo -> apt install sudo
2. Get packages up to date -> `sudo apt update` -> `sudo apt upgrade`

## #Creating Nonroot User <a id="adduser"></a>
1. Adding non root user and adding sudo rights -> `sudo adduser login` -> `sudo adduser login sudo`
2. Or you can give sudo rights by modifying sudoers file with `sudo visudo` command

## #Configure a Static IP <a id="staticIP"></a>
https://linuxconfig.org/how-to-setup-a-static-ip-address-on-debian-linux
1. In the virtual box network settings change NAT -> Bridged Adapter
2. Edit the file /etc/network/interfaces and setup our primary network: 
```console
   #The primary network interface
   auto enp0s3
```
3. Creating enp0s3 file into directory /etc/network/interfaces.d/ and add text:
```console
 iface enp0s3 inet static
    address 10.11.203.255
    netmask 255.255.255.252
    gateway 10.11.254.254
```
10.1X.0.0 is the network needed where X is the cluster.
Pick IP that is not taken.

4. Restart the network service and check new ip 
`sudo service networking restart`
`ip a`
if enp0s3 is down run this command to enable
`ip link set enp0s3 up`

## #Change the SSH Default Port <a id="sshPort"></a>
https://www.linuxlookup.com/howto/change_default_ssh_port
1. Modify /etc/ssh/sshd_config
2. Change #Port 22 to port of your choice '50113' 
3. Switch over to the new port by restarting SSH. 
`sudo /etc/init.d/ssh restart`
6. Verify SSH is listening on the new port by connecting to it: ssh valtteri@10.11.203.255 -p 50113

## #Setup SSH Access With Publickeys <a id="sshPubkey"></a>
https://www.linode.com/docs/security/authentication/use-public-key-authentication-with-ssh/
1. Use `ssh-keygen -t rsa` to generate a rsa public/private key pair
2. Just press Enter to accept the default location and file name.
3. Add passphrase when prompted.
This command will generate 2 files id_rsa and id_rsa.pub
    -id_rsa: Our private key, should be keep safely, She can be crypted with a password.
    -id_rsa.pub Our public key, you have to transfer this one to the server.
        To do that we can use: `ssh-copy-id -i /Users/vkurkela/.ssh/id_rsa.pub valtteri@10.11.203.255 -p 50113`
        The key is automatically added in ~/.ssh/authorized_keys on the server
4. Edit again the sshd_config file /etc/ssh/sshd_config to remove root login permit and password authentification
    -Change #PasswordAuthentication to to PasswordAuthentication no
    -Change #PermitRootLogin [...] to PermitRootLogin no and save
5. Restart the SSH daemon service
`sudo service sshd restart and check status`
`sudo service sshd status`
6. Test to connect remotely and check that login is only allowed with public key

## #Firewall Setup With UFW <a id="ufw"></a>
https://www.digitalocean.com/community/tutorials/how-to-set-up-a-firewall-with-ufw-on-ubuntu-18-04
1. First install ufw with sudo apt install ufw
2. Set the following rules
```
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 443
sudo ufw allow 80/tcp
sudo ufw allow 50113/tcp
```
Note that port 80/tcp is HTTP (only for TCP not UDP), 443 is HTTPS, and 50113 is SSH.
TCP is reliable as it guarantees delivery of data to the destination router.

3. Enable service and check your rules
`sudo ufw enable`
`sudo ufw status verbose`

## #DOS (Denial Of Service Attack) protection <a id="DOS"></a>
Denial of service attacks are meant to load a server to a level where it can't serve the intended users with the service.
https://www.garron.me/en/go2linux/fail2ban-protect-web-server-http-dos-attack.html
1. Sudo apt-get install fail2ban
(You need to have apache2 installed or add logpath for HTTP later)
2. Create local file `sudo nano /etc/fail2ban/jail.d/jail-debian.local`
```console
  [DEFAULT]
  bantime  = 10m
  findtime  = 10m
  maxretry = 5

  [sshd]
  enabled = true
  port = 50113
  maxretry = 3
  findtime = 300
  bantime = 600
  logpath = %(sshd_log)s
  backend = %(sshd_backend)s

  [http-get-dos]
  enabled = true
  port = http,https
  filter = http-get-dos
  logpath = /var/log/apache2/access.log
  maxretry = 300
  findtime = 300
  bantime = 600
  action = iptables[name=HTTP, port=http, protocol=tcp]
```
3. Create the filter:
create file /etc/fail2ban/filter.d/http-get-dos.conf and copy the text below in it:
```console
  [Definition]
  failregex = ^<HOST> -.*"(GET|POST).*
  ignoreregex =
```
When a line in the service’s log file matches the failregex in its filter, the defined action is executed for that service.
ignoreregex patterns to filter out what is normal server activity.

4. Restart service by `sudo ufw reload` and `sudo service fail2ban restart` to apply settings
*command to debug fail2ban: `/usr/bin/fail2ban-client -v -v start`
5. Activate fail2ban 
`sudo systemctl enable fail2ban`
6. Check status of fail2ban: 
`sudo systemctl status fail2ban`
*You can an also see the rules added by Fail2Ban by running the following command: `sudo iptables -L`
7. Tested with failed ssh login attempts against 10.11.201.251 and checking that it shows on the log file: 
`tail -f /var/log/fail2ban.log`
And by checking all of the banned ssh actions
`sudo fail2ban-client status sshd`
8. Tested to spam website (reduce maxretry first) and it should show on the log /var/log/fail2ban.log

## #Protection Against Port Scans <a id="scanSecure"></a>
Fail 2ban blocking the IP addresses of connections that perform unsuccessful authentication while portsentry, performs a blocking of IP addresses that are aiming to identify open ports on your Server
https://en-wiki.ikoula.com/en/To_protect_against_the_scan_of_ports_with_portsentry
Install portsentry: `sudo apt-get update && apt-get install portsentry`
1. Edit the /etc/default/portsentry
```console
TCP_MODE="atcp"
UDP_MODE="audp"
```
2. Edit the file /etc/portsentry/portsentry.conf to block UDP/TCP scans
```console
BLOCK_UDP="1"
BLOCK_TCP="1"
```
3. Uncomment the following one:
```console
KILL_ROUTE="/sbin/iptables -I INPUT -s $TARGET$ -j DROP"
```
4. Comment the following line:
```console
#KILL_ROUTE="/sbin/route add -host $TARGET$ reject"
```
5. Restart service and check status:
`sudo service portsentry restart`
`sudo service portsentry status`
6. You can check open ports and which application is listening on what port with `lsof -i -P`
To list all Internet and network files, use the -i option.

## #Disable the Services We Don’t Need <a id="DisableServices"></a>
https://www.digitalocean.com/community/tutorials/how-to-use-systemctl-to-manage-systemd-services-and-units
To check all processes: `systemctl list-units --type service --all`
Check processes that are enabled: `sudo systemctl list-unit-files --type service | grep enabled`

Services needed for this project:
```bash
apache2.service                        enabled //for web server
apparmor.service                       enabled //mandatory access controls
autovt@.service                        enabled //for login
cron.service                           enabled //for cron
dbus-org.freedesktop.timesync1.service enabled //Network Time Synchronization
fail2ban.service                       enabled //for fail2ban
getty@.service                         enabled //login
networking.service                     enabled //raises or downs the network interfaces
rsyslog.service                        enabled //for logs
ssh.service                            enabled //for ssh
sshd.service                           enabled //for ssh
syslog.service                         enabled //for logs
systemd-fsck-root.service              enabled-runtime //for file system checks
systemd-timesyncd.service              enabled //for synchronizing the system clock across the network
ufw.service                            enabled //for ufw
```

1. You can disable rest of the services: 
`sudo systemctl disable SERVICE_NAME`

## #Update Packages Script <a id="updateScript"></a>
1. Create a script: `nano update.sh`
```console
#!/bin/bash
sudo apt-get update -y >> /var/log/update.log
sudo apt-get upgrade -y >> /var/log/update.log
```
2. Give it permissions:
`sudo chmod 755 update.sh`
755 means read and execute access for everyone and also write access for the owner of the file.
3. To automate execution, we must edit the crontab file:
`sudo crontab -e`
To which we add the lines:
```console
0 4 * * 0 sudo ~scripts/update.sh
@reboot sudo ~/scripts/update.sh
```
This execute script every Sunday 4AM and when reboot

## #Monitor Crontab Changes Script <a id="cronScript"></a>
https://www.cyberciti.biz/faq/delete-all-root-email-mailbox/
Install mail:
`sudo apt install mailutils`
1. Create a script:
`nano cron_monitor.sh`
```console
#!/bin/bash
DIFF=$(diff /etc/crontab.back /etc/crontab)
cat /etc/crontab > /etc/crontab.back
if [ "$DIFF" != "" ]; then
    echo "crontab check: changed, notifying admin." | mail -s "crontab modified" root
fi
```
2. Give it permissions:
`sudo chmod 755 cron_monitor.sh`
3. Edit crontab by adding the following line:
```console
0 0 * * * sudo ~/scripts/cron_monitor.sh
```
To read simply type the following command:
`mail`
OR
`mailx`

## #Self-signed SSL and Debloyment <a id="apache"></a>
https://linuxize.com/post/how-to-install-apache-on-debian-10/
https://www.digitalocean.com/community/tutorials/how-to-create-a-self-signed-ssl-certificate-for-apache-in-debian-10
https://haydencdjames.io/linux-securely-copy-files-using-scp/
1. Copy your files into the folder /var/www/html/ You need to create temp folder because you don't have permissions to copy straight into html folder (change index.html to your file)
`scp -P 50113 file.txt username@to_host:/remote/directory/`
2. Install apache web server
3. Create a Self-Signed SSL Certificate for Apache (follow instructions link)

## #Deployment Automation <a id="automation"></a>
Configure a web server with these instructions and you can create a script that copies updated html file from temp folder  to /var/www/html/ if there is changes. Also this script sends mail to root if html file is updated. Script also makes backup.
After this you can create a cron job that runs the script for example once in a week.
!This of course requires that temp folder is updated from host machine before crontab happens!
1. Create script to ~/scripts/update_files.sh
```console
#!/bin/bash
DIFF=$(diff ~/temp/index.html /var/www/html/index.html)
if [ "$DIFF" != "" ]; then
    cat /var/html/index.html > ~/temp/index.html
    sudo cp ~/temp/example.html /var/www/html/index.html
    echo "index.html changed, notifying admin." | mail -s "Deployment done" root
fi
```
2. Add cronjob with `sudo crontab -e`
```console
0 0 * * * sudo ~/scripts/update_files.sh
```
