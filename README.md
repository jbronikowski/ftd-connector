FTD Connector
=======

Cisco FTD library to simplify sending and receiving commands from FTDs  



#### Requires:
- Python 2.7
- Paramiko >= 2.4.2


## Examples:

#### Create a dictionary representing the device.

```py
from ftd_connector import ftd_connection

my_device = {
    "ip": "10.0.0.1",
    "username": "admin",
    "password": "C1sco12345"
}

```
#### Enable Logging.

```py
# #  Enabling Logging
logger = logging.getLogger("ftd_connector")
handler = logging.FileHandler('app.log')
formatter = logging.Formatter('%(asctime)s - %(threadName)s - %(name)s.%(funcName)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

```


#### Establish an SSH connection to the device by passing in the device dictionary.

```py
device = ftd_connection(**my_device)
```

#### Sending Commands
FTD Connector will automatically switch between Clish and Expert mode based on which send method you choose to use. You wont have to worry about entering sudo su or su admin passwords

```py
#  Will send via expert
device.send_command_expert()
```
```py
#  Will send via clish
device.send_command_clish()
```
#### Execute Expert Commands.

```py
output = device.send_command_expert("ifconfig")
print(output)
```
```
br0       Link encap:Ethernet  HWaddr 00:00:00:04:00:01
          inet addr:127.0.4.1  Bcast:127.0.255.255  Mask:255.255.0.0
          inet6 addr: fe80::5492:c4ff:fea6:6f64/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:177534 errors:0 dropped:177528 overruns:0 frame:0
          TX packets:2 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:7101504 (6.7 MiB)  TX bytes:168 (168.0 B)
```
#### Execute Clish Commands.

```py
output = device.send_command_clish("show interface ip brief")
print(output)
```
```
Interface                  IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0         192.168.1.1     YES unset  up                    up
GigabitEthernet0/1         unassigned      YES unset  administratively down up
GigabitEthernet0/2         unassigned      YES unset  administratively down up
Internal-Control0/0        127.0.1.1       YES unset  up                    up
Internal-Data0/0           unassigned      YES unset  up                    up
Internal-Data0/0           unassigned      YES unset  up                    up
Internal-Data0/1           169.254.1.1     YES unset  up                    up
Management0/0              unassigned      YES unset  up                    up
```
####  Readiness Check
```py
my_device = {
    "ip": "10.0.0.1",
    "username": "admin",
    "password": "C1sco12345",
    "remote_server": "10.0.0.10",
    "remote_path": "/var/files/",
    "remote_username": "administrator",
    "remote_password": "C1sco12345",
    "image_name": "Cisco_FTD_Patch-6.2.0.5-38.sh",
    "image_hash": "d906de5be2a19dd7a1c21282aa84636b",
    "snort_level": "2.9.12"
}

device = ftd_connection(**my_device)

#  Get image from scp server if image does not exist
if not device.image_exist():
    device.get_image_from_server()

#  Get image from http server and store in /var/sf/updates by default
if not device.image_exist():
    device.get_image_from_http('http://10.0.0.2/Cisco_FTD_Patch-6.2.0.5-38.sh')

#  Check image md5 hash compared to servers. If it does not match quit
if not device.check_image():
    quit()

#  Start Readiness Check in detach mode
device.start_readiness_check()

#  Monitor Readiness Check
device.monitor_readiness_check()

#  Return results - Returns True or False
if not device.readiness_check_results():
    #  Generate troubleshoot file on failed readiness check
    device.generate_troubleshoot_file()
    #  Upload Troubleshoot and Image Logs
    device.upload_troubleshoot()
    device.upload_image_logs()


#  Checking Snort level
if device.check_snort_verison():
    print("Snort levels match!")
```

#### Upgrade Device

```py
my_device = {
    "ip": "10.0.0.1",
    "username": "admin",
    "password": "C1sco12345",
    "remote_server": "10.0.0.10",
    "remote_path": "/var/files/",
    "remote_username": "administrator",
    "remote_password": "C1sco12345",
    "image_name": "Cisco_FTD_Patch-6.2.0.5-38.sh",
    "image_hash": "d906de5be2a19dd7a1c21282aa84636b",
    "snort_level": "2.9.12"
}

device = ftd_connection(**my_device)

#  Get image from scp server if does not exist
if not device.image_exist():
    device.get_image_from_server()

#  Get image from http server
if not device.image_exist():
    device.get_image_from_http('http://10.0.0.2/Cisco_FTD_Patch-6.2.0.5-38.sh')

#  Check image md5 hash compared to servers. If it does not match quit
if not device.check_image():
    quit()

#  Checking Snort level
if not device.check_snort_verison():
    quit()
#  Start upgrade in detach mode
device.start_upgrade()

#  If upgrade is successfull device will reboot and return true.
#  If failed it will return false
if not device.monitor_upgrade():
    #  Uploading upgrade logs
    device.upload_image_logs()
    #  Generating Troubleshoot
    device.generate_troubleshoot_file()
    #  Upload Troubleshoot
    device.upload_troubleshoot()
```

#### Checking Failover Status
```py
device.check_failover_status()
```
```
Failover unit Primary
```

#### Get Device Information
```py
device.get_device_info()
```
```
OS="Fire Linux OS"
ROOT="/usr/local/sf"
ETC_PATH="/etc/sf"
VAR_RUN="/var/sf/run"
BIN_PATH="${ROOT}/bin"
INITD="/etc/rc.d/init.d"
SFINITD="${ROOT}/etc/init.d"
SFBIN="$BIN_PATH"
SFDATACORRELATOR="${BIN_PATH}/SFDataCorrelator"
HWSERIES=2
SWVERSION=6.2.0.5
SWBUILD=38
PERLVERSION=5.10.1
FEATURE=
OSVERSION=6.2.0
OSBUILD=42
...

```

###### You can return individual config variables
```py
device.get_device_info('SWVERSION')
```
```
6.2.0.5
```

#### SCP Client
```py
#Get files from SCP Server
device.scp_client('GET', local_path, remote_server,
                        remote_path,
                        remote_username, remote_password)

#Push files to SCP Server                        
device.scp_client('PUT', local_path, remote_server,
                        remote_path,
                        remote_username, remote_password)
```




## Questions/Discussion

If you find an issue with FTD Connection, please raise an issue within the issues section



---   
Josh Bronikowski  
Cisco Systems Engineer   
