"""Copyright (c) 2019 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.

"""

from ftd_connector import ftd_connection
import threading
import time

__author__ = "Josh Bronikowski <jbroniko@cisco.com>"
__copyright__ = "Copyright (c) 2019 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"


def ssh_connection(ip_address):
    #  Defining device variables
    #       param: ip
    #       param: username
    #       param: password
    #       param: verbose - default is set to False. This will stdout to shell
    #       param: debug_level - default is DEBUG. Typical python logging levls

    my_device = {
        "ip": ip_address,
        "username": "admin",
        "password": "C1sco12345",
        "verbose": True,
        "debug_level": "DEBUG"
    }

    #  Creating connection to device
    device = ftd_connection(**my_device)

    #  Sending and storing command via clish
    output = device.send_command_clish("show failover")

    #  Printing output from device
    print(output)

ip_addresses = ['10.0.0.1', '10.0.0.2', '10.0.0.3']

try:
    count = 0
    while count < len(ip_addresses):
            for i in xrange(5):
                    threading.Thread(target=ssh_connection, args=(
                        str(ip_addresses[count]),)).start()
                    time.sleep(.3)
                    count += 1
except Exception as e:
        print(e)
