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

__author__ = "Josh Bronikowski <jbroniko@cisco.com>"
__copyright__ = "Copyright (c) 2019 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"

#  Defining device variables
#       param: ip
#       param: username
#       param: password
#       param: verbose - default is set to False. This will stdout to shell
#       param: debug_level - default is DEBUG. Typical python logging levls
my_device = {
    "ip": "10.0.0.1",
    "username": "admin",
    "password": "C1sco12345",
    "verbose": False,
    "debug_level": "DEBUG"
}

#  Creating connection to device
device = ftd_connection(**my_device)

#  Sending and storing command via expert cli
output = device.send_command_expert("ifconfig")

#  Printing output from device
print(output)
