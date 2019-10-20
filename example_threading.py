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
import logging
import threading
import time

__author__ = "Josh Bronikowski <jbroniko@cisco.com>"
__copyright__ = "Copyright (c) 2019 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"

# #  Enabling Logging
logger = logging.getLogger('ftd_connector')
handler = logging.FileHandler('app.log')
formatter = logging.Formatter('%(asctime)s - %(threadName)s - %(name)s.%(funcName)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)


ip_addresses = ['10.91.52.156', '10.91.52.157', '10.91.52.158', '10.91.52.159', '10.91.52.249']
sensor_counter = len(ip_addresses)
print('Total number of sensors: {}\n\n'.format(sensor_counter))

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
    }

    #  Creating connection to device
    with ftd_connection(**my_device) as device:

        #  Sending and storing command via clish
        #  output = device.send_command_clish("config manager add 10.91.52.247 cisco")
        output = device.send_command_expert('md5sum /mnt/disk0/.private/startup-config')
        logger.info("TEST MESSAHE")
        #  device.disconnect()
        print(output)

count = 0
for ipv4 in ip_addresses:
    if ipv4:
        try:
            print('Connecting to {}... - {} of {}'.format(ipv4, sensor_counter - count, sensor_counter))
            threading.Thread(target=ssh_connection, name=ipv4, args=(ipv4,)).start()
        except Exception as error:
            print(error)
        finally:
            time.sleep(.5)

    count += 1
