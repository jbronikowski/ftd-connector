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

import logging
import paramiko
import re
import socket
import struct
import time
import traceback


__author__ = "Josh Bronikowski <jbroniko@cisco.com>"
__copyright__ = "Copyright (c) 2019 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"


class ftd_connection(object):
    """This is a python class to help FTD connections."""

    def __init__(
        #  Establish class
        self,
        ip="",
        username="",
        password="",
        remote_server=None,
        remote_path=None,
        remote_username=None,
        remote_password=None,
        image_name=None,
        image_hash=None,
        snort_level=None,
        verbose=False,
        debug_level="DEBUG"
    ):
        """This is a python class to help FTD connections."""
        self.ip = ip
        self.username = username
        self.password = password
        self.remote_server = remote_server
        self.remote_path = remote_path
        self.remote_username = remote_username
        self.remote_password = remote_password
        self.image_name = image_name
        if self.image_name:
            self.image_folder = '-'.join(self.image_name.split('-', 2)[:2])
        self.image_hash = image_hash
        self.snort_level = snort_level
        self.newline = '\r'
        self.current_send_string = ''
        self.channel = ""
        self.ansi_escape_codes = False
        self.RETURN = "\r"
        self.RESPONSE_RETURN = "\n"
        self.global_delay_factor = 1
        self.timeout = 100
        self.buffer_size = 1024
        self.verbose = verbose
        self.encoding = 'utf-8'
        self.current_output = ''
        self.current_output_clean = ''
        self.current_send_string = ''
        self.last_match = ''
        self.prompt = ''
        self.expert_mode_enabled = False
        self.troubleshoot_file_location = ""
        self.debug_level = debug_level
        self.upgradeErrors = False
        self.logger = logging.getLogger(__name__)
        if self.verbose:
            extra = {'ip': self.ip}
            self.logger.setLevel(self.debug_level)
            self.c_handler = logging.StreamHandler()
            self.c_format = logging.Formatter('%(asctime)s - %(ip)s - %(name)s.%(funcName)s - %(levelname)s - %(message)s')
            self.c_handler.setFormatter(self.c_format)
            self.logger.addHandler(self.c_handler)
            self.logger = logging.LoggerAdapter(self.logger, extra)
        self.establish_connection()
        self.establish_channel()
        self.wait_for_inital_prompt()

    def __enter__(self):
        """Establish a session using a Context Manager."""
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Gracefully close connection on Context Manager exit."""
        self.disconnect()

    def output_callback(self, msg):
        """Standard print to the terminal."""
        # if self.verbose:
        #     sys.stdout.write(msg + '\n')
        #     sys.stdout.flush()

    def establish_connection(self):
        """Establish a session with client with paramiko."""
        try:
            print(self.ip)
            self.logger.info("Trying to connect to %s", self.ip)
            # Create a new SSH client object
            self.client = paramiko.client.SSHClient()
            # Set SSH key parameters to auto accept unknown hosts
            self.client.load_system_host_keys()
            # Set SSH key parameters to auto accept unknown hosts
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Connect to the host
            self.client.connect(hostname=self.ip,
                                username=self.username,
                                password=self.password,
                                timeout=10
                                )
            self.logger.info("Successfully connected to %s", self.ip)

        except socket.error:
            self.logger.error("Socket error while \
                    trying to connect to {}".format(self.ip))

        except paramiko.AuthenticationException:
            self.logger.error("Authentication error while \
                    trying connect to {}".format(self.ip))
            return

        except paramiko.SSHException:
            return
        except Exception:
            traceback.print_exc()
        return ""

    def establish_channel(self, width=80, height=200):
        """Request an interactive shell session on this channel.

        If the server allows it, the channel will then
        be directly connected to the stdin, stdout, and stderr of the shell.
        """
        self.channel = self.client.invoke_shell(width=width, height=height)
        return ""

    def send(self, send_string):
        """Saves and sends the send string provided."""
        self.current_send_string = send_string

        """Sends command to ssh session"""
        self.channel.send(send_string + self.newline)

        """Displays to std output. Will hide password from output"""
        if send_string is self.password:
            send_string = 'Encypted Password being Sent'
        self.output_callback(send_string)
        #  Logging data to logger
        self.logger.debug("Sending data - %s", send_string)

    def send_wait_for_prompt(self, send_string):
        """Finds prompt then sends string."""
        #  Logging data to logger
        self.logger.info("Sending commnd and will wait for prompt")
        self.find_prompt()
        self.send(send_string)
        self.expect()
        return self.current_output_clean

    def send_command_clish(self, send_string):
        """Sends command via clish."""
        #  Logging data to logger
        self.logger.info("Sending command via Clish")
        if self.expert_mode_enabled:
            self.enter_clish_mode()
        return self.send_wait_for_prompt(send_string)

    def send_command_expert(self, send_string):
        """Sends command via expert mode"""
        #  Logging data to logger
        self.logger.info("Sending command via Expert")
        if not self.expert_mode_enabled:
            #  Logging data to logger
            self.logger.debug("Device in Clish mode")
            self.enter_expert_mode()
        return self.send_wait_for_prompt(send_string)

    def read_channel(self):
        """Generic handler that will read all the data from session."""
        output = ""
        while True:
            if self.channel.recv_ready():
                outbuf = self.channel.recv(65535)
                if len(outbuf) == 0:
                    raise EOFError("Channel stream closed by remote device.")
                output += outbuf.decode("utf-8", "ignore")
            else:
                break
        return output

    def clear_buffer(self):
        """Read any data available in the channel."""
        #  Logging data to logger
        self.logger.debug("Clearing buffer for next command")
        self.read_channel()

    def expect(self, re_strings='', timeout=None):
        """This function takes in a regular expression (or regular expressions)
        that represent the last line of output from the server.
        The function waits for one or more of the terms to be matched.
        The regexes are
        matched using expression \n<regex>$ so you'll need to provide an
        easygoing regex such as '.*server.*' if you wish to have a fuzzy
        match.

        :param re_strings: Either a regex string or list of regex strings
                            that we should expect; if this is not specified,
                            then EOF is expected (i.e. the shell is completely
                            closed after the exit command is issued)
        :param timeout: Timeout in seconds.  If this timeout is exceeded,
                            then an exception is raised.
        """

        if len(re_strings) is 0:
            re_strings = '.*{}.*'.format(self.prompt.strip())

        # Set the channel timeout
        timeout = timeout if timeout else self.timeout
        self.channel.settimeout(timeout)

        # Create an empty output buffer
        self.current_output = ''

        # This function needs all regular expressions to be in the form of a
        # list, so if the user provided a string, let's convert it to a 1
        # item list.
        if isinstance(re_strings, str) and len(re_strings) != 0:
            re_strings = [re_strings]

        # Loop until one of the expressions is matched or loop forever if
        # nothing is expected (usually used for exit)
        while (
            len(re_strings) == 0 or
            not [re_string for re_string in re_strings
                 if re.match('.*\n' + re_string + '$', self.current_output, re.DOTALL)]
        ):
            # Read some of the output
            current_buffer = self.channel.recv(self.buffer_size)

            # If we have an empty buffer, then the SSH session has been closed
            if len(current_buffer) == 0:
                break

            # Convert the buffer to our chosen encoding
            current_buffer_decoded = current_buffer.decode(self.encoding)

            # Strip all ugly \r (Ctrl-M making) characters from the current
            # read
            current_buffer_decoded = current_buffer_decoded.replace('\r', '')

            # Display the current buffer in realtime if requested to do so
            # (good for debugging purposes)

            current_buffer_decoded = self.strip_ansi_codes(
                current_buffer_decoded)

            self.output_callback(current_buffer_decoded)
            for split_line in current_buffer_decoded.split('\n'):
                #  Logging data to logger
                self.logger.debug("Received data - {}".format(split_line))

            # Add the currently read buffer to the output
            self.current_output += current_buffer_decoded

        # Grab the first pattern that was matched
        if len(re_strings) != 0:
            found_pattern = [(re_index, re_string)
                             for re_index, re_string in enumerate(re_strings)
                             if re.match('.*\n' + re_string + '$',
                                         self.current_output, re.DOTALL)]

        # Clean the output up by removing the sent command
        self.current_output_clean = self.current_output
        if len(self.current_send_string) != 0:
            self.current_output_clean = (
                self.current_output_clean.replace(
                    self.current_send_string + '\n', ''
                )
            )

        # Reset the current send string to ensure that multiple expect calls
        # don't result in bad output cleaning
        self.current_send_string = ''

        # Clean the output up by removing the expect output from the end if
        # requested and save the details of the matched pattern
        if len(re_strings) != 0 and len(found_pattern) != 0:
            self.current_output_clean = (
                re.sub(
                    found_pattern[0][1] + '$', '', self.current_output_clean
                )
            )
            self.last_match = found_pattern[0][1]
            return found_pattern[0][0]
        else:
            # We would socket timeout before getting here, but for good
            # measure, let's send back a -1
            return -1

    def tail(self,
             bufferCount=1, progressBar=False, line_prefix=None,
             callback=None, output_callback=None,
             stop_callback=lambda x: False,
             timeout=None):

        """
        This function takes control of an SSH channel and displays line
        by line of output as \n is recieved.  This function is specifically
        made for tail-like commands.

        :param line_prefix: Text to append to the left of each line of output.
                            This is especially useful if you are using my
                            MultiSSH class to run tail commands over multiple
                            servers.
        :param callback: You may optionally supply a callback function which
                         takes two paramaters.  The first is the line prefix
                         and the second is current line of output. The
                         callback should return the string that is to be
                         displayed (including the \n character).  This allows
                         users to grep the output or manipulate it as
                         required.
        :param output_callback: A function used to print ssh output. Printed to
                        stdoutby default. A user-defined logger may be passed
                        like output_callback=lambda m: mylog.debug(m)
        :param stop_callback: A function usesd to stop the tail, when function
        returns. True tail will stop, by default stop_callback=lambda x: False
        :param timeout: how much time to wait for data, default to None which
                        mean almost forever.
        """

        output_callback = output_callback if output_callback else self.output_callback

        # Set the channel timeout to the maximum integer the server allows,
        # setting this to None breaks the KeyboardInterrupt exception and
        # won't allow us to Ctrl+C out of teh script
        timeout = timeout if timeout else 2 ** (
            struct.Struct(str('i')).size * 8 - 1) - 1
        self.channel.settimeout(timeout)

        # Create an empty line buffer and a line counter
        current_line = b''
        received_buffer = b''
        line_counter = 0
        line_feed_byte = '\n'.encode(self.encoding)

        # Loop forever, Ctrl+C (KeyboardInterrupt) is used to break the tail
        while True:

            # Read the output one byte at a time so we can detect \n correctly
            buffer = self.channel.recv(bufferCount)
            # If we have an empty buffer, then the SSH session has been closed
            if len(buffer) == 0:
                break

            # Add the currently read buffer to the current line output
            current_line += buffer
            received_buffer += buffer
            if progressBar:
                received_buffer += '\n'

            # Display the last read line in realtime when we reach a \n
            # character
            if buffer == line_feed_byte or progressBar is True:
                current_line_decoded = current_line.decode(self.encoding)
                if line_counter:
                    output_callback(current_line_decoded)

                    if current_line_decoded.find('\n') > 0:
                        for current_line_decoded_split in current_line_decoded.split('\n'):
                            #  Logging data to logger
                            if current_line_decoded_split:
                                self.logger.debug("Received data - {}".
                                                  format(current_line_decoded_split))
                    else:
                        #  Logging data to logger
                        self.logger.debug(
                            "Received data - {}".format(
                                current_line_decoded)
                        )

                if stop_callback(current_line_decoded):
                    break
                #  Increase line_counter by 1 and reset current_line
                line_counter += 1
                current_line = b''
        #  Return collected buffer during the entire tail command
        return received_buffer

    def find_prompt(self, delay_factor=1):
        """Find current network device prompt.

        :param delay_factor:
        :type delay_factor: int
        """
        #  Logging data to logger
        self.logger.debug("Finding prompt")
        # Clearing buffer to ensure we gather just the prompt
        self.clear_buffer()
        #  Sending return to session
        self.send(self.RETURN)
        # Waiting by 1xdelay factor.
        time.sleep(delay_factor * 1)

        # Initial attempt to get prompt
        prompt = self.read_channel()

        # Check if the only thing you received was a newline
        count = 0
        prompt = prompt.strip()
        while count <= 10 and not prompt:
            prompt = self.read_channel().strip()
            if prompt:
                pass
            else:
                self.send(self.RETURN)
                time.sleep(delay_factor * 0.1)
            count += 1

        # If multiple lines in the output take the last line
        #  prompt = self.normalize_linefeeds(prompt)
        prompt = prompt.split(self.RESPONSE_RETURN)[-1]
        prompt = prompt.strip()
        if not prompt:
            #  Logging data to logger
            self.logger.error("Unable to find prompt: {}".format(prompt))
        time.sleep(delay_factor * 0.1)
        self.clear_buffer()
        #  Storing prompt in self.prompt for future use
        self.prompt = prompt
        return prompt

    def wait_for_inital_prompt(self, timeout=15):
        """This function allows the session to wait for FTD to fully load."""
        #  Logging data to logger
        self.logger.info("Waiting for initial prompt")
        #  Expecting to see intial > from FTD
        self.expect('.*>.*', timeout=timeout)

    def enter_expert_mode(self):
        """This function does the suquence of commnds to enter expert mode"""
        #  Logging data to logger
        self.logger.info('Entering Expert Mode')
        self.send('expert')
        self.expect('.*admin@.*', timeout=15)
        self.send('sudo su')
        self.expect('.*[pP]assword:.*|.*root@.*', timeout=5)
        #  If assword is seen in response, send password. This is used when
        #  first attempt to get into expert mode.
        if 'assword:' in self.current_output:
            self.send(self.password)
            self.expect('.*root@.*', timeout=5)
        #  Setting expert_mode_enable as a varible to reference later on
        self.expert_mode_enabled = True

    def enter_clish_mode(self):
        """This function does the suquence of commnds to enter clish mode"""
        if self.expert_mode_enabled:
            #  Logging data to logger
            self.logger.info('Entering Clish Mode')
            self.send('su admin')
            self.expect('.*>.*')
            #  Setting expert_mode_enable as a varible to reference later on
            self.expert_mode_enabled = False

    def check_failover_status(self):
        """This function returns failover status from clish."""
        #  Logging data to logger
        self.logger.info("Checking Failover Status")
        return self.send_command_clish('show failover | include Failover unit')

    def show_int_brief(self):
        """This function returns interface information from clish."""
        #  Logging data to logger
        self.logger.info("Checking interface brief")
        return self.send_command_clish("show int ip brief")

    def check_file_exsits(self, path):
        """This will check is a file exisitng and return true if it does"""
        #  Logging data to logger
        self.logger.info("Checking if {} exists".format(path))

        output = self.send_command_expert('[ -f {} ] || echo $SF_ROOT_PATH'.format(path))
        if "/ngfw" in output:
            return False
        return True

    def check_md5_hash(self, path, hash):
        """This fuction check the hash against the provided hash for file"""
        #  Logging data to logger
        self.logger.info("Checking MD5 hash for %s", path)
        self.send_command_expert('md5sum {}'.format(path))
        #  Checking hash against hash provided and returns true or false
        if hash in self.current_output_clean:
            return True
        return False

    def check_image(self):
        if self.image_name and self.image_hash is None:
            #  Logging data to logger
            self.logger.error(
                "No image or hash has been declared to the object")
            return "No image or hash has been declared to the object"
        #  Checks image from object that was set in class creation
        return self.check_md5_hash('/var/sf/updates/{}'.format(
            self.image_name), self.image_hash)

    def check_snort_verison(self):
        """Checking snort verison and returning value"""
        #  Logging data to logger
        self.logger.info("Checking snort version")

        #  Check if snort level has been set
        if not self.snort_level:
            self.logger.error("No snort level specific in object. Quiting")
            quit()

        #  Checking level
        if self.snort_level not in self.send_command_expert('sudo /var/sf/detection_engines/*/snort -V'):
            self.logger.error("Snort levels do not match")
            return False

        self.logger.info("Snort levels match")
        return True

    def scp_client(self, direction, local_path, remote_server, remote_path,
                   remote_username, remote_password):
        """SCP Client that can be used as GET or PUT.
        :param direction: PUT or GET
        :param local_path: local file or folder including entire local_path
        :param remote_server: IP or hostname
        :param remote_path: Specify the path for remote_server
        :param remote_username: remote_server username
        :param remote_password: remote_server password
        """

        #  Logging data to logger
        self.logger.info("Creating SCP Session")
        #  Checking if session is in expert mode. If not, will enter
        if not self.expert_mode_enabled:
            self.enter_expert_mode()

        #  Error responses that will terminate session any time it is seen
        errorResponses = [
            "No such file or directory",
            "Is a directory",
            "Permission denied"
        ]

        #  stop_callback is used to listen to every message that is received,
        #  and acts opon it
        def stop_callback(msg):
            if any(error in msg for error in errorResponses):
                #  Logging data to logger
                self.logger.error(msg)
                quit()
            # Stop if prompt is seen
            return self.prompt in msg

        # output_callback can be used for any additonal function to store data.
        def output_callback(msg):
            return

        try:
            #  Trying to find prompt to ensure we know when file is complete
            self.find_prompt()
            if direction is 'GET':
                #  Logging data to logger
                self.logger.info("Getting data {}@{}:{} {}".format(
                                 remote_username, remote_server, remote_path,
                                 local_path))

                #  Using the native SCP within FTD
                self.send("scp -o StrictHostKeyChecking=no {}@{}:{} {}".format(
                    remote_username, remote_server, remote_path, local_path))
            if direction is 'PUT':
                #  Logging data to logger
                self.logger.info("Sending data {}@{}:{} {}".format(
                    remote_username, remote_server, remote_path, local_path))

                #  Using the native SCP within FTD
                self.send("scp -o StrictHostKeyChecking=no -r {} {}@{}:{}".
                          format(local_path, remote_username,
                                 remote_server, remote_path))
            self.expect('.*[pP]assword:.*', timeout=15)

            #  Sending SCP remote password to ssh session
            self.send(remote_password)
        except Exception as e:
            raise

        #  Monitoring output from ssh session
        output = self.tail(bufferCount=1024, progressBar=True,
                           output_callback=output_callback,
                           stop_callback=stop_callback)

        #  Logging data to logger
        self.logger.info("SCP Session Complete")

        return output

    def get_image_from_server(self):
        """Gathering image from SCP Server with infommation specified in
            object
            """

        #  Logging data to logger
        self.logger.info("Gathering image from SCP Server")

        #  Using scp_client to get image from SCP server
        self.scp_client('GET', '/var/sf/updates/', self.remote_server,
                        self.remote_path + self.image_name,
                        self.remote_username, self.remote_password)

    def send_files_to_server(self, local_path):
        """Sending files/folders SCP Server with infommation specified in
            object
            """

        #  Logging data to logger
        self.logger.info("Sending files to SCP Server")

        #  Using scp_client to get image from SCP server
        self.scp_client('PUT', local_path, self.remote_server,
                        self.remote_path + self.ip + "/",
                        self.remote_username, self.remote_password)

    def image_exist(self):
        """Check to see if image already is downloaded and valid"""

        self.logger.info("Checking if image exist on FTD")
        if self.check_file_exsits("/var/sf/updates/" + self.image_name):
            if self.check_image():
                self.logger.info("Image exist and hash is valid")
                return True
        return False

    def get_image_from_http(self, url):
        """Gathering image from http server and storing in /var/sf/updates"""

        #  Logging data to logger
        self.logger.info("Gathering image from http server")

        #  Checking if session is in expert mode. If not, will enter
        if not self.expert_mode_enabled:
            self.enter_expert_mode()

        #  Error responses that will terminate session any time it is seen
        errorResponses = [
            "wget:"
        ]

        #  stop_callback is used to listen to every message that is received,
        #  and acts opon it
        def stop_callback(msg):
            if any(error in msg for error in errorResponses):
                #  Logging data to logger
                self.logger.error(msg)
                quit()
            # Stop if prompt is seen
            return self.prompt in msg

        def output_callback(msg):
            return

        try:
            #  Trying to find prompt to ensure we know when file is complete
            self.find_prompt()
            #  Using native wget command within FTD
            self.send(
                'wget {} -O /var/sf/updates/{}'.
                format(url, url.split('/')[-1]))
        except Exception as e:
            raise

        #  Monitoring output from ssh session
        output = self.tail(bufferCount=1024, progressBar=True,
                           output_callback=output_callback,
                           stop_callback=stop_callback)

        #  Logging data to logger
        self.logger.info("Gathered image from http server")
        return output

    def get_device_info(self, value="''"):
        """Get device info from /etc/sf/ims.conf"""

        #  Logging data to logger
        self.logger.info("Gathering device information")

        #  Sending command via expert mode
        self.send_command_expert(
            'cat /etc/sf/ims.conf | grep {}'.format(value))
        if value is '':
            return self.current_output_clean
        return self.current_output_clean.split('=')[-1]

    def start_readiness_check(self):
        """Start readiness check in --detach mode."""

        #  Logging data to logger
        self.logger.info("Checking for image")
        if not self.check_file_exsits("/var/sf/updates/{}".format(self.image_name)):
            self.logger.error("Image file does not exist. Exiting")
            quit()

        self.logger.info("Starting readiness check for image %s", self.image_name)
        self.logger.info("Cleaning up old log files")

        #  Sending command via expert mode.
        self.send_command_expert("rm -rf /var/log/sf/" + self.image_folder)
        output = self.send_command_expert('install_update.pl --detach --readiness-check /var/sf/updates/{}'.format(self.image_name))
        #  Logging data to logger
        self.logger.info("Started readiness check for image %s", self.image_name)
        return output

    def monitor_readiness_check(self):
        """Start readiness check in --detach mode."""
        #  Logging data to logger
        self.logger.info("Starting to monitor readiness check for image %s",
                         self.image_name)

        #  Checking if session is in expert mode. If not, will enter
        if not self.expert_mode_enabled:
            self.enter_expert_mode()

        #  Error responses that will terminate session any time it is seen
        errorResponses = [
            "not a signed"
        ]

        #  stop_callback is used to listen to every message that is received,
        #  and acts opon it
        def stop_callback(msg):
            if any(error in msg for error in errorResponses):
                #  Logging data to logger
                self.logger.error(msg)
                quit()
            # Stop if prompt is seen
            return "UPGRADE READINESS CHECK COMPLETE" in msg

        # output_callback can be used for any additonal function to store data.
        def output_callback(msg):
            #  Can put any output callback here. To Database, etc
            return

        try:
            self.send('tail -F /var/log/sf/' + self.image_folder + '/upgrade_readiness/main_upgrade_script.log')
        except Exception as e:
            raise

        output = self.tail(output_callback=output_callback, stop_callback=stop_callback)
        self.send("\x03")
        self.expect('.*root@.*')
        #  Logging data to logger
        self.logger.info("Readiness has finished")

    def readiness_check_results(self):
        """Start readiness check in --detach mode
            return: True for pass and False for Failed
        """
        #  Logging data to logger
        self.logger.info("Checking readiness check results for image %s", self.image_name)

        #  Checking if session is in expert mode. If not, will enter
        if not self.expert_mode_enabled:
            self.enter_expert_mode()

        self.send_wait_for_prompt('cat /var/log/sf/' + self.image_folder +
                                  '/upgrade_readiness/main_upgrade_script.log \
                                  | grep "UPGRADE READINESS CHECK COMPLETE"')
        if 'No such file or directory' in self.current_output_clean:
            #  Logging data to logger
            self.logger.info("Readiness check has not been started yet.")
            return False, 'No such file or directory'

        if 'PASS' not in str(self.current_output_clean).upper():
            #  Logging data to logger
            self.logger.info("Readiness check failed")
            return False
        #  Logging data to logger
        self.logger.info("Readiness check passed with no issues")
        return True

    def generate_troubleshoot_file(self):
        """This will gerneate out a troubleshoot file and return file location"""

        #  Logging data to logger
        self.logger.info("Generating troubleshoot file")

        #  Checking if session is in expert mode. If not, will enter
        if not self.expert_mode_enabled:
            self.enter_expert_mode()

        # Sending command to generate troubleshoot file
        self.send('sudo sf_troubleshoot.pl')

        #  stop_callback is used to listen to every message that is received,
        #  and acts opon it
        def stop_callback(msg):
            if "not a signed" in msg:
                self.logger.error(msg)
                quit()
            return "Troubleshooting information" in msg

        # output_callback can be used for any additonal function to store data.
        def output_callback(msg):
            if 'Troubleshooting information' in msg:
                msg = msg.split()
                #  Logging data to logger
                self.logger.info("Troubleshoot file has been gererated at %s",
                                 msg[-1])

                # Setting self variable to locaiton of troubleshooting file
                self.troubleshoot_file_location = msg[-1]
            return msg[-1]
        self.tail(output_callback=output_callback, stop_callback=stop_callback)
        return self.troubleshoot_file_location

    def upload_image_logs(self):
        """Upload image logs from upgrade or readiness check"""
        #  Logging data to logger
        self.logger.info("Sending image logs to SCP Server")

        #  Sending Logs to SCP server
        self.send_files_to_server("/var/log/sf/" + self.image_folder)

    def upload_troubleshoot(self):
        """Upload troubleshoot file"""
        #  Logging data to logger
        self.logger.info("Sending troubleshoot file to SCP Server")
        if not self.troubleshoot_file_location:
            self.logger.error("Troubleshoot file not found. Please run generate_troubleshoot_file()")
            quit()
        #  Sending Logs to SCP server
        self.send_files_to_server(self.troubleshoot_file_location)

    def start_upgrade(self):
        """Start upgrade in --detach mode
            return: ssh session output
        """

        self.logger.info("Checking for image")
        if not self.check_file_exsits("/var/sf/updates/{}".format(self.image_name)):
            self.logger.error("Image file does not exist. Exiting")
            quit()

        #  Logging data to logger
        self.logger.info("Starting upgrade for %s", self.image_name)
        self.logger.info("Cleaning up old log files")

        #  Cleaning up old logs for image
        self.send_command_expert("rm -rf /var/log/sf/" + self.image_folder)

        #  Sending upgrade command
        output = self.send_command_expert('install_update.pl --detach /var/sf/updates/{}'.format(self.image_name))
        self.logger.info("Image upgrade has started for %s", self.image_name)
        return output

    def monitor_upgrade(self):
        """Monitor upgrade
            :param image: image to start image
            return: ssh session output
        """
        #  Logging data to logger
        self.logger.info("Monitoring upgrade status for %s", self.image_name)

        #  Checking if session is in expert mode. If not, will enter
        if not self.expert_mode_enabled:
            self.enter_expert_mode()

        #  Error responses that will terminate session any time it is seen
        errorResponses = [
            "not a signed",
            "Fatal error"
        ]

        #  stop_callback is used to listen to every message that is received,
        #  and acts opon it
        def stop_callback(msg):
            if any(error in msg for error in errorResponses):
                #  Logging data to logger
                self.logger.error(msg)
                self.upgradeErrors = True
                return True
            # Stop if System will now rebootn is seen in message
            return "System will now reboot" in msg

        # output_callback can be used for any additonal function to store data.
        def output_callback(msg):

            return

        try:
            self.send('tail -F /var/log/sf/' + self.image_folder + '/status.log')
        except Exception as e:
            raise

        output = self.tail(output_callback=output_callback,
                           stop_callback=stop_callback)

        #  Sending CTRL + C once stop_callback is found
        self.send("\x03")
        self.expect('.*root@.*')

        #  Logging data to logger
        if self.upgradeErrors:
            self.logger.info("Upgrade has failed.")
            return False

        self.logger.info("Upgrade has completed. System will reboot")
        return True

    def normalize_linefeeds(self, a_string):
        """Convert `\r\r\n`,`\r\n`, `\n\r` to `\n.`
        :param a_string: A string that may have non-normalized line feeds
            i.e. output returned from device, or a device prompt
        :type a_string: str
        """

        newline = re.compile("(\r\r\r\n|\r\r\n|\r\n|\n\r)")
        a_string = newline.sub(self.RESPONSE_RETURN, a_string)
        if self.RESPONSE_RETURN == "\n":
            # Convert any remaining \r to \n
            return re.sub("\r", self.RESPONSE_RETURN, a_string)

    def strip_ansi_codes(self, s):
        return re.sub(r'\x1b\[([0-9,A-Z]{1,2}(;[0-9]{1,2})?(;[0-9]{3})?)?[m|K]?', '', s)
