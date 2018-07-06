#!/usr/bin/env python

import logging
import socket
import ssl
import threading
import json
import uuid
import signal
import select
from collections import OrderedDict
from Queue import Queue
from time import sleep, time
from subprocess import Popen, PIPE
import xml.etree.ElementTree as ElementTree
import argparse
import hashlib
#import random
#import string

logging.basicConfig(level=logging.DEBUG,format='[%(name)-10s] %(message)s',)

RECV_DELIM='\n'
NUM_THREADS = 3
SLEEP_INTERVAL = 0.1

SEND_LOCK = threading.Lock()

SYN = 'syn'
ACK = 'ack'
UDP = 'udp'
NULL = 'null'
FIN = 'fin'
XMAS = 'xmas'
WIN = 'win'
MAI = 'maimon'
CONN = 'connect'
PING = 'ping'
scan_type_map = { SYN :'-sS'
                , ACK :'-sA'
                , UDP :'-sU'
                , NULL:'-sN'
                , FIN :'-sF'
                , XMAS:'-sX'
                , WIN :'-sW'
                , MAI :'-sM'
                , CONN:'-sT'
                , PING:''
                }

def generate_id():
    u_hash = hashlib.md5()
    u_hash.update(str(uuid.getnode()))
    return u_hash.hexdigest()
    
class NMap():
    
    def __init__(self, ip, ports=None):
        self.ip = ip
        self.ports = ports
        self.host_discover = False
        self.logger = logging.getLogger('NMap[%s:%s]' % (ip, ports))
        
    def parse_xml(self, xml):
        results = {}
        #self.logger.debug("XML: %s" % xml)
        tree = ElementTree.fromstring(xml)
        
        runstats = tree.find('runstats').find('finished')
        success = runstats.get('exit')
        
        #TODO if for some reason syntax fails, raise an error which is caught by the AgentHandlers command
        if 'error' in success:
            raise Exception
        
        host = tree.find('host')
        if host is not None:
            ports = host.find('ports')
            times = host.find('times')
            address = host.find('address')
            status = host.find('status')
            host_script = host.find('hostscript')
            os_info = host.find('os')
        
            if os_info is not None:
                os_match = os_info.find('osmatch')
                results['os'] = os_match.get('name') + " (" + os_match.get('accuracy') + "%)"
        
        if status is not None:
            results['host_state'] = status.get('state')
            results['host_reason'] = status.get('reason')
        
        if address is not None:
            results['ip'] = address.get('addr')
        
        if ports is not None:
            port = ports.find('port')
            results['port'] = port.get('portid')
            results['protocol'] = port.get('protocol')
            port_state = port.find('state')
            results['port_state'] = port_state.get('state')
            results['port_reason'] = port_state.get('reason')
            bannerfp = port.find('service')
            bannergrab = port.find('script')
            
            if bannerfp is not None:
                results['service'] = bannerfp.get('servicefp')
            
            if bannergrab is not None:
                results['banner'] = bannergrab.get('output')
            
        if host_script is not None:
            script = host_script.find('script')
            results['script'] = script.get('output')
            # if running the firewalk script, get the entire list of ports returned from the ACK scan and send those back
            if script.get('id') == 'firewalk':
                ports_dict = {}
                all_ports = host.findall('port')
                for porti in all_ports:
                    port_state = porti.find('state')
                    ports_dict[porti.get('portid')] = {'state':port_state.get('state'),'reason':port_state.get('reason')} 
                results['port'] = ports_dict

        if times is not None:
            results['srtt'] = times.get('srtt')

        return results
        
    def build_scan(self, scan_type):
        '''
        This method builds the nmap command line... I dont like the current state of it, but its a quick solution and can be changed later without messing up much.
        '''
        
        # TODO this needs some work. For host discovery lets look at options for icmp address mask requests (type 17) and timestamp requests (type 13)
        if self.host_discover:
            discovery_flag = "-sn"
            dns_resolution = ""
            port_string = ""
        else:
            discovery_flag = "-Pn"
            dns_resolution = "-n"
            port_string = "-p %s" % self.ports
            
        scan_type_option = scan_type_map[scan_type]
        
        nmap_command = "nmap -vv %s %s %s %s %s -oX -" % (dns_resolution, discovery_flag, scan_type_option, port_string, self.ip)
        return nmap_command
    
    def launch_scan(self,nmap_cmd):
        scan = Popen(nmap_cmd.split(), stdin=PIPE, stdout=PIPE)
        output = scan.communicate()[0]
        scan.wait()
        return output
        
    def abstract_scan(self,scan_type):
        nmap_cmd = self.build_scan(scan_type)
        raw_results = self.launch_scan(nmap_cmd)
        #self.logger.debug(raw_results)
        results = self.parse_xml(raw_results) 
        return results
        
    def syn_scan(self):
        return self.abstract_scan(SYN)
    
    def ack_scan(self):
        return self.abstract_scan(ACK)
        
    def scan(self, scan_type):
        return self.abstract_scan(scan_type)
        
    def ping(self):
        self.host_discover = True
        return self.abstract_scan(PING)
        
    def banner_grab(self):
        nmap_cmd = "nmap -vv -n -sT -sV -Pn --script banner -p %s %s -oX -" % (self.ports, self.ip)
        raw_results = self.launch_scan(nmap_cmd)
        results = self.parse_xml(raw_results)
        return results
        
    def firewalk(self):
        nmap_cmd = "nmap -vv -n -Pn -sA --script=firewalk --traceroute -p %s %s -oX -" % (self.ports, self.ip)
        #self.logger.debug(nmap_cmd)
        raw_results = self.launch_scan(nmap_cmd)
        results = self.parse_xml(raw_results)
        return results
        
    def os_detect(self):
        nmap_cmd = "nmap -vv -n -Pn -O -sT %s -oX -" % (self.ip)
        #self.logger.debug(nmap_cmd)
        raw_results = self.launch_scan(nmap_cmd)
        results = self.parse_xml(raw_results)
        return results
        
    def vuln_scan(self):
        #nmap_cmd = "nmap -vv -n -Pn -sS -sV --script=vulnscan --script-args vulscancorrelation=1 -p %s %s -oX -" % (self.ports, self.ip)
        nmap_cmd = "nmap -vv -n -Pn -sV -sC --script vuln -p %s %s -oX -" % (self.ports, self.ip)
        raw_results = self.launch_scan(nmap_cmd)
        results = self.parse_xml(raw_results)
        return results

class AgentWorker(threading.Thread):
    
    '''
    This is the threaded consumer class
    '''
    
    def __init__(self, group=None, target=None, name=None,
                 args=(), kwargs=None, verbose=None):
        threading.Thread.__init__(self, group=group, target=target, name=name,
                                  verbose=verbose)
        self.logger = logging.getLogger('AgentWorker-%d' % kwargs['t_num'])
        self.kwargs = kwargs
        self.client = self.kwargs['client']
        self.keep_running = True
        self.cmd_map = {}
        
    def pong(self,kwargs):
        '''
        test command
        '''
        self.logger.debug('PONG')
        return (True, {'msg':'PONG'})
        
    def syn(self, kwargs):
        '''
        Used to launch the scans
        '''
        target = kwargs['ip']
        port = kwargs['port']

        #scan_type = kwargs['scan_type']
        try:
            scanner = NMap(target,port)
            results = scanner.syn_scan()
            return (True, results)
        except:
            return (False, {})
            
    def ping(self, kwargs):
        target = kwargs['ip']
        
        try:
            scanner = NMap(target, '')
            results = scanner.ping()
            return (True, results)
        except Exception as e:
            raise
            return (False, {})
        
    def banner_grab(self, kwargs):
        target = kwargs['ip']
        port = kwargs['port']
        
        try:
            scanner = NMap(target,port)
            results = scanner.banner_grab()
            return (True, results)
        except:
            return (False, {})
    
    def firewalk(self, kwargs):
        target = kwargs['ip']
        port = kwargs['port']

        try:
            scanner = NMap(target,port)
            results = scanner.firewalk()
            return (True, results)
        except:
            return (False, {})
        
    def os_detect(self, kwargs):
        target = kwargs['ip']

        try:
            scanner = NMap(target, '')
            results = scanner.os_detect()
            return (True, results)
        except:
            return (False, {})
            
    def vuln_scan(self, kwargs):
        target = kwargs['ip']
        port = kwargs['port']

        try:
            scanner = NMap(target,port)
            results = scanner.vuln_scan()
            return (True, results)
        except:
            return (False, {})
        
    def setup_controller(self):
        '''
        Setup the application controller.
        '''
        self.cmd_map['pong'] = self.pong
        self.cmd_map['syn'] = self.syn
        self.cmd_map['ping'] = self.ping
        self.cmd_map['banner_grab'] = self.banner_grab
        self.cmd_map['firewalk'] = self.firewalk
        self.cmd_map['os_detect'] = self.os_detect
        self.cmd_map['vuln_scan'] = self.vuln_scan
        
        ## TODO
        #disconnect
        #stop scans
        
    def run(self):
        self.logger.debug('Starting thread')
        
        #first thing when thread runs, setup the application controller.
        self.setup_controller()
        
        while self.keep_running:
            #block until something is available in the queue
            task = self.client.q.get(True)
            self.logger.debug('Executing task')
            
            task_id = task['task_id']
            session_id = task['session']
            command = task['cmd']
            command_args = task['args']
            
            # fetch and execute the abstract method
            cmd_method = self.cmd_map[command]
            success, results = cmd_method(command_args)
            
            # aggregate results for sending to server
            response = {}
            response['task_id'] = task_id
            response['session'] = session_id
            response['response'] = success
            response['results'] = results
            #response['error'] = True
            #response['error_msg'] = None
            
            #TODO these locks may not be required, but I think when we get high throughput we may encounter issues if we dont have it
            #SEND_LOCK.acquire()
            self.client.queue_response(response)
            #SEND_LOCK.release()
            
            # let the queue know you finished your task
            self.client.q.task_done()


class AgentClient():
    
    '''
    This class acts as the main container for all other working threads
    '''
    def __init__(self,num_threads):
        self.logger = logging.getLogger('AgentClient')
        self.keep_alive = True
        self.sendq = OrderedDict()
        self.num_threads = num_threads
        self.threads = []
        self.q = Queue()
        
    def start_threads(self, num_threads):
        '''
        Spins up the predefined number of threads. Each thread has access to the client object (this) as well as its thread number.
        '''
        for i in range(num_threads):
            worker = AgentWorker(kwargs={'client':self,'t_num':i})
            worker.setDaemon(True) #Set to false, and find way to flag threads to terminate. May be a memory leak here.
            self.threads.append(worker)
            worker.start()
    
    def check_keys(self, keys, data):
        dont_exist = []
        for key in keys:
            if key not in data:
                dont_exist.append(key)
        
        return dont_exist
    
    def send(self,data):
        '''
        handles all the encoding and sending of data to the server.
        '''
        self.logger.debug('Sending data')
        content = json.dumps(data)
        #self.logger.debug("Sending Data: %s" % content)
        self.client_socket.send(content + "\n")
    
    def recv(self):
        '''
        This is a recvall based on a newline delimeter becuase python's worst failure is that it doesnt do this for you.
        '''
        total_data=[];data=''
        while True:
            data=self.client_socket.recv(8192)
            if RECV_DELIM in data:
                total_data.append(data[:data.find(RECV_DELIM)])
                break
            total_data.append(data)
            if len(total_data)>1:
                #check if end_of_data was split
                last_pair=total_data[-2]+total_data[-1]
                if RECV_DELIM in last_pair:
                    total_data[-2]=last_pair[:last_pair.find(RECV_DELIM)]
                    total_data.pop()
                    break
        all_recvd = ''.join(total_data)
        #self.logger.debug("Received Data: %s" % all_recvd)
        return all_recvd
    
    def process_data(self, task):
        '''
        This is the handler for the application controller.
        '''
        
        # process the data by checking its validity and sending it to the 'q'. A worker will pick it up out of there.
        
        # Check the the data received from the server has the necessary KVP

        missing_keys = self.check_keys(['cmd','args','task_id'],task)
        if len(missing_keys) > 0:
            self.logger.debug("Task did not conform.")
            response = {}
            response['args'] = task
            response['error'] = True
            response['error_msg'] = "The following keys are missing: %s" % ','.join(missing_keys)
            self.queue_response(response)
        else:
            # if it does conform, add the task to the queue.
            self.logger.debug("Dispatching task %s" % task['task_id'])
            self.q.put(task)
        
    
    def queue_response(self,response):
        '''
        This queues responses from threads to be sent back to the server. This is controlled by a Lock within the threads handler.
        '''
        task_id = response['task_id']
        self.logger.debug('Queuing response to task %s ' % str(task_id))
        self.sendq[task_id] = response
        
    def check_sendq(self):
        '''
        Checks if data to be sent to the server. If so, grab the first item and send it.
        '''
        if len(self.sendq) > 0:
            task = self.sendq.popitem(last=False)
            self.send(task[1])
    
    def handle(self):
        '''
        This loops handling the sending and receiving of data from the server and any necessary subsequent method calls.
        '''
        
        while self.keep_alive:
            # So we dont blow up the machine, sleep at an interval.
            sleep(SLEEP_INTERVAL)
            try: 
                # Check the sockets status
                r,w,e = select.select([self.client_socket],[self.client_socket],[self.client_socket], 1.0)
                if e:
                    # Socket in error. Its essentially hosed. 
                    self.logger.debug("Error with socket")
                    self.keep_alive = False
                if r:
                    # Server is trying to send something to us. Get it, decode it, dispatch to application controller.
                    self.raw = self.recv()
                    self.data = json.loads(self.raw)
                    self.process_data(self.data)
                if w:
                    # We can send something (socket is almost always going to be writeable, even when ther other end has shut down the socket), check the send queue.
                    self.check_sendq()
            except Exception as e:
                self.logger.debug("An error occured: %s " % e)
                raise
            
        
    def register_agent(self):
        '''
        Handles all communications involved in registering the agent with the server.
        '''
        self.logger.debug("Registering agent")
        self.agent_id = generate_id()
        agent_info = {}
        agent_info['id'] = self.agent_id
        
        self.send(agent_info)
        
        response = json.loads(self.recv())
        
        return response['success']
    
    def disconnect(self):
        '''
        Handle whatever necessary to gracefully disconnect.
        '''
        # TODO do something with the taskings in the queue and being processed. Consider sending a bean with tasks that were pending and never completed...
        self.keep_alive = False
        self.client_socket.close()
        self.logger.debug("Disconnected")
        
    def connect(self, ip, port):
        '''
        Attempts to connect to given ip and port. If successful, starts up worker threads and handler loop.
        '''
        self.logger.debug("Connecting...")
        try:
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            self.client_socket = ssl.wrap_socket(s,
                                       ca_certs="agent_cert.pem",
                                       cert_reqs=ssl.CERT_REQUIRED,
                                       ssl_version=ssl.PROTOCOL_TLSv1)
            self.client_socket.connect((ip,port))

            # Successfully connected, so sends registration info to the server.
            success = self.register_agent()
            
            # If the server accepts the registration (i.e found necessary information, etc), else.
            if success:
                self.logger.debug("Successfully registered")
                # starts the threads and connects them to the tasking queue
                self.start_threads(self.num_threads)
                # Starts the handler loop which listens for tasking from the server and adds them to the shared queue.
                self.handle()
                # Blocked until the handle() loop terminates.
                self.disconnect()
            else:
                self.logger.debug("Failed to register; Server indicated failure")

        except Exception as e:
            self.logger.debug("Error connecting: %s" % e)
            
            
    def shutdown(self, signal, frame):
        '''
        Shutdown client cleanly
        '''
        self.logger.debug("Shutdown initiated")
        import sys
        self.disconnect()
        sys.exit(0)

if __name__ == "__main__":
    
    logger = logging.getLogger('Main')
    
    parser = argparse.ArgumentParser(description='Callback/Callin Scanning Agent')
    parser.add_argument('--action', dest='action', nargs='+', choices=['cb','l'],help='call back or listen', required=True)
    parser.add_argument('--ip', dest='ip', nargs='?', action='store', help='ip to listen from or call-back to.',default='127.0.0.1')
    parser.add_argument('--port', dest='port', nargs='?',action='store', help='port to listen on or call-back to.', required=True)
    parser.add_argument('--interval', dest='interval', nargs='?', action='store', type=int,help='Callback interval in minutes.',default=1)
    parser.add_argument('--threads', dest='num_threads', nargs='?', action='store',type=int,help='Number of threads to run.',default=NUM_THREADS)

    args = parser.parse_args()
    
    import os
    uid = os.getuid()
    if uid != 0:
        logger.debug('Must run as root!')
        sys.exit(0)
    
    logger.debug('Press Ctrl+C to exit')
    
    if 'cb' in args.action:
        logger.debug('Doing callbacks...')
    
        #TODO temporary location. Depends on how we setup the listener part of the agent...
        client = AgentClient(args.num_threads)
        signal.signal(signal.SIGINT, client.shutdown)
    
        # force callback on startup
        last_callback_time = time() - (args.interval * 60)
        while True:
            if (time() - last_callback_time) > args.interval * 60:
                logger.debug('Callback time!')
                client.connect(args.ip,int(args.port))
                last_callback_time = time()
            else:
                logger.debug('Sleep cycle')
                sleep(10)
        
        signal.pause()
        
    elif 'l' in args.action:
        logger.debug('Not yet implemented')
