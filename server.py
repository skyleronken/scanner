#!/usr/bin/env python

# TODO
# Default ports list
# Permit skipping of hsot discovery. In that case, go straight to stage 2.


import threading
import logging
from SocketServer import ThreadingMixIn, StreamRequestHandler, TCPServer
import ssl
import signal
import sys
import json
from pymongo import MongoClient, ASCENDING
from collections import OrderedDict
import select
from time import sleep
import uuid
import datetime
import netaddr
from Queue import Queue, Empty
import random

logging.basicConfig(level=logging.DEBUG,format='[%(name)-10s] %(message)s',)

MONGO_PORT = 27017
MAX_POOL_SIZE = 200 # increase this if db IO is bottleneck
DB_NAME = 'scan_db'
AGENT_LISTENER_DEFAULT_PORT = 9992
SCAN_HANDLER_SLEEP_INTERVAL = .1
AGENT_TASK_THRESHOLD = 10

HOST_DISCOVER_STAGE = 1
SCAN_STAGE = 2
FIREWALK_STAGE = 3 
OS_DETECT_STAGE = 5
BANNER_GRAB_STAGE = 4
VULN_SCAN_STAGE = 6

DEFAULT_SCAN = 'syn'
DEFAULT_DISCOVER = 'ping'

server = None
mongo_client = None
DB = None
agent_map = {}
scan_handlers = {}
active_scans = {}

class APIHandler(StreamRequestHandler):
    
    def __init__(self, request, client_address, server):
        self.logger = logging.getLogger('APIRequestHandler')
        self.command_map = {}
        StreamRequestHandler.__init__(self, request, client_address, server)
        return

    def check_keys(self, keys, data):
        dont_exist = []
        for key in keys:
            if key not in data:
                dont_exist.append(key)
        
        return dont_exist

    def echo_command(self, kwargs):
        '''
        This is a test command for the client API
        '''
        return (True,"PONG")
    
    def start_agent_listener(self, kwargs):
        '''
        This command will start the agent listener on a given port if provided. Else starts it on the default (see globals)
            Arguments:
                'port' : integer : indicating what port to listen on
        '''
        if 'port' in kwargs:
            port = kwargs['port']
        else:
            port = AGENT_LISTENER_DEFAULT_PORT
        results = server.start_agent_server(int(port))
        return (results,None)
        
    def stop_agent_listener(self, kwargs):
        '''
        Command to close down the agent listener
        '''
        results = server.stop_agent_server()
        return (results,None)
        
    def start_scan(self, kwargs):
        '''
        Command to start an existing scan. This assumes that no scanning of the target has occured yet.
            Arguments:
                'scan_id' : str : UUID of the scan to start
        '''
        
        scans = DB.scans
        scan = scans.find_one({'uuid':kwargs['scan_id']})
        
        if scan:
            scan_handler = ScanHandler(kwargs=scan)
            scan_session_id = scan_handler.uuid
            scan_handler.setDaemon(True) #Set to false, and find way to flag threads to terminate. May be a memory leak here.
            scan_handlers[scan_session_id] = scan_handler
            scan_handler.start()
            active_scans[scan_session_id] = scan_handler
            return (True,{})
        else:
            self.logger.debug('Scan not found')
            return (False,{"error":True,"error_msg":"Scan not found"})
    
    def delete_scan(self, kwargs):
        #TODO
        pass
    
    def rerun_scan(self, kwargs):
        scan_id = kwargs['scan_id']
        scan = DB.scans.find_one({'uuid':scan_id})
        
        del scan['_id']
        new_uuid = str(uuid.uuid4())
        scan['uuid'] = new_uuid
        scan["creation_date"] = datetime.datetime.utcnow()
        scan['complete'] = False
        
        scan_id = DB.scans.insert_one(scan).inserted_id
        
        run_results = self.start_scan({'scan_id':new_uuid})

        return run_results
    
    def get_scan_results(self, kwargs):
        #TODO
        pass
    
    def create_scan(self, kwargs):
        '''
        Command to create a new scan.
            Arguments:
                'ips' : str : This is an nmap-like string of IP addresses. 
                                Supported formats: 
                                         CIDR: 192.168.1.0/24
                                        Range: 192.168.1.1-254
                                         List: 192.168.1.1,192.168.1.12,etc (Note, this is still passed as a string)
                'ports' : str : a list of ports to be scanned.
                                Supported formats:
                                         List: 80,8080,443,22
                                        Range: 20-2000
                'agents' : list(str) : a list of agent uuids to use in the scanning. Default should be all agents.
                'default_scan' : str : an enum string of what type of port scan technique to prefer/start with.
                'default_discovery' : str : and enum string of what type of discovery technique to prefer/start with.
                'os_detect' : bool : whether or not to attempt OS detection (Stage 5)
                'banner_grab' : bool : attempt banner grabbing on a port (Stage 4)
                'firewalk' : bool : attempt firewalk if suspected firewall (Stage 3)
                'vuln_scan' : bool : attempt vulnerability scans on fully enumerated services (Stage 6)
                'verify_fw' : bool : requires all scans resulting in RST or dropped packets (suspected FW or filtering) to be completed by a second agent.
        '''
        # TODO do some major checks, throw exceptions within sub functions and add exception handling here
        
        missing_keys = self.check_keys(['ips','ports'],kwargs)
        if len(missing_keys) > 0:
            error_msg = "The following keys are missing: %s" % ','.join(missing_keys)
            return (False, error_msg)
        
        ips = kwargs['ips']
        ports = kwargs['ports']
        
        #TODO do some type checking here to make sure everything is decoded to the type format it should be. Should throw exceptions if not.
        
        #TODO Check for supported ips and ports formats
        
        scans = DB.scans
        scan = { "uuid": str(uuid.uuid4())
                ,"creation_date": datetime.datetime.utcnow()
                ,"ips": ips
                ,"ports" : ports
                ,"agents" : kwargs.get('agents',[])
                ,"default_scan" : kwargs.get('default_scan',DEFAULT_SCAN)
                ,"default_discovery" : kwargs.get('default_discovery',DEFAULT_DISCOVER)
                ,"os_detect" : kwargs.get('os_detect',True)
                ,"banner_grab" : kwargs.get('banner_grab',True)
                ,"firewalk" : kwargs.get('firewalk',True)
                ,"vuln_scan" : kwargs.get('vuln_scan', True)
                ,"verify_fw" : kwargs.get('verify_fw',True)
                ,"complete" : False
                }
        
        scan_id = scans.insert_one(scan).inserted_id
        
        return (True,{"scan_id":scan['uuid']})
    
    def list_agents(self, kwargs):
        '''
        Command returns a two-dimensional list of agents by their UUID and their IPs. [(id,ip),(id,ip),etc...]
        '''
        agents = []
        for agent_id,agent in agent_map.iteritems():
            agents.append(( agent_id
                          , agent.client_address[0]
                          ))
            
        return (True, agents)
    
    def disconnect_agent(self, kwargs):
        '''
        Command will disconnect an individual agent by its UUID. Will return a true/false success flag as well as the agents ID:
            Arguments:
                'id' : str : The UUID of the agent; enumerated via list_agents if UUID is not previously known.
        '''
        agent_id = kwargs['id']
        agent = agent_map[agent_id]
        result = agent.disconnect()
        return (result, [agent_id])
        
    def disconnect_all_agents(self, kwargs):
        '''
        Command will disconnect all of the connected agents. Does not prevent them from calling back again. 
        Returns True if completely successful. Partial successes return false. Both instances return a map indicating agents that were disconnected and those that are still connected.
        '''
        orig_size = len(agent_map)
        successful_dc = []
        failed_dc = []
        
        for agent_id,agent in  agent_map.iteritems():
            result = agent.disconnect()
            if result:
                successful_dc.append(agent_id)
            else:
                failed_dc.append(agent_id)
        
        overall_result = True
        if len(successful_dc) < orig_size:
            overall_result = False
            
        response = {}
        response['disconnected'] = successful_dc
        response['still_connected'] = failed_dc
        return (overall_result,response)
    
    def process_command(self, data):
        '''
        This is the application controller handler.
        '''
        #Get the command and kwargs passed from the listening loop
        command = data['cmd']
        args = data['args']
        self.logger.debug("Command: %s" % command)
        
        #Abstractly retrieve the appropriate method based on the 'cmd' parameter.
        cmd_method = self.command_map[command]
        #Call the method and retrieve its (Bool,list) results.
        results_tuple = cmd_method(args)
        
        #Place those results into a dictionary for encoding and sending
        results_dic = {}
        results_dic['success'] = results_tuple[0]
        results_dic['results'] = results_tuple[1]
        
        return results_dic
    
    def setup(self):
        '''
        This method implements the StreamRequestHandler interface.
        This is called whenever a client issues a request. It therefore sets the up application controller.
        '''
        # Setup the application controller.
        self.command_map['echo'] = self.echo_command
        
        ## Scan related commands
        self.command_map['create_scan'] = self.create_scan
        self.command_map['start_scan'] = self.start_scan
        #TODO self.command_map['stop_scan'] = self.stop_scan
        self.command_map['delete_scan'] = self.delete_scan
        #TODO self.command_map['resume_scan'] = self.resume_scan
        #TODO self.command_map['edit_scan'] = self.edit_scan
        self.command_map['rerun_scan'] = self.rerun_scan
        self.command_map['get_scan_results'] = self.get_scan_results
        # Note: the resume and edit scan should allow for users to decide on a more aggressive scan (i.e add banner grabbing) and pick up where it left off; meaning, dont require it to rerun the initial scans.
        
        ## API Related commands
        #TODO self.command_map['get_api'] = self.get_api
        #TODO self.command_map['import_database'] = self.import_database
        
        ## Listener related commands
        self.command_map['start_listener'] = self.start_agent_listener
        self.command_map['stop_listener'] = self.stop_agent_listener
        
        ## agent related commands
        #TODO self.command_map['add_agent'] = self.add_agent
        #TODO self.command_map['delete_agent'] = self.delete_agent
        #TODO self.command_map['connect_agent'] = self.connect_agent
        #TODO self.command_map['connect_agent_list'] = self.connect_agent_list
        #TODO self.command_map['connect_all_agents'] = self.connect_all_agents
        self.command_map['list_agents'] = self.list_agents
        self.command_map['disconnect_agent'] = self.disconnect_agent
        #TODO self.command_map['disconnect_agent_list'] = self.disconnect_agent_list
        self.command_map['disconnect_all_agents'] = self.disconnect_all_agents
        
        return StreamRequestHandler.setup(self)
    
    def handle(self):
        '''
        This method is called (again, implements the StreamRequestHandler interface) once the connected client issues its request.
        Here we handle the reading of the data->decoding it->dispatching to the application controller->getting the results->encoding->sending back.
        '''
        self.logger.debug('Handling request')
        #Read from socket using newline delimeter as the flag
        self.raw = self.rfile.readline().strip()
        #Decode JSON into Python object
        self.data = json.loads(self.raw)
        #Dispatch to application controller handler
        self.results = self.process_command(self.data)
        #Encode results into JSON
        self.response = json.dumps(self.results)
        #Send response back to the client.
        self.wfile.write(self.response + "\n")
        
    def finish(self):
        self.logger.debug('Request Complete')
        return StreamRequestHandler.finish(self)
        
class APIListener(ThreadingMixIn, TCPServer):
    
    '''
    This class is started at startup. Permits the client to submit commands to the server.
    '''
    def __init__( self
                , server_address
                , RequestHandlerClass
                , certfile
                , keyfile
                , ssl_version=ssl.PROTOCOL_TLSv1
                , bind_and_activate=True):
        TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        self.certfile = certfile
        self.keyfile = keyfile
        self.ssl_version = ssl_version
        
    def get_request(self):
        '''
        This makes our connection an ssl connection.
        '''
        newsocket, fromaddr = self.socket.accept()
        connstream = ssl.wrap_socket( newsocket
                                    , server_side = True
                                    , certfile = self.certfile
                                    , keyfile = self.keyfile
                                    , ssl_version = self.ssl_version)
        return connstream, fromaddr

class AgentHandler(StreamRequestHandler):
    
    '''
    Threaded class representing each persistent connection from an Agent.
    '''
    
    def __init__(self, request, client_address, server):
        self.ip = client_address[0]
        self.logger = logging.getLogger('AgentHandler (%s)' % client_address[0])
        self.keep_alive = True
        self.sendq = Queue()#OrderedDict()
        self.agent_id = None
        StreamRequestHandler.__init__(self, request, client_address, server)
        return
    
    def send(self, data):
        '''
        Helper method to handle the encoding and sending of data to the specific agent.
        '''
        content = json.dumps(data)
        #self.logger.debug('Sending data: %s' % content)
        self.wfile.write(content + "\n")
        
    def queue_task(self,task_id,session_id,cmd,args):
        '''
        This method adds tasks to the sending queue for this specific agent.
        '''
        #TODO This will require a thread lock
        task = {}
        task['task_id'] = task_id
        task['session'] = session_id
        task['cmd'] = cmd
        task['args'] = args
        #self.logger.debug('Queuing task %s' % str(task_id))
        #append this task to an OrderedDict so we can identify it by its task UUID but still operate as a FIFO.
        #self.sendq[task_id] = task
        self.sendq.put(task)
        
    def check_sendq(self):
        '''
        Checks the send queue for tasks, pops it off and sends it.
        '''
        #if len(self.sendq) > 0:
        if not self.sendq.empty():
            #task = self.sendq.popitem(last=False)
            #task = task[1]
            task = self.sendq.get()
            
            #Update the task document with the send time
            DB.tasks.update_one({'uuid':task['task_id']},{'$set':{'tasked_date':datetime.datetime.utcnow()}},upsert=False)
            
            #popitem returns (key, item). We just want the item.
            #TODO if there is an issue when tasking, detect it so that you can add the task back into a queue or kick it back to the scanhandler's tasker to send to a different guy
            self.send(task)
            self.sendq.task_done()
    
    def process_data(self,data):
        '''
        This method will handle the results sent back from the agent. This will be the application controller handler.
         'data' will contain:
            session : str : scan handler's id
            response : bool : true or false based on success on the other end
            task_id : str : task uuid
            results : dict : dictionary of the results
        '''
        if 'error' in data:
            self.logger.debug('Error response received from agent: %s' % data["error_msg"])
        else:
            #self.logger.debug('Got response for task %s' % data['task_id'])
            scan_h = active_scans[data['session']]
            # I dont like passing the agent_id here has a parameter, but it will provide some speed enhancement so the ScanHandler doesn't have to query the database for it.
            task_id = data['task_id']
            #Update the task document with the response time
            DB.tasks.update_one({'uuid':task_id},{'$set':{'response_date':datetime.datetime.utcnow(),'complete':True}},upsert=False)
            scan_h.queue_response(data['response'], task_id, data['results'], self.agent_id)
        
    def disconnect(self):
        '''
        Gracefully clean up the agents connection; communicate with agent to cleanly disconnect on the agent side.
        '''
        # TODO do other things like check or clear up its current tasks
        self.keep_alive = False
        
        # remove the agent so it doesnt receive more tasking.
        if self.agent_id:
            del agent_map[self.agent_id]
            
            for scan_id, scan_h in scan_handlers.iteritems():
                scan_h.unregister_agent(self.agent_id)
        
        return True
    
    def register_agent(self, agent_info):
        
        self.agent_id = self.agent_info['id']
        agent_map[self.agent_id] = self
        
        #Add agent to database if not existant
        DB.agents.update({'uuid':self.agent_id},{'$set':{'uuid':self.agent_id,'last_connect':datetime.datetime.utcnow(),'ip':self.ip}},upsert=True)
        
        # Loop through active sessions. If the agent should be used by one of those, register it with the scan handler.
        for sess_id, sess_h in active_scans.iteritems():
            agents = sess_h.scan['agents']
            if self.agent_id in agents or len(agents) == 0:
                #self.logger.debug("Registering %s with %s" % (self.agent_id, sess_id))
                sess_h.register_agent(self)
                
        return True
        
    
    def handle(self):
        '''
        StreamRequestHandler interface called upon successful connection from agent.
        '''
        
        self.logger.debug('Tasking...')
        
        #Register Agent; agent should send basic info upon every connection to identify itself uniquely with the server for tasking.
        self.raw = self.rfile.readline().strip()
        self.agent_info = json.loads(self.raw)

        #'id' is a required KVP in the agent's registration info.
        if 'id' in self.agent_info:
            success = self.register_agent(self.agent_info)
            
            response = {}
            response['success'] = success
            
            #TODO Send back success or failure based on if the agent has tasking. So a good id still can return false if no scans requiring the agent is active.
            self.send(response)
            self.logger.debug('Agent %s registered' % self.agent_id)
        else:
            self.logger.debug('Agent failed to register')
            self.finish()

        sock = self.request
        
        #Communicate with Agent
        
        #TODO Fix this. If bad JSON came back from client it would DC them. This should detect closed sockets somehow...
        try: 
            while self.keep_alive:
                # check if the socket is readable, writeable or in error. 1 second timeout.
                r,w,e = select.select([sock],[sock],[sock], 1.0)
                #TODO consider reordering or more intelligently determining if read or write takes priority based upon the size of the buffer or queues.
                if e:
                    # if in error end the loop. Disconnected already essentially.
                    self.logger.debug("Error with socket")
                    self.keep_alive = False
                elif r:
                    # The agent is trying to send us something. Grab it, decode it, and dispatch it to the application controller. Responses dont occur here to allow async comms.
                    self.raw = self.rfile.readline().strip()
                    self.data = json.loads(self.raw)
                    self.process_data(self.data)
                elif w:
                    # If the socket can be written to (which is always True unless the buffer is full) then ask the queue to send the next command.
                    
                    ### TEST MECHANISM - DELETE ME###
                    #sleep(2)
                    #self.queue_task('1',None,'pong',{})
                    #################################
                    
                    self.check_sendq()
        except Exception as e:
            self.logger.debug("An error occured: %s " % e)
            #raise
        
    def finish(self):
        self.logger.debug('Agent disconnected')
        self.disconnect()
        return StreamRequestHandler.finish(self)
    
    def setup(self):
        '''
        This implements the StreamRequestHandler interface. Setup the application controller here.
        '''
        self.logger.debug('Agent connected')
        return StreamRequestHandler.setup(self)

class AgentListener(ThreadingMixIn, TCPServer):
    
    '''
    This class handles agents that must call back (i.e NAT'd or non-public IP hosts)
    '''
    def __init__( self
                , server_address
                , RequestHandlerClass
                , certfile
                , keyfile
                , ssl_version=ssl.PROTOCOL_TLSv1
                , bind_and_activate=True):
        TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        self.certfile = certfile
        self.keyfile = keyfile
        self.ssl_version = ssl_version
        
    def get_request(self):
        '''
        Wraps our socket in SSL/TLS
        '''
        newsocket, fromaddr = self.socket.accept()
        connstream = ssl.wrap_socket( newsocket
                                    , server_side = True
                                    , certfile = self.certfile
                                    , keyfile = self.keyfile
                                    , ssl_version = self.ssl_version)
        return connstream, fromaddr

class ScanHandler(threading.Thread):
    '''
     Scanning methodology:
        - Stage 1 = Host Discovery; fast and simple
        - Stage 2 = Port scanning
        - Stage 3 = Firewalking?
        - Stage 4 = Banner grabbing?
        - Stage 5 = Extra OS discovery scans?
        - Stage 6 = Vulnerability scans?
        
     It should remember state of a scan, so you can later go and run the next stage of a scan if you decide to do so.
    
    '''
    
    def __init__(self, group=None, target=None, name=None,
                 args=(), kwargs=None, verbose=None):
        threading.Thread.__init__(self, group=group, target=target, name=name,
                                  verbose=verbose)
        self.scan_id = kwargs['uuid']
        self.uuid = str(uuid.uuid4())
        self.logger = logging.getLogger('ScanHandler-%s' % self.uuid.split('-')[4])
        self.scan = kwargs
        self.keep_alive = True
        self.results_queue = Queue()
        self.tasking_queue = OrderedDict()
        self.current_stage = 1
        self.active_agents = {}

        # Setup the stages flags. 
        self.stage_statuses = { 1:False
                              , 2:False
                              , 3:False
                              , 4:False
                              , 5:False
                              , 6:False}
                              
        if not self.scan['os_detect']: self.stage_statuses[OS_DETECT_STAGE] = None
        if not self.scan['firewalk']: self.stage_statuses[FIREWALK_STAGE] = None
        if not self.scan['banner_grab']: self.stage_statuses[BANNER_GRAB_STAGE] = None
        if not self.scan['vuln_scan']: self.stage_statuses[VULN_SCAN_STAGE] = None
        if self.scan['default_discovery'] is None: self.stage_statuses[HOST_DISCOVER_STAGE] = None
        if self.scan['default_scan'] is None: self.stage_statuses[SCAN_STAGE] = None
        
        self.stage_task_creators = { HOST_DISCOVER_STAGE: self.generate_hostdiscovery_tasks
                                    ,SCAN_STAGE: self.generate_scan_tasks
                                    ,FIREWALK_STAGE: self.generate_firewalk_tasks
                                    ,BANNER_GRAB_STAGE: self.generate_bannergrab_tasks
                                    ,OS_DETECT_STAGE: self.generate_osdetect_tasks
                                    ,VULN_SCAN_STAGE: self.generate_vulnscan_tasks}
                                    
        self.stage_results_handlers = { HOST_DISCOVER_STAGE: self.handle_hostdiscovery_results
                                        ,SCAN_STAGE: self.handle_scan_results
                                        ,FIREWALK_STAGE: self.handle_firewalk_results
                                        ,BANNER_GRAB_STAGE: self.handle_bannergrab_results
                                        ,OS_DETECT_STAGE: self.handle_osdetect_results
                                        ,VULN_SCAN_STAGE: self.handle_vulnscan_results
                                        }
    
    def register_agent(self, agent_handler):
        agent_id = agent_handler.agent_id
        
        self.active_agents[agent_id] = { "useable":True #This will go false if we think the agent is being blocked, or is to be reserved by something else.
                                        ,"task_count":0
                                        ,"handler":agent_handler
                                        } #How many tasks this agent is currently processing
        self.logger.debug("Agent %s added to scan session" % agent_id)
        
    def unregister_agent(self, agent_id):
        if agent_id in self.active_agents.keys():
            del self.active_agents[agent_id]
            self.logger.debug("Unregistering Agent %s" % agent_id )
        
    def load_previous_session(self,session):
        '''
        This is used when resuming a scan to load the previous sessions local variables so run() can pick up where it left off.
        '''
        pass
    
    def get_target_by_ip(self,ip):
        
        targets = DB.targets
        
        target = targets.find_one({"ip":ip})
        
        if target is None:
            new_uuid = str(uuid.uuid4())
            new_target = {"uuid": new_uuid
                         ,"creation_date" : datetime.datetime.utcnow()
                         ,"ip" : ip
                         ,"status" : None
                         ,"last_status_check" : None
                         ,"ports":{}
                         ,"os" : None
                         }
            
            target_id = targets.insert_one(new_target).inserted_id
            target = targets.find_one({"uuid":new_uuid})
            self.logger.debug("Created Target - %s" % ip)
        
        return target
    
    def close_down_scan(self):
        self.keep_alive = False
    
    def complete_scan(self):
        scan = DB.scans.find_one({'uuid':self.scan_id})
        scan['complete'] = True
        scan['completed_time'] = datetime.datetime.utcnow()
        del scan['_id'] # cant attempt ot update the id field
        DB.scans.update_one({'uuid':self.scan_id},{'$set':scan})
        
        return
    
    def check_ip_format(self,ip):
        
        try:
            #netaddr's IPAddress object will fill in unprovided octets. Therefore, we want to throw an error here.
            if ip.count('.') < 3:
                raise Exception
            
            ip_obj = netaddr.IPAddress(ip)
            return True
        except:
            return False
            
        pass
        
    def parse_cidr_ips(self,cidr):
        
        try:
            ips = netaddr.IPNetwork(cidr)
            ip_obj_list = list(ips)
            ip_list = [ str(ip) for ip in ip_obj_list]
            return ip_list
        except:
            return []
    
    def parse_ip_range(self,ipr):
        self.logger.debug("Parsing %s as range" % ipr)
        try:
            split_octets = ipr.split('.')
    
            low_ip = ''
            high_ip = ''
            for octet in split_octets:

                if '-' in octet:
                    split_octet = octet.split('-')
                    l_octet = split_octet[0]
                    h_octet = split_octet[1]
                else:
                    l_octet = octet
                    h_octet = octet
                low_ip = low_ip + l_octet + '.'
                high_ip = high_ip + h_octet + '.'

            #make a list based upon our built ips (remove the trailing .)
            ip_obj_list = list(netaddr.iter_iprange(low_ip[:-1], high_ip[:-1]))
            ip_list = [ str(ip) for ip in ip_obj_list]
            return ip_list
        except:
            return []
            
    def translate_ip_notation(self,ip_input):
        #turn ips into a list (will return a single element list if no commas)
        ips_list = ip_input.split(',')
        parsed_ip_list = []
        for ip in ips_list:
            self.logger.debug("Parsing %s" % ip)
            if '/' in ip:
                parsed_ip_list = parsed_ip_list + self.parse_cidr_ips(ip)
            elif '-' in ip:
                parsed_ip_list = parsed_ip_list + self.parse_ip_range(ip)
            else:
                res = self.check_ip_format(ip)
                if res : parsed_ip_list.append(ip)
        
        return parsed_ip_list
    
    def translate_port_notation(self,port_input):
        
        ports_list = port_input.split(',')
        parsed_port_list = []
        for port in ports_list:
            if '-' in port:
                parsed_port_list = parsed_port_list + self.parse_port_range(port)
            else:
                res = self.check_port_format(port)
                if res : parsed_port_list.append(port)
                
        return parsed_port_list
    
    def check_port_format(self,port):
        '''
        Simply check that the port number is in the actual port range
        Alternatively we could return 1 if the number was less than 1 and return 65535 if the number was greater than that
        '''
        
        port = int(port)
        if port >= 1 and port <= 65535:
            return True
        else:
            return False
        
    def parse_port_range(self,port):
        '''
        This method will make a port range (1-1026) into a list of ports [1,2,3,4,etc].
        We assume a lot of things here that should probably be checked:
            - only a single '-' is provided. If not, only the first two numbers will be used.
            - Use of more than one range per CSV would be imporperly formatted and should return an error previous to this method being called (i.e during type checks?)
            - The first element in the split ports list is actually lower than the high number.
        '''
        ports = port.split('-')
        low_port = int(ports[0])
        high_port = int(ports[1])
        
        # check that the ports are in the appropriate range
        if self.check_port_format(low_port) and self.check_port_format(high_port):
            return range(low_port,high_port+1)
        else:
            # if ports are out of range, fails silently and returns an empty list
            return []
            
    def abstract_task_generator(self, stage, technique, target_id, port = None):
        
        tasks = DB.tasks
        new_uuid = str(uuid.uuid4())
        task = task = { "uuid": new_uuid
                    ,"creation_date" : datetime.datetime.utcnow()
                    ,"associated_scan" : self.scan_id
                    ,"stage" : stage
                    ,"technique" : technique
                    ,"target" : target_id
                    ,"port" : port
                    ,"complete" : False
                    ,"tasked_agent" : None
                    ,"tasked_date" : None
                    ,"response_date" : None
                    ,"response" : None
                    }
        tasks.insert_one(task).inserted_id
        return new_uuid
    
    def generate_abstract_result(self, task, results_body):
        
        new_uuid = str(uuid.uuid4())
        target_id = task['target']
        task_id = task['uuid']

        newresult = { "uuid": new_uuid
                  ,"creation_date" : datetime.datetime.utcnow()
                  ,"associated_scan" : self.scan_id
                  ,"target" : target_id
                  ,"task" : task_id
                  ,"raw" : results_body
                 }
                 
        new_id = DB.taskresults.insert_one(newresult).inserted_id
        DB.tasks.update_one({'uuid':task_id},{'$set':{'response':new_uuid}})
        
        return new_uuid
        
    def generate_confirmation_task(self, task):
        self.logger.debug("Generating confirmation task")
        new_task_id = self.abstract_task_generator(task['stage'], task['technique'], task['target'], task['port'])
        previous_agent = task['tasked_agent']
        task = DB.tasks.update_one({'uuid':new_task_id},{'$set':{'previous_agent':previous_agent}})
        return new_task_id
            
    def generate_hostdiscovery_tasks(self):
        
        parsed_ip_list = self.translate_ip_notation(self.scan['ips'])

        tasks = DB.tasks
        
        default_discovery_tech = self.scan['default_discovery']
        for ip in parsed_ip_list:
            target_id = self.get_target_by_ip(ip)['uuid']
            self.abstract_task_generator(HOST_DISCOVER_STAGE, default_discovery_tech, target_id)

        hd_task_count = tasks.find({"associated_scan":self.scan_id,"stage":HOST_DISCOVER_STAGE}).count()

        return hd_task_count
        
    def handle_hostdiscovery_results(self, task, results):
        
        result_id = self.generate_abstract_result(task, results)
        
        host_state = results['host_state']
        host_reason = results['host_reason']

        target_id = task['target']
        #If host status is up, update the target accordingly
        if 'up' in host_state:
            #self.logger.debug('Host is up!')
            DB.targets.update_one({'uuid':task['target']},{'$set':{'status':True,'last_status_check':datetime.datetime.utcnow()}})
        
        else:
            # If this is the second host discovery task for this target from this scan_id then mark the target as down
            hostdiscover_attempt_count = DB.tasks.find({'target':target_id,'associated_scan':self.scan_id,'stage':HOST_DISCOVER_STAGE}).count()
            if hostdiscover_attempt_count > 1:
                #self.logger.debug('Host confirmed down')
                DB.targets.update_one({'uuid':task['target']},{'$set':{'status':False,'last_status_check':datetime.datetime.utcnow()}})
            else:
                #self.logger.debug('Lets try again to see if they may be up...')
                task_id = self.generate_confirmation_task(task)
                task = DB.tasks.find_one({"uuid":task_id})
                self.tasking_queue[task_id] = task
            
        return
        
    def generate_scan_tasks(self):

        parsed_port_list = self.translate_port_notation(self.scan['ports'])
        
        #Check if stage 1 tasks exist.
        stage1_count = DB.tasks.find({'associated_scan':self.scan_id,'stage':SCAN_STAGE-1}).count()
        
        parsed_ip_list = self.translate_ip_notation(self.scan['ips'])

        if stage1_count > 0:
            # If stage 1 tasks, filter to hosts that are up.
            target_list = DB.targets.find({'status':True, 'ip' : { '$in' : parsed_ip_list}})
            if target_list.count() > 0:
                self.logger.debug("Found %d Live Hosts from Host Discovery" % target_list.count())
                ip_list = [target['ip'] for target in target_list]
            else:
                # If the query returned no results, assume all targets are down/filtered and force scan anyway.
                self.logger.debug("Host Discovery reported all down. Assuming filtered")
                ip_list = parsed_ip_list
        else:
            self.logger.debug("No host discovery conducted. Assuming all up")
            ip_list = parsed_ip_list
        
        # Return the cartesian product of ips and ports: [('192.168.1.1',22),('192.168.1.1',25)...,('192.168.1.50',22),('192.168.1.50',25)]
        ip_port_list = [(ip, port) for ip in ip_list for port in parsed_port_list]
        
        # Generate Stage 2 tasks
        default_scan_tech = self.scan.get('default_scan')
        for ip_port in ip_port_list:
            ip, port = ip_port
            target_id = self.get_target_by_ip(ip)['uuid']
            self.abstract_task_generator(SCAN_STAGE, default_scan_tech, target_id, port)

        scan_task_count = DB.tasks.find({"associated_scan":self.scan_id,"stage":SCAN_STAGE}).count()

        return scan_task_count
    
    def handle_scan_results(self, task, results):
        
        result_id = self.generate_abstract_result(task, results)
        
        # Check port status. open, closed, filtered, etc.
        port_state = results['port_state']
        port_reason = results['port_reason']
        target_id = task['target']
        target_ip = results['ip']
        target_port = task['port']
        port_key = 'ports.' + str(target_port)
        
        # if filtered, try again
        if 'filtered' in port_state:
            self.logger.debug("%s:%s Filtered" % (target_ip,target_port))
            scan_attempts = DB.tasks.find({'target':target_id,'associated_scan':self.scan_id,'stage':SCAN_STAGE,'port':target_port}).count()
            # if second try and filtered, add to filtered list
            if scan_attempts > 1:
                self.logger.debug("%s:%s Really is filtered" % (target_ip,target_port))
                DB.targets.update_one({'uuid':target_id},{'$set':{port_key:{'state':'filtered'},'last_status_check':datetime.datetime.utcnow()}})
            else:
                self.logger.debug("Retasking for %s:%s" % (target_ip,target_port))
                task_id = self.generate_confirmation_task(task)
                task = DB.tasks.find_one({"uuid":task_id})
                self.tasking_queue[task_id] = task
        
        # if open, add to open
        if 'open' in port_state:
            self.logger.debug("%s:%s Open" % (target_ip,target_port))
            DB.targets.update_one({'uuid':target_id},{'$set':{port_key:{'state':'open'},'last_status_check':datetime.datetime.utcnow(),'status':True}})
            
        # if closed, add to closed
        if 'closed' in port_state:
            self.logger.debug("%s:%s Closed" % (target_ip,target_port))
            DB.targets.update_one({'uuid':target_id},{'$set':{port_key:{'state':'closed'},'last_status_check':datetime.datetime.utcnow()}})
        
        return

    def generate_firewalk_tasks(self):
        
        firewalled_targets = DB.taskresults.find({'associated_scan':self.scan_id,'raw.port_state':'filtered'},{'target':1,'_id':0}).distinct('target')
        
        for target_id in firewalled_targets:
            self.abstract_task_generator(FIREWALK_STAGE, 'firewalk', target_id, self.scan['ports'])
        
        firewalk_task_count = DB.tasks.find({"associated_scan":self.scan_id,"stage":FIREWALK_STAGE}).count()
        
        return firewalk_task_count
        
    def handle_firewalk_results(self, task, results):
        
        result_id = self.generate_abstract_result(task, results)
        
        # TODO Nothign really to flag in the target about... I guess potentially could give better explanation for previosuly 'filtered' ports?...
        
        return
    
    def generate_bannergrab_tasks(self):
        
        open_targets = DB.taskresults.find({'associated_scan':self.scan_id,'raw.port_state':'open'},{'target':1,'_id':0}).distinct('target')
        
        for target in DB.targets.find({'uuid': {'$in':open_targets}}):
            for port, port_info in target['ports'].iteritems():
                port_state = port_info['state']
                #self.logger.debug("%s:%s = %s" % (target['ip'],port,port_state))
                if 'open' in port_state:
                    self.logger.debug("Generating banner grab: %s:%s" % (target['ip'],port))
                    self.abstract_task_generator(BANNER_GRAB_STAGE, 'banner_grab', target['uuid'], port)
            
        bannergrab_task_count = DB.tasks.find({"associated_scan":self.scan_id,"stage":BANNER_GRAB_STAGE}).count()
        
        return bannergrab_task_count
    
    def handle_bannergrab_results(self, task, results):
        
        result_id = self.generate_abstract_result(task, results)
        
        target_id = task['target']
        target_ip = results['ip']
        target_port = str(task['port'])
        port_key = 'ports.' + target_port
        banner = results['banner']
        servicefp = results['service']
        
        # TODO do some string comparison here to look for OS fingerprints within the service fingerprint. 
        self.logger.debug("%s:%s = %s (%s)" % (target_ip,str(target_port),banner,servicefp))
        
        target = DB.targets.find_one({'uuid':target_id})
        
        target['ports'][target_port] = {'fingerprint':servicefp,'banner':banner,'state':'open'}
        target['last_status_check'] = datetime.datetime.utcnow()
        del target['_id']
        
        DB.targets.update_one({'uuid':target_id},{'$set':target})
        
        return
    
    def generate_osdetect_tasks(self):

        blank_os_targets = DB.taskresults.find({'associated_scan':self.scan_id},{'target':1,'_id':0}).distinct('target')
        
        for target in DB.targets.find({'uuid': {'$in':blank_os_targets},'os':None,'status':True}):
            ip = target['ip']
            self.logger.debug("%s needs OS Detection" % (ip))
            self.abstract_task_generator(OS_DETECT_STAGE, 'os_detect', target['uuid'])
        
        osdetect_task_count = DB.tasks.find({"associated_scan":self.scan_id,"stage":OS_DETECT_STAGE}).count()
        
        return osdetect_task_count
    
    def handle_osdetect_results(self, task, results):

        target_id = task['target']
        target_ip = results['ip']
        os = results['os']
        
        self.logger.debug("%s is %s" % (target_ip,os))
        DB.targets.update_one({'uuid':target_id},{'$set':{'os':os,'last_status_check':datetime.datetime.utcnow()}})

        result_id = self.generate_abstract_result(task, results)
        
        return
    
    def generate_vulnscan_tasks(self):
        #TODO change this to query off of the 'target'
        open_targets = DB.taskresults.find({'associated_scan':self.scan_id,'raw.port_state':'open'},{'target':1,'_id':0}).distinct('target')
        
        for target in DB.targets.find({'uuid': {'$in':open_targets}}):
            for port, port_info in target['ports'].iteritems():
                port_state = port_info['state']
                #self.logger.debug("%s:%s = %s" % (target['ip'],port,port_state))
                if 'open' in port_state:
                    self.logger.debug("Generating vuln scan: %s:%s" % (target['ip'],port))
                    self.abstract_task_generator(VULN_SCAN_STAGE, 'vuln_scan', target['uuid'], port)
        
        vulnscan_task_count = DB.tasks.find({"associated_scan":self.scan_id,"stage":VULN_SCAN_STAGE}).count()
        
        return vulnscan_task_count
    
    def handle_vulnscan_results(self, task, results):
        
        #TODO Didnt have any good test cases to look at XML for parsing.... 
        
        result_id = self.generate_abstract_result(task, results)
        
        return
    
    def queue_response(self,response, task_id, results_body, agent_id):
        results = {}
        results['response'] = response
        results['task_id'] = task_id
        results['results'] = results_body
        self.results_queue.put(results)
        # Ugggggglllyyyyy. Reduce the calling agents task count.
        self.active_agents[agent_id]['task_count'] -= 1
    
    def process_results(self):
        
        try:
            cur_result = self.results_queue.get_nowait()
            
            success = cur_result['response']
            task_id = cur_result['task_id']
            results = cur_result['results']
            
            #self.logger.debug('Processing results for %s' % task_id)
            
            task = DB.tasks.find_one({'uuid':task_id})

            # get the appropriate handler for the task
            result_handler = self.stage_results_handlers[task['stage']]
            result_handler(task,results)
            
            return
        
        except Empty:
            #If the queue is blocking still, then just return without having done anything.
            self.logger.debug('Attempted to process a result, but the queue is still blocking')
            return
        
    def check_if_stage_complete(self, stage_num):
        
        status = self.stage_statuses[stage_num]
        
        #Check if flag is set to even run this stage
        if status is None:
            return None
        
        #Check if this stage was previously marked complete (previous session)
        if status is True:
            return True
        
        if status is False:
            
            #check if any tasks exists
            tasks = DB.tasks
            task_count = tasks.find({"associated_scan":self.scan_id,"stage":stage_num}).count()
        
            #If not, then this stage needs to be ran (return False)
            if task_count == 0:
                return False
            
            else:
            #if so, check to see if they have been completed
                incomplete_task_count = tasks.find({"associated_scan":self.scan_id,"stage":stage_num,"complete":False}).count()
            
                if incomplete_task_count == 0 and self.results_queue.empty():
                    # if they have been completed, this stage is done (return True)
                    return True
                else:
                    #if not, this stage needs to be ran still (return False)
                    return False
    
    def set_stage_complete(self, stage_num):
        # The provided stage is now complete
        self.stage_statuses[stage_num] = True
    
    def start_next_stage(self, stage_num):
        self.current_stage = stage_num
        
        tasks = DB.tasks
        #Are there any tasks generated for this stage?
        task_count = tasks.find({"associated_scan":self.scan_id,"stage":self.current_stage}).count()
        
        if task_count == 0:
            # Create tasks
            generator = self.stage_task_creators[self.current_stage]
            created_tasks_count = generator()
            self.logger.debug("Generated %d tasks for Stage %d" % (created_tasks_count, self.current_stage))
        
        # Once generated, or already existing, queue them to the tasks queue so the tasker can do stuff with them. Sort by uuid to randomize.    
        tasks = tasks.find({"associated_scan":self.scan_id,"stage":self.current_stage,"complete":False}).sort('uuid',ASCENDING)
        self.logger.debug("%d Tasks to be queued" % tasks.count())
        for t in tasks:
            t_uuid = t['uuid']
            self.logger.debug("Queueing Task %s" % t_uuid)
            self.tasking_queue[t_uuid] = t
    
    def tasker(self):
        
        # Check if tasks to distribute
        if len(self.tasking_queue) > 0:
            
            if len(self.active_agents) == 0:
                #self.logger.debug("No active agents availble")
                return
            
            #TODO consider changing this to do batches (task 5 at a time) or one task per call or fill agents to threshold every time tasker is called.
            
            # If so, check if local agent queue tracker isnt too full
            randomized_agents = self.active_agents.items()
            random.shuffle(randomized_agents)
            for agent_id, agent_info in randomized_agents:
                if (agent_info['useable'] is True) and (agent_info['task_count'] < AGENT_TASK_THRESHOLD):
                    # If there is space, add tasks to the agents queue
                    try:
                        task = self.tasking_queue.popitem(last=False)[1]
                    except KeyError:
                        return
                    
                    task_id = task['uuid']
                    
                    #Check if this task has a 'previous_agent' flag so as not to resue it. Even if it is, if we only have a single active_agent, we have no other option.
                    if 'previous_agent' in task and len(self.active_agents) > 1:
                        if task['previous_agent'] in agent_id:
                            self.tasking_queue[task_id] = task
                    
                    task_cmd = task['technique']
                    target_id = task['target']
                    target = DB.targets.find_one({'uuid':target_id})
 
                    task_args = { 'ip'   : target.get('ip')
                                , 'port' : task.get('port','')
                                }
                    a_handler = agent_info['handler']
                    
                    #self.logger.debug("Tasking %s" % (task_id))
                    a_handler.queue_task(task_id, self.uuid, task_cmd, task_args)
                    # Update task so we know whe it was tasked too.
                    DB.tasks.update_one({'uuid':task_id},{'$set':{'tasked_agent':agent_id}},upsert=False)
                    
                    # See above TODO, could return here so only a single task is queued per call of tasker.... not sure if I like this, but it prevents holding up the processing of results...
                    agent_info['task_count'] += 1
                    
                    if len(self.tasking_queue) % 25 == 0:
                        self.logger.debug("[Stage %d] %d more tasks to assign" % (self.current_stage, len(self.tasking_queue)))
            return
            
        else:
            
            #TODO Check for tasks that have been sent to agents but have taken a really long time, or that agent is no longer active. Reassign that task appropriately. 
            
            #self.logger.debug('No tasks in queue')
            return
        
    def find_next_stage(self):
        c = self.current_stage
        for i in range(c,len(self.stage_statuses)+1):
            status = self.check_if_stage_complete(i)
            if not status and status is not None:
                return i
        # If all stages are done
        return 0
    
    def run(self):
        self.logger.debug('Starting scan handler')
        
        #check agent_map for agents that we use
        for agent_id, agent_h in agent_map.iteritems():
            if agent_id in self.scan['agents'] or len(self.scan['agents']) == 0:
                self.register_agent(agent_h)
        
        #Find the earliest stage needing to be completed. We don't use 0 index in this dict.
        self.current_stage = self.find_next_stage()
        
        #Kick off the first incomplete stage
        self.logger.debug('Starting scan at Stage %d' % self.current_stage)
        self.start_next_stage(self.current_stage)
        
        while self.keep_alive:
            #Check if results need to be processed
            if not self.results_queue.empty():
                #self.logger.debug('Results queue is not empty')
                self.process_results()
    
            #else:
                
            stage_status = self.check_if_stage_complete(self.current_stage)
        
            if stage_status is True:
                # If there are more possible stages to be ran, iterate current_stage and loop.
                self.logger.debug('Setting Stage %d to complete' % self.current_stage)
                self.set_stage_complete(self.current_stage)
                next_stage = self.find_next_stage()
                if next_stage > 0:
                    self.logger.debug('Starting Stage %d' % next_stage)
                    self.start_next_stage(next_stage)
                
                else:
                    self.logger.debug('Scan Completed!')
                    # TODO mark scan as completed within database
                    self.complete_scan()
                    self.close_down_scan()
            elif stage_status is False:
                self.tasker()
            else:
                self.logger.debug('Stage %d is not meant to be ran... Skipping' % self.current_stage)
                #self.current_stage = self.find_next_stage()
        
            sleep(SCAN_HANDLER_SLEEP_INTERVAL)

    def shutdown(self):
        self.keep_alive = False

class ScannerServer:
    
    '''
    This class acts as the main container for all other working threads
    '''
    def __init__(self):
        self.logger = logging.getLogger('ScannerServer')
    
    def start_servers(self,api_port):
        '''
        Used to start up servers at run time. Does a few things:
            1. Attempts to connect to MongoDB to test if its alive.
            2. Starts up the API listener
            3. Starts up the agent server automatically. This can be removed and require the existing API call. Consider a command line switch for runtime config.
        '''
        try:
            mongo_client = MongoClient('localhost', MONGO_PORT, maxPoolSize=MAX_POOL_SIZE)
            global DB
            DB = mongo_client[DB_NAME]
            self.logger.debug("MongoDB Connection is up")
        except Exception as e:
            self.logger.debug("Could not connect to MongoDB")
            self.shutdown(None, None)
        
        try:
            self.api_server = APIListener(('0.0.0.0',api_port), APIHandler,"api_cert.pem","api_key.pem")
            server_thread = threading.Thread(target=self.api_server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            self.logger.debug("API Listener started.")
        except Exception as e:
            self.logger.debug("API Listener failed to start: %s " % e)
            self.shutdown(None, None)
            
        #TODO make this a command line switch to start agent listener on startup.
        self.start_agent_server()
            
    def start_agent_server(self, agent_port=AGENT_LISTENER_DEFAULT_PORT):
        
        '''
        Starts the agent server. Agents will start connecting back once this is open. Can define a port or use the default (see globals).
        '''
        
        try:
            self.agent_server = AgentListener(('0.0.0.0',agent_port), AgentHandler,"agent_cert.pem","agent_key.pem")
            server_thread = threading.Thread(target=self.agent_server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            self.logger.debug("Agent Listener started.")
            return True
        except Exception as e:
            self.logger.debug("Agent Listener failed to start: %s " % e)
            return False
            
    def stop_agent_server(self):
        '''
        Shut down the agent listener. Anything the needs to be gracefully handled on shutdown can be added here: 
        i.e, indexing of uncompleted tasks, diconnecting the agents to allow their own disconnect protocols to complete, etc.
        '''
        try:
            #TODO somehow call disconnect_all_agents on the API Handler to allow graceful disconnects...
            self.agent_server.shutdown()
            self.agent_server.server_close()
            self.logger.debug("Agent Listener stopped.")
            return True
        except Exception as e:
            self.logger.debug("Agent Listener failed to stop: %s " % e)
            return False
            
    def stop_api_server(self):
        '''
        Shut down the API server. This essentially stops the entire server.
        '''
        try:
            self.api_server.shutdown()
            self.api_server.server_close()
            self.logger.debug("API Listener stopped.")
            return True
        except Exception as e:
            self.logger.debug("API Listener failed to stop: %s " % e)
            return False
    
    def stop_active_scans(self):
        self.logger.debug("Stopping Active Scans")
        for scan_id, scan_h in active_scans.iteritems():
            scan_h.shutdown()
    
    def shutdown(self, signal, frame):
        '''
        Method to shutdown the entire server gracefully.
        '''
        self.logger.debug("Shutdown initiated")
        self.stop_active_scans()
        self.stop_agent_server()
        self.stop_api_server()
        sys.exit(0)

if __name__ == "__main__":
    
    logger = logging.getLogger('Main')
    server = ScannerServer()
    
    server.start_servers(9999)
    
    # Maintain main thread until kill signal
    signal.signal(signal.SIGINT, server.shutdown)
    logger.debug('Press Ctrl+C to exit')
    signal.pause()
