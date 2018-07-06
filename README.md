# scanner
A distributed and intelligent scanning/enumeration tool


This project is truly distributed. X number of agents may connect to the server at any given time. 

A simple scanning configuration request is sent to the API listener of the server. 

The server will break the summarized scan targets (CIDR/Net ranges/Net blocks + Port lists/port ranges/etc) into single IP/Port tuples (IP,Port).

The tuples will be queued and tracked by the server. Sent to the agent of actioning. Results will be aggregated.

The scanner will retask a different agent in the event that possible firewalling may occur. If it looks like an agent is blocked (filtered results, yet the next tasked agent was not filtered), the server will stop sending tasks to that agent.

The scanner also implements enumeration in stages: Host discovery, port scanning, firewalking, banner grabing/service enum, vuln scanning, etc. All are optional and feed the subsequent stages.

Currently the agent uses simple nmap scans, but the agent can be entirely adjusted to do the actions however it is desired. 

