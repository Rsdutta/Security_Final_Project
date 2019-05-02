# Security_Final_Project

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
