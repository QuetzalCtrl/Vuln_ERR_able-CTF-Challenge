# Vuln_ERR_able

Welcome to the Vuln_ERR_able challenge ! 

Vuln_ERR_able is simple CTF challenge where you'll be confronted to common web exploitation, enumeration, and some basic privesc.

This github repo contains everything you need to try this CTF from within your local environment, but you can also find it on TryHackMe (right here: tryhackme.com/jr/vulnerrable). 

## Requirements

- If you want to try this challenge locally, please make sure you have vagrant and VirtualBox installed on your system, as the VM booting and configuration is made using those tools
- If you want to try it on TryHackMe, you'll need an account in order to access the room. You'll also need to connect to TryHackMe's private network using their VPN config file. For the VPN connexion part, everything is explained directly on TryHackMe, under the "Access" window.

## Installation

This part concerns those who want to run the vulnerable VM locally. If you want accessing it via TryHackMe, just ignore this part.

1. Clone this repo to your local machine: 

`git clone https://github.com/QuetzalCtrl/Vuln_ERR_able-CTF-Challenge.git`

2. Navigate to the directory where the repository was cloned, and to `/VulnERRable_App/box`, this is where the vagrant config file is supposed to be:

`cd Vuln_ERR_able-CTF-Challenge/VulnERRable_App/box`

3. Build the VM. This step can take some time.

`vagrant up`

4. Test the connexion:

`ping 192.168.56.80`

That's it, you're ready to start the challenge now ! Vagrant configured a private network you and the VM have in common. By default in this network, you're reffered to `192.168.56.1` and the VM is `192.168.56.80`.

## Goal

This is a CTF-typ challenge, the goal is simple: you'll have to read the content of the "flags" (2 .txt files placed inside the VM), `user.txt` and `root.txt`. The first one is readable by any low-privileged user on the system, but in order to read the second one, you'll need root access.
No initial credentials or ssh connexions are given, so you'll have to scan the activity of the VM, find what services are running and how you can exploit them. 
Have fun, and keep on hacking !

## Write-up 

If you're stuck or you just want to see the solution to this challenge, I wrote a complete detailled write-up (`/WriteUp/WriteUp.md` on this repo), explaining step-by-step how you can exploit this VM's vulnerabilities. 
