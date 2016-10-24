#sshvpn

#sshvpn create a vpn using OpenSSH forwards.

sshvpn creates a transparent VPN by setting up ssh forwards on the loopback interface and adding host entries to the hosts file. For every forward there will be an IP-address on the loopback interface with the first octet changed to 127. The last three octets will contain the original IP-address. All forwards in sshvpn are defined in the "${forward}" array. The syntax is very simple and consists of comma separated values. See the next example for more information.

forward array example:

forward[0]='forward_host,forward_port,stepping_stone,ssh_port,username'
forward[1]='smtp.epsilix.nl,25,wormhole.epsilix.nl,22,jelle'
forward[2]='imaps.epsilix.nl,993,wormhole.epsilix.nl,22,jelle'
forward[3]='www.epsilix.nl,80,wormhole.epsilix.nl,22,jelle'
forward[4]='https.epsilix.nl,443,wormhole.epsilix.nl,22,jelle'

forward_host: Host to forward traffic to.
forward_port: Port to forward traffic to on host to forward to.
stepping_stone: The ssh stepping stone server that forwards the traffic.
ssh_port: The OpenSSH port on the ssh stepping stone server.
username: The username used for the ssh forwards on the stepping stone.

Before using sshvpn setup passwordless access to the SSH stepping stone server for the specified username. You can set the ssh_key variable to point to your private key so sshvpn can use it to create the tunnels.

ssh_key='/home/jelle/.ssh/id_rsa'
