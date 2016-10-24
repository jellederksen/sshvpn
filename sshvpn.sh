#!/bin/bash
#
#Copyright (c) 2016 Jelle Derksen jelle@epsilix.nl
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in
#all copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.
#
#sshvpn create a vpn using OpenSSH forwards.

#sshvpn creates a transparent VPN by setting up ssh forwards on the loopback
#interface and adding host entries to the hosts file. For every forward there
#will be an IP-address on the loopback interface with the first octet changed
#to 127. The last three octets will contain the original IP-address. All
#forwards in sshvpn are defined in the "${forward}" array. The syntax is very
#simple and consists of comma separated values. See the next example for more
#information.

#forward array example:

#forward[0]='forward_host,forward_port,stepping_stone,ssh_port,username'
#forward[1]='smtp.epsilix.nl,25,wormhole.epsilix.nl,22,jelle'
#forward[2]='imaps.epsilix.nl,993,wormhole.epsilix.nl,22,jelle'
#forward[3]='www.epsilix.nl,80,wormhole.epsilix.nl,22,jelle'
#forward[4]='https.epsilix.nl,443,wormhole.epsilix.nl,22,jelle'

#forward_host: Host to forward traffic to.
#forward_port: Port to forward traffic to on host to forward to.
#stepping_stone: The ssh stepping stone server that forwards the traffic.
#ssh_port: The OpenSSH port on the ssh stepping stone server.
#username: The username used for the ssh forwards on the stepping stone.

forward[0]='forward_host,forward_port,stepping_stone,ssh_port,username'

#Before using sshvpn setup passwordless access to the SSH stepping stone server
#for the specified username. You can set the $ssh_key variable to point to your
#private key so sshvpn can use it to create the tunnels.

ssh_key='/home/jelle/.ssh/id_rsa'

#Do not edit below this line####################################################
me="${0##*/}"
dn='/dev/null'
fqdn_regex='^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$'
ip_regex='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
user_regex='^[a-z_][a-z0-9_]{0,32}$'
pid_file='/tmp/sshvpn.pid'
hosts_file='/etc/hosts'

usage() {
	echo "usage: ${me} [ -s ] [ -k ] [ -h ]
	-s: start sshvp
	-k: kill sshvp
	-h: show usage" >&2
}

err() {
	echo "${0##*/}: ${1}" >&2
}

mes() {
	echo "${0##*/}: ${1}"
}

#Check if we have root privileges. We need root rights to be able to bind to
#ports below 1023 on the loopback interface. Without it we won't be able to
#create a transparent tunnel.If this function is executed while starting
#sshvpn, we also want to check if a pid file exists. sshvpn should not be
#able to start while being active.
do_checks() {
	if [[ ${UID} != 0 ]]; then
		err 'need root privileges'
	 	return 1
	fi
	#Check if the calling function is start_vpn and if so check if a pid
	#file exists.
	if [[ ${FUNCNAME[1]} == start_vpn && -f "${pid_file}" ]]; then
		err "pid file ${pid_file} found"
		return 1
	fi
}


#Check if the data given is correct and enough to create a OpenSSH forward. The
#data tested here comes from a element in the forward array. When the tested
#data is incorrect we return a non-zero exit code.
check_forward() {
	#Check if the host to forward to is a valid fqdn or IP-address.
	if [[ ! $1 =~ $fqdn_regex && ! $1 =~ $ip_regex ]]; then
		err "$1 incorrect fqdn or IP-address"
		return 1
	fi
	#Check if the port to forward to is a valid port number.
	if [[ $2 -lt 1 || $2 -gt 65535 ]]; then
		err "$2 incorrect port number"
		return 1
	fi
	#Check if the host to forward from (ssh stepping stone server) is
	#a valid fqdn or IP-address.
	if [[ ! $3 =~ $fqdn_regex && ! $3 =~ $ip_regex ]]; then
		err "$3 incorrect fqdn or IP-address"
		return 1
	fi
	#Check if the port on the host to forward from (ssh stepping
	#stone server) is a valid port number.
	if [[ $4 -lt 1 || $4 -gt 65535 ]]; then
		err "$4 incorrect port number"
		return 1
	fi
	#Check if username is a valid username.
	if [[ ! $5 =~ $user_regex ]]; then
		err "$5 incorrect username"
		return 1
	fi
}

#Check if the port we want to listening on with our forward is available.
check_port() {
	#Open fd4 as a duplicate of fd2 and redirect stderr to /dev/null.
	exec 4>&2; exec 2>"${dn}"
	#Check if a daemon is listening on localhost:port. Errors when no
	#daemon is listening are send to /dev/null. Due to the previous
	#redirect. We don't want to see those error messages.
	if exec 5<>"/dev/tcp/${1}/${2}"; then
		#Restore stderr by opening fd2 as a duplicate of fd4
		exec 2>&4; exec 4>&-
		#Close network connection to localhost:port
		#exec 5<&-; exec 5>&-
		#Daemon is listening port is not free.
		return 1
	else
		#Restore stderr by opening fd2 as a duplicate of fd4
		exec 2>&4; exec 4>&-
		#No daemon is listening port is free.
		return 0
	fi
}

#If we have the host IP-address we check if it's in the hosts file. If not we
#add it to the host file. When we know the hostname we try to resolv it on the
#SSH stepping stone server and add the hostname and IP-address to the host file.
#The first octet of the IP-address will be changed to 127 so connections are
#made to the OpenSSH tunnel on the loopback interface. Adding the hostname to
#the host file pointing to the loopback interface will create our transparent
#vpn.
configure_networking() {
	#If a IP-address is given and it's not in the /etc/hosts file add it.
	#The IP-address first octet is changed to 127 so we can force traffic
	#trough the tunnel. We add a comment ${me} after the IP-address so we
	#can filter out the address later when we want to remove it from the
	#loopback interface.
	if [[ ${1} =~ ${ip_regex} ]]; then
		ip="127.${1#*.}"
		if ! grep -q "${ip}" "${hosts_file}"; then
			echo "${ip}     ${ip} #${me}" >> "${hosts_file}"
		fi
	else
		#When a hostname is given we resolv it on the SSH stepping
		#stone server. The hostname and IP-adress are added to the
		#/etc/hosts file. We change the first octet of the IP-address
		#to 127 so we can redirect the traffic trough the tunnel.
		ip="$(ssh -l "${3}" -i "${ssh_key}" "${2}" "dig ${1} +short" 2> "${dn}")"
		[[ -z ${ip} ]] && err "failed to resolv ${1}" && return 1
		ip="127.${ip#*.}"
		if ! grep -q "${1}" "${hosts_file}"; then
			echo "${ip}     ${1} #${me}" >> "${hosts_file}"
		fi
	fi
	#Check if the given IP-address is already on the loopback
	#interface if not add it.
	if ip addr show dev lo | grep "${ip}" > "${dn}" 2>&1; then
		#Check if the given port is already in use.
		if check_port "${ip}" "${4}"; then
			return 0
		else
			err "${ip}:${4} port already in use"
			return 1
		fi
	else
		if ip addr add "${ip}/32" dev lo; then
			return 0
		else
			err "failed to add ${ip} to interface lo"
			return 1
		fi
	fi
}

#Create a OpenSSH forward to the SSH stepping stone server
create_forward() {
	#${6} Username to login to SSH stepping stone server.
	#${1} Loopback IP-address.
	#${3} Port to bind on on the loopback interface IP-address.
	#${2} IP-address to forward to from SSH stepping stone server,
	#${3} Port to forward to from the SSH stepping stone server.
	#${4} hostname or IP-address of the SSH stepping stone server.
	#${5} OpenSSH port on the SSH stepping stone server.
	#${dn} redirect errors to /dev/null we dont want to see them.
	if ssh -fNl "${6}" -i "${ssh_key}" -L "${1}:${3}:${2}:${3}" "${4}" -p "${5}" > "${dn}" 2>&1; then
		#Determine PID of startend OpenSSH forward and add
		#it to the pid file in the pid file.
		if ! lsof -t -i "@${1}:${3}" >> "${pid_file}"; then
			err "failed to ssh forward PID to ${pid_file}"
			return 1
		else
			return 0
		fi
	else
		return 1
	fi
}

start_vpn() {
	if ! do_checks; then
		err "failed checks"
		return 1
	fi
	for f in "${forward[@]}"; do
		#${h} Host to forward to from the SSH stepping stone server.
		#${p} = Port on host to forward to from the SSH stepping stone server.
		#${s} = The SSH stepping stone server.
		#${x} = The port SSH port on the SSH stepping stone.
		#${u} = The username on the SSH stepping stone.
		while IFS=',' read h p s x u; do
			if ! check_forward "${h}" "${p}" "${s}" "${x}" "${u}"; then
				err "forward variable incorrect"
				return 1
			fi
			if ! configure_networking "${h}" "${s}" "${u}" "${p}"; then
				err "failed to configure networking"
				return 1
			fi
			if ! create_forward "${ip}" "${h}" "${p}" "${s}" "${x}" "${u}"; then
				err "failed to create OpenSSH forward"
				return 1
			fi
		done<<<"${f}"
	done
}

#When the pid file exists kill all the PID's in it and remove the pid file.
kill_forward() {
	if [[ -f $pid_file ]]; then
		while read pid ; do
			if ! kill ${pid} > "${dn}" 2>&1; then
				err "failed to kill ${pid}"
				return 1
			fi
		done<"${pid_file}"
		if ! rm "${pid_file}" > "${dn}" 2>&1; then
			err "failed to remove ${pid_file}"
			return 1
		fi
	fi
}

#Remove all the IP-addresses on the loopback interface we added for the OpenSSH
#forwards. We can identify the IP-addresses in the /etc/hosts file wearing the
#comment from the variable ${me}.
delete_lo_ip() {
	#Add all sshvpn IP-addresses to the array loopback_ips
	loopback_ips=( $(grep "${me}" /etc/hosts | cut -d ' ' -f 1) )
	for i in "${loopback_ips[@]}"; do
		#Check if the IP-address is still on the interface.
		if ip addr show dev lo | grep -q "${i}"; then
			#If the IP-address is still on the interface remove it.
			if ! ip addr del "${i}/32" dev lo; then
				err "failed to remove IP from lo"
				return 1
			fi
		fi
	done
}

#Check if there are entries in the /etc/hosts file wearing the ${me} tag and
#if so remove them. We dont want these entries when the tunnels are not up.
delete_host_resolv() {
	if ! sed -i "/#${me}/d" "${hosts_file}"; then
		err "failed to remove host from $hosts_file"
		return 1
	fi
}

kill_vpn() {
	if ! do_checks; then
		err "failed checks"
		return 1
	fi
	if ! kill_forward; then
		err "failed to kill ssh forward"
		return 1
	fi
	if ! delete_lo_ip; then
		err "failed to remove IP"
		return 1
	fi
	if ! delete_host_resolv; then
		err "failed to remove host from resolv"
		return 1
	fi
}

main() {
	if [[ -z ${1} ]]; then
		usage
		exit 1
	else
		while getopts skhv pars; do
			case "${pars}" in
			s)
				if ! start_vpn; then
					err "failed to start vpn"
					exit 99
				fi
				;;
			k)
				if ! kill_vpn; then
					err "failed to stop vpn"
					exit 99
				fi
				exit 0
				;;
			h)
				usage
				exit 0
				;;
			*)
				usage
				exit 99
				;;
			esac
		done
	fi
}

main "${@}"
