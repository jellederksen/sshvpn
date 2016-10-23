#!/bin/bash

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

#Sshvpn.sh create an vpn using ssh local forward.

forward[0]='demo.epsilix.nl,993,wormhole.epsilix.nl,22,jelle'

ssh_key='/home/jelle/.ssh/id_rsa'

#Do not edit below this line####################################################
me="${0##*/}"
dn='/dev/null'
fqdn_regex='^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$'
ip_regex='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
user_regex='^[a-z_][a-z0-9_]{0,32}$'
pid_file='/tmp/sshvpn.pid'
hosts_file='/etc/hosts'

print_stderr() {
	echo "${0##*/}: ${1}" >&2
}

#Perform basis checks for sshvpn to be able to function.
do_checks() {
	if [[ ${UID} != 0 ]]; then
		print_stderr 'need root privileges'
	 	return 1
	fi
	#check of the calling function equals start_vpn We only
	#want to check for a pid file when we start sshvpn.
	if [[ ${FUNCNAME[1]} == start_vpn && -f "${pid_file}" ]]; then
		print_stderr "found pid file ${pid_file}"
		return 1
	fi
	return 0
}

check_forward() {
	#Check if the host to forward to is a valid fqdn or IP-address.
	if [[ ! $1 =~ $fqdn_regex && ! $1 =~ $ip_regex ]]; then
		print_stderr "$1 incorrect fqdn or IP-address"
		return 1
	fi
	#Check if the port to forward to is a valid port number.
	if [[ $2 -lt 1 || $2 -gt 65535 ]]; then
		print_stderr "$2 incorrect port number"
		return 1
	fi
	#Check if the host to forward from is a valid fqdn or IP-address.
	if [[ ! $3 =~ $fqdn_regex && ! $3 =~ $ip_regex ]]; then
		print_stderr "$3 incorrect fqdn or IP-address"
		return 1
	fi
	#Check if the port on the host to forward from is a valid port number.
	if [[ $4 -lt 1 || $4 -gt 65535 ]]; then
		print_stderr "$4 incorrect port number"
		return 1
	fi
	#Check if username is a valid username.
	if [[ ! $5 =~ $user_regex ]]; then
		print_stderr "$5 incorrect username"
		return 1
	fi
	return 0
}

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

configure_networking() {
	if [[ ${1} =~ ${ip_regex} ]]; then
		ip="127.${1#*.}"
		if ! grep -q "${ip}" "${hosts_file}"; then
			echo "${ip}     ${ip} #${me}" >> "${hosts_file}"
		fi
	else
		ip="$(ssh -l "${3}" -i "${ssh_key}" "${2}" "dig ${1} +short" 2> "${dn}")"
		[[ -z ${ip} ]] && print_stderr "failed to resolv ${1}" && return 1
		ip="127.${ip#*.}"
		if ! grep -q "${1}" "${hosts_file}"; then
			echo "${ip}     ${1} #${me}" >> "${hosts_file}"
		fi
	fi
	if ip addr show dev lo | grep "${ip}" > "${dn}" 2>&1; then
		if check_port "${ip}" "${4}"; then
			return 0
		else
			print_stderr "${ip}:${4} port already in use"
			return 1
		fi
	else
		if ip addr add "${ip}/32" dev lo; then
			return 0
		else
			print_stderr "failed to add ${ip} to interface lo"
			return 1
		fi
	fi
}

create_forward() {
	if ssh -fNl "${6}" -i "${ssh_key}" -L "${1}:${3}:${2}:${3}" "${4}" -p "${5}" > "${dn}" 2>&1; then
		if ! lsof -t -i "@${1}:${3}" >> "${pid_file}"; then
			print_stderr "failed to ssh forward PID to ${pid_file}"
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
		print_stderr "failed checks"
		return 1
	fi
	for f in "${forward[@]}"; do
		#h = hostname, p = port, s = ssh host, x = port, u = username
		while IFS=',' read h p s x u; do
			if ! check_forward "${h}" "${p}" "${s}" "${x}" "${u}"; then
				print_stderr "forward variable incorrect"
				return 1
			fi
			if ! configure_networking "${h}" "${s}" "${u}" "${p}"; then
				print_stderr "failed to configure networking"
				return 1
			fi
			if ! create_forward "${ip}" "${h}" "${p}" "${s}" "${x}" "${u}"; then
				print_stderr "failed to create SSH forward"
				return 1
			fi
		done<<<"${f}"
	done
	return 0
}

kill_forward() {
	while read pid ; do
		if ! kill ${pid} > "${dn}" 2>&1; then
			print_stderr "failed to kill ${pid}"
			return 1
		fi
		done<"${pid_file}"
		if ! rm "${pid_file}" > "${dn}" 2>&1; then
			print_stderr "failed to remove ${pid_file}"
			return 1
		fi
	return 0
}

delete_lo_ip() {
	loopback_ips=( $(grep "${me}" /etc/hosts | cut -d ' ' -f 1) )
	for i in "${loopback_ips[@]}"; do
		if ! ip addr del "${i}/32" dev lo; then
			print_stderr "failed to remove IP from lo"
			return 1
		fi
	done
	return 0
}

delete_host_resolv() {
	if grep -q "#${me}" "${hosts_file}" > "${dn}" 2>&1; then
		if ! sed -i "/#${me}/d" "${hosts_file}"; then
			print_stderr "failed to remove host from $hosts_file"
			return 1
		fi
	fi
	return 0
}

kill_vpn() {
	if ! do_checks; then
		print_stderr "failed checks"
		return 1
	fi
	if ! kill_forward; then
		print_stderr "failed to kill ssh forward"
		return 1
	fi
	if ! delete_lo_ip; then
		print_stderr "failed to remove IP"
		return 1
	fi
	if ! delete_host_resolv; then
		print_stderr "failed to remove host from resolv"
		return 1
	fi
	return 0
}


main() {
	if [[ -z ${1} ]]; then
		print_stderr "${usage}"
		exit 99
	else
		while getopts skhv pars; do
			case "${pars}" in
			s)
				if ! start_vpn; then
					print_stderr "failed to start vpn"
					exit 99
				fi
				;;
			k)
				if ! kill_vpn; then
					print_stderr "failed to stop vpn"
					exit 99
				fi
				exit 0
				;;
			h)
				print_stdout "${usage}"
				exit 0
				;;
			*)
				print_stderr "${usage}"
				exit 99
				;;
			esac
		done
	fi
}

main "${@}"
