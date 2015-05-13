#!/bin/bash
########################################################################
# yapkd.sh - Yet Another Port Knocking  Daemon		                   #
#								                                       #
#   Copyright (C) 2007-2011  Anathema`				                   #
#								                                       #
#   This program is free software: you can redistribute it and/or      #
#   modify it under the terms of the GNU General Public License as     #
#   published by the Free Software Foundation, either version 2 of     #
#   the License.						                               #
#								                                       #
#   This program is distributed in the hope that it will be useful,    #
#   but WITHOUT ANY WARRANTY; without even the implied warranty of     #
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      #
#   GNU General Public License for more details.		               #
#								                                       #
#   You should have received a copy of the GNU General Public License  #
#   along with this program.  If not, see			                   #
#   <http://www.gnu.org/licenses/>.				                       #
#								                                       #
#								                                       #
#  Cheers to all ex-screw and ex-b.r. :)                               #
########################################################################


# The file with the keys in must be in the form:
#
# firstkey
# secondkey
# thirdkey
# and so on...
KEYFILE="passwd" # KEY FILE
VERBOSE=0
IFACE=eth0
PORT="2007" # Port to listen on
METHOD=-1
VER=1.0
CRYPTSEC="msackhacklab" # cryptcat key enc
MAX_FAIL=3
SECTYPE=""
IPDB="/var/run/yapki.db"
ANTIDOS=1 # default is to active Anti-DOS mode

###########################
#                         #
###### BEGIN OF CODE ######
#                         #
###########################

function banner() {
	echo -e "\n..::[Yet Another Port Knocking Implementation v.$VER]::.."
	echo -e "\t..::[Davide \`Anathema\` Barbato]::.."
	echo -e "\t\t..::[MSAck Hacklab]::..\n"
}

function usage() {
	banner
	echo "Usage:"
	echo -e "`basename $0` [-h] [-v] [-d] [-i interface] [-k keyfile] [-p port] -s sec type -m method"
	echo "Where:"
	echo -e "-h\tshow this help"
	echo -e "-v\tverbose output"
	echo -e "-d\tAnti-DOS disabled (default: active)"
	echo -e "-i\tset the interface on which listen to (default: $IFACE)"
	echo -e "-k\tselect the file with security key(s) (default: $KEYFILE)"
	echo -e "-p\tset the port to bind on (default: $PORT)"
	echo -e "-s\tset the security method to use"
	echo -e "\tmd5 checking method"
	echo -e "\totp (One Time Password) method"
	echo -e "-m\tselect the port knocking method to use"
	echo -e "\t1\tiptables rule"
	echo -e "\t2\tsshd down/up"
	exit 0
}

function check_args() {
	local ifc=`ifconfig -a | grep "${IFACE}"`

	if [ ! -s ${KEYFILE} ]; then 
		echo "[x] Password file "$KEYFILE" not found or empty."
		exit 1
	fi
	
	if [ -z "${ifc}" ]; then
		echo "[x] Interface "${IFACE}" not present."
		exit 1
	fi	

	if [ "${METHOD}" != "1" ] && [ "${METHOD}" != "2" ]; then
		echo "[x] Invalid method."
		exit 1
	fi

	if [ -z "${SECTYPE}" ] || [ "${SECTYPE}" != "md5" ] && [ "${SECTYPE}" != "otp" ]; then
		echo "[x] Invalid security type."
		exit 1
	fi
}

function check_bins() {
	CRYPTCAT=`which cryptcat`
	IPTABLES=`which iptables`
	SSHD=`which sshd`

	if [ -z "${CRYPTCAT}" ]; then
		echo "[x] Cryptcat not found. Please install it."
		exit 1
	fi

	if [ -z "${IPTABLES}" ]; then
		echo "[x] Iptables not found. Please install it."
		exit 1
	fi

	if [ -z "${SSHD}" ]; then
		echo "[x] SSHD not found. Please install it."
		exit 1
	fi
}

function check_sshd() {
	local p=`ps -C sshd -o pid=`
	if [ -z "$p" ]; then
		echo "[!] WARNING: SSHd is NOT running."
	fi
}

function check_startup() {
	local pr

	# clean db if cleaner function didn't work well...
	if [ -e "${IPDB}" ]; then
		rm -f "${IPDB}"
	fi
	# ...and create a blank one
	touch "${IPDB}"
	
	# if we have two instances of yapki there can be
	# some conflicts...with this check we can try to
	# avoid them
	pr=$(ps aux | grep `basename $0`)
	if [ -z "${pr}" ]; then
		echo "[x] Error: `basename $0` already running!"
		exit 1
	fi
}

function cleaner() {
	if [ -e "$tmpfile" ]; then
		rm -f "$tmpfile"
	fi

	if [ -e "${IPDB}" ]; then
		rm -f "${IPDB}"
	fi

	# kill the check_user_login() bg function
	kill -9 $subpid
	exit 0
}

# from cryptcat logfile we grep the connected IP
function grep_ipcon() {
	IPCON=`grep "connect" ${1} | awk -F ' ' '{print $6}'`
	IPCON=${IPCON#[}
	IPCON=${IPCON%]}
}

function get_ip_index() {
	local index=0
	local ipc="$1"
	
	# fast check to avoid full array scrolling
	if [[ ! "${IPLIST[@]}" =~ "$ipc" ]]; then
		echo "-1"
	fi
	# full array scrolling!
	while [ "${index}" -lt "${#IPLIST[@]}" ]; do
		if [ "${IPLIST[$index]}" == "${ipc}" ]; then
			echo "$index"
		fi
		index=$(( $index + 1 ))	
	done
}

# this function count each IP error connection
# to a max of 3...then ban it
function log_fail() {
	local ipidx
	local tfile="$1"

	grep_ipcon "${tfile}"
	ipidx=$(get_ip_index "${IPCON}")
	
	# in this case this is the first $IPCON failed login
	if [ "$ipidx" == "-1" ]; then
		IPLIST=( "${IPLIST[@]}" "${IPCON}" )
		IPTRYLIST=( "${IPTRYLIST[@]}" 1 )
	else # otherwise let's increment his counter
		IPTRYLIST[$ipidx]=$(( ${IPTRYLIST[$ipidx]} + 1 ))
		# ban!	
		if [ "${IPTRYLIST[$ipidx]}" == "${MAX_FAIL}" ]; then
			${IPTABLES} -A INPUT -p tcp --dport ${PORT} -s ${IPCON} -j DROP
		fi
	fi
}

# this function write the successful authenticated
# IP to the db file $IPDB
function log_success() {
	local ftmp="$1"
	local ip

	grep_ipcon "${ftmp}"
	ip=$(grep "${IPCON}" "${IPDB}")
	# avoid to write the same IP two time
	# multiple connection from same host possibile!
	# NOTE: in the case of OTP sec method, the same
	# IP need to specify a different key from the old one
	if [ -z "$ip" ]; then
		echo "$IPCON" >> "${IPDB}"
	fi
} 		

# make IPLIST and IPTRYLIST shorter
function remove_ip_list() {
	local idx=$(get_ip_index "$1")

	${IPLIST[$idx]}=""
	if [ "${ANTIDOS}" == "1" ]; then
		${IPTRYLIST[$idx]}=""
	fi
	#IPLIST=(${IPLIST[@]%%$ip})
}

# this function deletes the iptables rule
# from $1 (chain) associated to $2 (IP logged out)
function remove_ip_chain() {
	local num=-1
	local chain=$1
	local ip=$2
	# count the rules to find the exact line to delete
	${IPTABLES} -S "$chain" | while read rule; do
		num=$(( $num + 1 ))
		# we find it!
		if [[ "$rule" =~ "$ip" ]]; then
			${IPTABLES} -D "$chain" $num
			break
		fi
	done
}

function remove_ip_iptables() {
	remove_ip_chain "INPUT" $1
	remove_ip_chain "OUTPUT" $1
}

function md5_sectype() {
	local tfile="$1"
	local md5orig=$(md5sum $KEYFILE | awk -F ' ' '{print $1}')
	# run the listening cryptcat and wait for a key
	local md5remote=$("${CRYPTCAT}" -k "${CRYPTSEC}" -l -p ${PORT} -v 2> "$tfile")
	
	echo "[*] Got md5 - checking..."
	if [ "${md5orig}" != "${md5remote}" ]; then # if the keys are different
		return 1
	fi
	
	return 0
}

# Sonne's first idea and suggestion 
# modified by me
function otp_sectype() {
	local tfile="$1"
	local rkey=$("${CRYPTCAT}" -k "${CRYPTSEC}" -l -p ${PORT} -v 2> "$tfile")
	echo "[*] Got key - checking..."
	local pfile=$(grep "$KEYFILE" "${rkey}")
	
	# the key is already used...OTP!
	if [ -z "$pfile" ] || [[ "$pfile" =~ "blacklisted" ]]; then
		return 1
	else # blacklist the new key...OTP!
		sed -i 's/'"${pfile}"'/'"${pfile}"':blacklisted/' "$KEYFILE"	
	fi
	return 0
}

function set_sectype() {
	if [ "${SECTYPE}" == "md5" ]; then
		sectype="md5_sectype"
	elif [ "${SECTYPE}" == "otp" ]; then
		sectype="otp_sectype"
	fi
}

function set_method() {
	if [ "${METHOD}" == "1" ]; then
		start_method="iptables_method"
	elif [ "${METHOD}" == "2" ]; then
		start_method="sshdownup_method"
	fi
}

function iptables_method() {
	local sshport=`netstat -anp --inet | grep sshd | awk -F ' ' '{print $4}'|cut -d ':' -f2 2> /dev/null`

	if [ -z "${sshport}" ]; then
		if [ "$VERBOSE" == "1" ]; then
			echo "[!] Cannot get SSHd bind port. Assuming 22"
		fi
		sshport=22
	fi
	
	local ret=$(grep "${IPCON}" "${IPDB}")
	# in this case the IP already had authenticated themself
	# then we already have the IPTABLES rules and no need to
	# re-write the same rule
	if [[ "$ret" =~ "connected" ]]; then
		return 1
	fi
	IPLIST=( "${IPLIST[@]}" "${IPCON}" )
	
	# open it!
	${IPTABLES} -I INPUT 1 -p tcp --dport $sshport -s "${IPCON}" -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
	${IPTABLES} -I OUTPUT 1 -p tcp --sport $sshport -d "${IPCON}" -m state --state RELATED,ESTABLISHED -j ACCEPT
	
	return 0
}

function sshdownup_method() {
	# TODO check if this function actually works
	# verificare se sshd e' up o down
	# nel caso sia up verificare se qualcuno e' loggato
	# in caso contrario buttarlo giu
	# tutto questo dovrebbe farlo checkssshd()

	# vedere il main della vecchia versione (ci sara'?)
	local ret=$(get_ip_index "$IPCON")

	if [ "$ret" != "-1" ]; then
		return 1
	fi
	IPLIST=( "${IPLIST[@]}" "${IPCON}" )
}

# background function to check whenever an user logoff
function check_user_login() {
	local line

	ofs=$IFS
	# let's make it running endlessy
	while true; do
		IFS=$'\n'
		# read each IP
		for ip in "$(cat "${IPDB}")"; do
			# if already disconnected we need to do nothing
			if [[ "$ip" =~ "disconnected" ]]; then
				continue
			fi
			# check if $ip is connected to SSH
			line=$(netstat -np --inet | grep sshd | grep "$ip")
			
			# `if [ -z $line ]` means that $ip is connected to SSH
			# if so we need to add the ":connected" label to that IP
			# if not present.
			# if `if [ -z $line ]` is false but the IP has the label
			# connected, then it means that $ip had logged out, then
			# remove it from IPLIST, IPTRYLIST and from iptables
			if [[ "$ip" =~ "connected" ]] && [ ! -z "${line}" ]; then
				remove_ip_list "${ip}"
				remove_ip_iptables "${ip}"
			elif [[ ! "$ip" =~ "connected" ]] && [ -z "${line}" ]; then
				sed -i -e 's/'"${ip}"'/'"${ip}"':connected/' "$IPDB" 
			fi
		done
		IFS=$ofs
		# make it not so cpu intensive (hey, it's a while true loop!)
		sleep 15
	done
}
		
		
# Function checking if the login on ssh was successful
function checksshd() {
	ret=$(ps auxw | grep sshd: | grep -v grep >/dev/null; echo $?) # see if someone is logged in
	if [ "${ret}" != "0" ]; then # if not
		echo "[!] Noone logged in! shutting down sshd..." # kill sshd
		killall -9 sshd
                break
	fi
	sleep 2
}

# Main port knocking loop
function mainloop() {
	# this file is fondamental to whole script
	local tmpfile="tmp.$(date +%s)"

	echo "[+] Waiting for auth on port ${PORT}."
	local ret=$($sectype $tmpfile)
	
	if [ "$ret" == "1" ]; then
		echo "[x] Wrong key supplied."
		if [ "${ANTIDOS}" == "1" ]; then
			# log the IP login failed
			log_fail "${tmpfile}"
		fi
		rm -f "${tmpfile}"
	else
		echo "[*] Key is valid - Opening sshd..."
		log_success "${tmpfile}"
		rm -f "${tmpfile}"
		# function pointer style
		$start_method
	fi
}

# set the cleaner function
trap 'cleaner' 2

if [ "${UID}" != "0" ]; then
	echo "[!] You must be root."
	exit 1
fi

if [ "$#" -lt 2 ]; then
	usage
fi

while getopts "hvdp:k:i:m:s:" argv; do
	case "${argv}" in
		v) VERBOSE=1;;
		p) PORT="$OPTARG";;
		k) KEYFILE="$OPTARG";;
		i) IFACE="$OPTARG";;
		m) METHOD="$OPTARG";;
		s) SECTYPE="$OPTARG";;
		d) ANTIDOS=0;;
		h|*) usage;;
	esac
done

# some initial checks
check_args
check_bins
check_sshd
check_startup

# set modes
set_method
set_sectype

check_user_login&
subpid=$!

# start the whole thing
while true; do mainloop; done
