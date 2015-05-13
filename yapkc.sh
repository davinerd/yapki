#!/bin/bash
########################################################################
#  yapkc.sh - Yet Another Port Knocking Client   		               #
#								                                       #
# Just specify the host you want to connect to		                   #
#								                                       #
#   Copyright (C) 2007-2011  Anathema`				                   #
#								                                       #
#   This program is free software: you can redistribute it and/or      #
#   modify it under the terms of the GNU General Public License as     #
#   published by the Free Software Foundation, either version 2 of the #
#   License, or any later version.				                       #
#								                                       #
#   								                                   #
#   This program is distributed in the hope that it will be useful,    #
#   but WITHOUT ANY WARRANTY; without even the implied warranty of     #
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      #
#   GNU General Public License for more details.		               #
#								                                       #
#   You should have received a copy of the GNU General Public License  #
#   along with this program.  If not, see 			                   #
#   <http://www.gnu.org/licenses/>.				                       #
#								                                       #
#  Cheers to all ex-screw and ex-b.r. :)		                       #
########################################################################

CRYPTOKEY="msackhacklab"
PASS="passwd"

function usage () {
	echo "Usage: $0 server port"
        exit 1
}

# this function replace the -q netcat option
function kill_crypt() {
	while true; do
		#c=`ps -C cryptcat -o pid=`
		c=`ps -U $USER | grep cryptcat | awk -F ' ' '{print $1}'`
		if [ x"$c" != "x" ]; then
			kill -9 $c
			return
		fi
	done
}

#check if file exist and isn't null and number of params
if  [ "${#}" -lt 2 ] || ! [ -s "${PASS}" ]; then 
	usage
fi

echo "[+] Creating md5 hash file..."
md5check=$(md5sum ${PASS} | awk -F ' ' '{print $1}')
echo "[+] Sending passwd hash file to ${1} on port ${2}..."
kill_crypt&
send=$(echo $md5check | cryptcat -k "$CRYPTOKEY" ${1} ${2} &>/dev/null)
sleep 10
echo "[*] Key sent."
echo "[*] Now try to login via ssh!"
exit 0
