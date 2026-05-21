#!/bin/sh
##############################
# General disclaimer, utilize this script at your own responsibility.
# Any modifications to the script should be shared back.
##############################
# Upcoming functions ..
# - add a switch to generate suggestion of sequential remove order
# - add switch to run autobalance right after adding the last node
# - add a switch to smartfail in parallel
# - initiate in screen session 
# - add disclaimer
# - promote system files
#
##############################
# To be fixed
# smartfail report (calculate the seconds from different phases)
# for i in `isi job reports view 113626|egrep -i elapsed|awk '{print $3;}'`; do echo Adding: $i; totalsum=(($totalsum + $i)); done; echo "the total sum in seconds is: $totalsum;totalsum=
#

##############################
# APPLIED FIXES
# 0.70 added a feature to list node model when identifying the nodes to be removed from the cluster
##############################

clsmgmt_date="2024/09/14"
clsmgmt_license="MIT"
clsmgmt_author="Elie Koivunen"
clsmgmt_maintainer="Elie Koivunen"
clsmgmt_email="Elie.Koivunen@dell.com"
clsmgmt_credits=""
clsmgmt_disclaimer=" \r\n Copyright 2024 Dell \r\n\r\n Permission is hereby granted, free of charge, to any person obtaining  \r\n a copy of this software and associated documentation files (the-Software),  \r\n to deal in the Software without restriction, including without limitation  \r\n the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or  \r\n sell copies of the Software, and to permit persons to whom the Software is  \r\n furnished to do so, subject to the following conditions: The above copyright  \r\n notice and this permission notice shall be included in  \r\n all copies or substantial portions of the Software. All changes should be  \r\n shared back. \r\n\r\n THE SOFTWARE IS PROVIDED AS-IS, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, \r\n INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A \r\n PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT \r\n HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION \r\n OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH \r\n THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE."

SCRIPT_VERSION="0.70" 
SCRIPT_PATH=$(pwd) 
##############################

##############################
# Define usage function to print help menu
##############################
usage() {
	echo ""
	echo "###################################################################################"
	echo ""	
	echo -e "${clsmgmt_disclaimer}"
	echo ""	
	echo "Author:		${clsmgmt_author}"
	echo "Maintainer:	${clsmgmt_maintainer}"
	echo "Credits:		${clsmgmt_credits}"
	echo "Email:		${clsmgmt_email}"
	echo "Version:	${SCRIPT_VERSION}"
	echo "Release date:	${clsmgmt_date}"
	echo "License:	${clsmgmt_license}"
	echo ""
	echo "###################################################################################"
	echo "General disclaimer, utilize this script at your own responsibility."
	echo "Any modifications to the script should be shared back."
	echo ""
	echo "Script version: ${SCRIPT_VERSION}"
	echo ""
	echo "Usage: $0 [OPTIONS]"
	echo ""
	echo "Options:"
	echo "  --remove-nodes-lnn=11,10,9,8		          	Remove nodes with the specified node identifiers"
	echo "  --add-nodes-serials=/PATH/TO/FILE/WITH/SERIALS  	Add nodes with serial numbers listed in the specified file"
	echo "  --carve-nodes-lnn=4,3,2                         	Carve the selected nodes into own nodepool"
	echo "  --list-node-neighborhoods                       	Display existing node neighborhoods and the corresponding member nodes"
	echo "  --help                                        	Display this help menu"
	echo ""
	echo "Run this script in a screen session!"
	echo "Example: screen -S cls-mgmt-sh -d -m sh ./cls-mgmt.sh --remove-nodes-lnn=8,7,6,5"
	echo ""
	echo "###################################################################################"

}

##############################
# remove nodes function
##############################
remove_nodes() {

# reset var
myremcount=""


# defining paths
myremovablenodes="${SCRIPT_PATH}/mgmt-nodes-removable.txt"
mylogfile="${SCRIPT_PATH}/log-nodes-removed.txt"

# remove previously created log file and list of removable nodes 
rm -rf ${mylogfile}| tee -a ${mylogfile}
rm -rf ${myremovablenodes}| tee -a ${mylogfile}

# Logging on which node the script is running
echo "Running on: $(hostname)" | tee -a ${mylogfile}

#Visual inspection of provided variable
user_add_input="$1"
echo "Provided input: `echo ${user_add_input}|sed 's/--remove-nodes-lnn=//g'`"| tee -a ${mylogfile}

# Clean up the user provided input prior to processing 
if echo "$user_add_input"|sed 's/--remove-nodes-lnn=//g'| grep -qE '^[0-9,]+$'; then
	echo "Provided value is valid, continuing .."| tee -a ${mylogfile}
	echo "Current path:${SCRIPT_PATH}"| tee -a ${mylogfile}
	# echo "Original node identifiers: $(echo $1 | sed 's/--remove-nodes-lnn=//g')"| tee -a ${mylogfile}
	# echo "Modified node identifiers: $(echo $1 | sed 's/.*=//; s/,/ |/g')"| tee -a ${mylogfile}
	echo "Identified the following nodes:"| tee -a ${mylogfile}

	# list identified nodes to be removed
	for node in $(echo "$1" | sed 's/.*=//; s/,/ /g'); do
		echo
		echo "To be removed Node LNN: $node"| tee -a ${mylogfile}
		#isi_nodes %{lnn} %{serialno}|egrep -i "^$node" >>  ${myremovablenodes}
		isi_nodes %{lnn} %{serialno}|egrep -w "\b^$node\b" >>  ${myremovablenodes}
		#v0.70 start
		isi_nodes %{lnn} %{serialno}|egrep -w "\b^$node\b"
		isi_for_array -n$node "isi_hw_status |egrep 'Product:'"|awk '{print $3;}'| tee -a ${mylogfile}
		#v0.70 end
	done
	
	# count total number of nodes to be removed based on output
	myremcount="`cat ${myremovablenodes} |wc -l|awk '{print $1;}'`"
	echo
	echo "Total number of nodes to be removed: ${myremcount}" | tee -a ${mylogfile}
	
	echo "Revising node details and removal order:"| tee -a ${mylogfile}
	cat  ${myremovablenodes}| tee -a ${mylogfile}

	# USER ACKNOWLEDGE TO CONTINUE 
	echo
	echo "Your acknowledgement is required to proceed. Do you want to continue? (y/n)"| tee -a ${mylogfile}
	read user_ack
	if [ "$user_ack" != "y" ]; then
		echo "Exiting script. No changes have been made."| tee -a ${mylogfile}
		exit 1
	fi
	echo "Proceeding..."| tee -a ${mylogfile}
	echo "The following nodes have been flagged for removal:"| tee -a ${mylogfile}
	cat ${myremovablenodes} | tee -a ${mylogfile}

	myremincr="0"
	
	#execute the removal of of nodes in an orderly fashion
	# read the file line by line
while read line; do
	# extract the variables from the user input
	mylnn=$(echo "$line" | awk '{print $1;}')
	nodeserial=$(echo "$line" | awk '{print $2;}')
	mydatestart=$(date)

	#
 	# Add code to check that there arent other flexprotect jobs running before triggering a smartfail
 	#
  
	echo "Timestamp smartfail job start: ${mydatestart}"| tee -a ${mylogfile}
	echo "Smartfailing node LNN: ${mylnn} Serial: ${nodeserial}"| tee -a ${mylogfile}
	echo "Executing: isi devices node smartfail --node-lnn=${mylnn} --force"| tee -a ${mylogfile}
	isi devices node smartfail --node-lnn=${mylnn} --force

	# Check if the smartfailing has completed
    while ! checkstr=$(isi devices node list --no-header --no-footer | egrep ${nodeserial}); do
    # If not present, wait for 900 seconds and check again
		mydatecheck=$(date)
		echo "Timestamp status-check: ${mydatecheck}"| tee -a ${mylogfile}
    sleep 900
    done

    #showback jobengine report id and duration of individual node removal
    myjereportid=$(isi job reports list|egrep -i "FlexProtectLin|FlexProtect" | egrep Succeeded | tail -1|awk '{print $2;}')
    myjeduration=$(isi job reports view `isi job reports list |egrep -i "FlexProtectLin|FlexProtect" | egrep Succeeded | tail -1 | awk '{print $2;}'` | egrep -i elapsed | head -1|awk '{print $5;}'|sed 's/(//g'|sed 's/)//g')
    echo "Node removal report id: ${myjereportid} "| tee -a ${mylogfile}
    echo "Node removal duration: ${myjeduration} "| tee -a ${mylogfile}
    echo "Removed LNN:${mylnn} SERIAL:${nodeserial}"| tee -a ${mylogfile}

	# list removed node count
    myremincr=$((myremincr+1))
	echo "Smartfail count: $myremincr/${myremcount}"| tee -a ${mylogfile}

	mydatecomplete=$(date)
	echo "Timestamp of node expulsion completion: ${mydatecomplete}"| tee -a ${mylogfile}
    echo "-----"| tee -a ${mylogfile}

    # waiting for 5 minutes before repeating the loop process as a grace period for hanging activity.
    echo "Waiting for 5 minutes grace period before looping .."| tee -a ${mylogfile}
    sleep 300	


# If the string is present, continue with the next entry
done < ${myremovablenodes}


echo "Total of smartfailled nodes: $myremincr/${myremcount}"| tee -a ${mylogfile}

echo "Activity completed!"| tee -a ${mylogfile}
exit 0
else
    echo "Input string is not valid, quiting!"| tee -a ${mylogfile}
	exit 1
fi


}

##############################
# add nodes function
##############################
add_nodes() {
# reset var
myaddinc=""
#capture user provided input
myaddablenodes="`echo $1|sed 's/--add-nodes-serials=//g'`"
mylogfile="${SCRIPT_PATH}/log-nodes-join.txt"

#cleanup previous log files
rm -rf ${mylogfile}

# Logging on which node the script is running
echo "Running on: $(hostname)" | tee -a ${mylogfile}

# verify that the nodes to be added are visible on the cluster backend and thus ready to be joined ..
echo "Verify the nodes to be added are visible in the system .."| tee -a ${mylogfile}
echo .| tee -a ${mylogfile}
isi devices node list --no-header --no-footer | awk '{print $1}' > mgmt-joinable-nodes.txt| tee -a ${mylogfile}
rm -fr  mgmt-nodes_not_found.log 2> /dev/null | tee -a ${mylogfile}
for i in $(cat $myaddablenodes)
        do
           grep -q $i mgmt-joinable-nodes.txt | tee -a ${mylogfile}
           ext_status=$?
           if [ $ext_status =  1 ]
              then
                 echo $i >> mgmt-nodes_not_found.log | tee -a ${mylogfile}
           fi
        done
    if [  -f mgmt-nodes_not_found.log ]
       then
        echo "Following serials were not found" | tee -a ${mylogfile}
        cat  mgmt-nodes_not_found.log | tee -a ${mylogfile}
        echo "Exiting script, no changes were made" | tee -a ${mylogfile}
        exit 1 | tee -a ${mylogfile}
     fi

#validate that file/path is correct
if [ -f "$myaddablenodes" ]; then
  echo "The file path is valid .."| tee -a ${mylogfile}
	# excess mylogfile variable entry
 	#mylogfile="${SCRIPT_PATH}/log-nodes-added.txt"
	echo "Current path:${SCRIPT_PATH}"| tee -a ${mylogfile}
	echo "Adding nodes with serial numbers listed in: ${myaddablenodes}"| tee -a ${mylogfile}
	cat ${myaddablenodes}| tee -a ${mylogfile}

	# count total number of nodes to be added based on output
	myaddcount="`cat ${myaddablenodes} |wc -l|awk '{print $1;}'`"
	echo "Total number of nodes to be added: ${myaddcount}" | tee -a ${mylogfile}

	myaddincr="0"

	# USER ACKNOWLEDGE TO CONTINUE 
	echo "Your acknowledgement is required to proceed. Do you want to continue? (y/n)"| tee -a ${mylogfile}
	read user_ack
	if [ "$user_ack" != "y" ]; then
		echo "Exiting script. No changes have been made."| tee -a ${mylogfile}
		exit 1
	fi
	echo "Proceeding..."| tee -a ${mylogfile}

# process node addition to the cluster in an orderly fashion 
	while read line; do
	# check joinable node state BEGIN
	#
	# A node that is visible in the backend may be the following states:
	# - error ; in the case of hardware or inherited issues.
	# - working ; in the process of joining the cluster.
	# - available ; ready to join a cluster.

	echo "Monentarily holding back joining of the node to verify that there are no nodes in an ERROR or WORKING STATE .."| tee -a ${mylogfile}
	check_node_join_state="isi devices node list --verbose --no-header --no-footer"

	#  check join_state_output
	check_join_state() {
	    join_state_output=$($check_node_join_state)

	# Check for "error" state in the join_state_output
    	echo "$join_state_output" | grep -iq "error"
    	if [ $? -eq 0 ]; then
        	echo "A node in error was found and operator review is required to remediate!"| tee -a ${mylogfile}
        	exit 1
    	fi	

    	# Check for "working" state in the join_state_output
    		echo "$join_state_output" | grep -iq "work"
    	if [ $? -eq 0 ]; then
        	return 1
    	else
        	return 0
    	fi
	}

	# Loop to backoff in case a joinable node is found in a working state
 	while true; do
    	check_join_state
    	result=$?
    	if [ $result -eq 1 ]; then
        	echo "A joinable node was found in a Working state, waiting for 900 seconds."| tee -a ${mylogfile}
        	sleep 900
    	else
        	echo "No nodes were found in 'error' nor 'work' state, exiting holdback loop."| tee -a ${mylogfile}
        	break
    	fi
	done

	echo "Waiting for a five minute grace period prior to proceeding to join a node .."| tee -a ${mylogfile}
	sleep 300

	# check joinable node state END  

	# check if a node is down BEGIN
	# checking the cluster group info for potential down state nodes to avoid backend lock conflicts
	check_groupinfo_down="isi_group_info -h |egrep -iq down"

	# Function to check for the "down" string
 	# revise on whether to enable this check
	#check_for_down() {
	#    output=$($check_groupinfo_down)
	#    echo "$output" | grep -iq "down"  | tee -a ${mylogfile}
	#    return $?
	#}
	## Initial inspection of groupinfo
	#if check_for_down; then
	#    echo "Found a node on DOWN state, backing off and will recheck in 5min .." | tee -a ${mylogfile}
	#    while check_for_down; do
	#        echo "  Waiting.." | tee -a ${mylogfile}
	#        sleep 300  # Wait for 300 seconds
	#    done
	#    echo "All nodes now are in an UP state, proceeding .." | tee -a ${mylogfile}
	#else
	#    echo "Did not find any nodes in DOWN state, proceeding .." | tee -a ${mylogfile}
	#fi
  	## check if a node is down END

     # add nodes BEGIN
  		# extract the variables from the line
		newnodeserial=$(echo "$line" | awk '{print $1;}'| tr '[:lower:]' '[:upper:]')
		mydatestart=$(date)
		echo "Timestamp start: ${mydatestart}"| tee -a ${mylogfile}
		echo "Adding node:${newnodeserial}"| tee -a ${mylogfile}
		echo "Executing: isi devices node add --serial-number=${newnodeserial} --force"| tee -a ${mylogfile}
		isi devices node add --serial-number=${newnodeserial} --force

		#check and verify that the node has been successfully added to the cluster
		while ! checkstr=$(isi_nodes %{id} %{lnn} %{name} %{serialno}|egrep -q "${newnodeserial}"); do
		# If not present, wait for 900 seconds and check again
			mydatecheck=$(date)
			echo "Timestamp status-check: ${mydatecheck}"| tee -a ${mylogfile}
			sleep 900
		done
		
		echo "Added node: ${newnodeserial}"| tee -a ${mylogfile}
		addednodedetails=$(isi_nodes %{id} %{lnn} %{name} %{serialno}|egrep -i ${newnodeserial})
		echo "ID --- LNN --- NAME --- SERIAL"| tee -a ${mylogfile}
		echo ${addednodedetails}| tee -a ${mylogfile}

		myaddincr=$((myaddincr+1))
		echo "Added nodes: $myaddincr/${myaddcount}"| tee -a ${mylogfile}
		mydatecomplete=$(date)
		echo "Timestamp of completion: ${mydatecomplete}"| tee -a ${mylogfile}
		echo "-----"| tee -a ${mylogfile}

		#wait 5min as a grace period to avoid cluster activity conflict ..
		echo "Waiting for 5 minutes grace period before looping .."| tee -a ${mylogfile}
		sleep 300

		# If the string is present, continue with the next entry
	done < ${myaddablenodes} 

	echo "The following nodes have been added to the cluster:"	| tee -a ${mylogfile}
	isi_nodes NODENAME: %{name} SERIAL: %{serialno} LNN: %{lnn} ID: %{id} |egrep -i "`cat ${myaddablenodes} |xargs echo|sed 's/ /|/g'`"| tee -a ${mylogfile}
	echo "Total of added nodes: $myaddincr/${myaddcount}"| tee -a ${mylogfile}
	echo "Activity completed!"| tee -a ${mylogfile}
	exit 0
else
	echo "The file path is invalid!"| tee -a ${mylogfile}
	exit 1
fi
    	# add nodes END
	
}

##############################
# carve nodes function
##############################
carve_nodes() {



# reset var
mycarvecount=""
# defining paths
mycarvablenodes="${SCRIPT_PATH}/mgmt-nodes-carvable.txt"
mylogfile="${SCRIPT_PATH}/log-nodes-carved.txt"

# remove previously created log file and list of removable nodes 
rm -rf ${mylogfile}| tee -a ${mylogfile}
rm -rf ${mycarvablenodes}| tee -a ${mylogfile}


# Logging on which node the script is running
echo "Running on: $(hostname)" | tee -a ${mylogfile}

#Visual inspection of provided variable
user_carve_input="$1"
echo "Provided input: `echo ${user_carve_input}|sed 's/--carve-nodes-lnn=//g'`"| tee -a ${mylogfile}

# Clean up the user provided input prior to processing 
if echo "$user_carve_input"|sed 's/--carve-nodes-lnn=//g'| grep -qE '^[0-9,]+$'; then
	echo "Provided value is valid, continuing .."| tee -a ${mylogfile}
	echo "Current path:${SCRIPT_PATH}"| tee -a ${mylogfile}
	echo "Original node identifiers: $(echo $1 | sed 's/--carve-nodes-lnn=//g')"| tee -a ${mylogfile}
	echo "Modified node identifiers: $(echo $1 | sed 's/.*=//; s/,/ |/g')"| tee -a ${mylogfile}
	echo ""
	echo "Identified the following nodes .."| tee -a ${mylogfile}
	echo ""
	# list identified nodes to be carved

	carveidentifyloop="0"
	for node in $(echo "$1" | sed 's/.*=//; s/,/ /g'); do
		#loop count
		carveidentifyloop=$((carveidentifyloop + 1))
		#identify individual node details
		echo "Inventizing: ${carveidentifyloop}"		
		echo "To be carved Node-lnn: $node"| tee -a ${mylogfile}
		isi_nodes %{lnn} %{serialno}|egrep -i "^$node" >>  ${mycarvablenodes}
		echo "Node $node belongs to nodepool: `isi status --node=$node|egrep -i pools|awk '{print $NF}'`"| tee -a ${mylogfile}
		carvesrcpoolid="`isi status --node=$node|egrep -i pools|awk '{print $NF}'`"
		isi storagepool nodepools view ${carvesrcpoolid} |egrep -i Nodes:|sed -e 's/Nodes://g'|sed -e 's/,//g'|wc -w |awk '{print "Total number of nodes in the source nodepool:", $1;}'| tee -a ${mylogfile}
		#identify number of nodes in the pool the node bellongs to
		carvesrcpoolnodecount="`isi storagepool nodepools view ${carvesrcpoolid} |egrep -i Nodes:|sed -e 's/Nodes://g'|sed -e 's/,//g'|wc -w |awk '{print $1;}'`"
		#echo "Number of nodes in nodepool: ${carvesrcpoolnodecount}"
	done
	# quantify how many nodes would remain in the nodepool after carving out the given number of nodes
	carvedsrcpoolpost="$((${carvesrcpoolnodecount} - ${carveidentifyloop}))"
	echo "Number of nodes that would remain in the source nodepool: ${carvedsrcpoolpost}"| tee -a ${mylogfile}


# check that all provided node-lnn to be carved are from the same source nodepool
	if [ `cat ${mylogfile}|egrep -i "belongs to nodepool:"|awk '{print $NF}'|sort -uk 1,1|wc -l` -ge 2 ]; then
		echo ""
		echo "The provided node-lnns are sourced from more than a single common nodepool."| tee -a ${mylogfile}
		echo "This is currently not supported due to required additional sanity checks."| tee -a ${mylogfile}
		echo "Please carve manually!"| tee -a ${mylogfile}
		echo ""
		exit 1
	else
		echo ""
		echo "The provided node-lnns are sourced from a single common nodepool, proceeding .."| tee -a ${mylogfile}
		echo ""
	fi
	
	#verifying that the source nodepool is not a manually created nodepool
	# ${carvesrcpoolid}
	#
	echo "Checking nodepool creation mode for nodepool: ${carvesrcpoolid}"| tee -a ${mylogfile}
	
	mycarvenodepoolmode="`isi storagepool nodepools view ${carvesrcpoolid}|egrep -i manual|sed -e 's/Manual: //g'|awk '{print $1;}'`"
	echo "nodepool ${carvesrcpoolid} mode is: ${mycarvenodepoolmode} "| tee -a ${mylogfile}

	if [ "${mycarvenodepoolmode}" == "No" ] ; then
		echo "The nodepool creation mode is default, proceeding .."| tee -a ${mylogfile}	
	else
		echo "The source nodepool creation mode is manual. It is not possible to carve from a nodepool in manual mode, quiting!"| tee -a ${mylogfile}
		exit 1
	fi

	# interrupt if less than 3 nodes remain on the source nodepool
	if [ "${carvedsrcpoolpost}" -ge 3 ]; then
		echo ""
		echo "The minimum required number of nodes is retained on the source nodepool, proceeding .."| tee -a ${mylogfile}
	else
		echo ""
		echo "A minimum of three nodes is required to remain on the source nodepool, quiting!"| tee -a ${mylogfile}
	exit 1
	fi
	
	
	# count total number of nodes to be carved based on output
	mycarvecount="`cat ${mycarvablenodes} |wc -l|awk '{print $1;}'`"
	echo "Total number of nodes to be carved: ${mycarvecount}" | tee -a ${mylogfile}
	echo ""

	
	# check that a minimum of three nodes are selected
	if [ "${mycarvecount}" -ge 3 ]; then
		echo "The minimum required number of three nodes is addressed, proceeding .."| tee -a ${mylogfile}
		echo "Revising node details and carve order:"| tee -a ${mylogfile}
		cat  ${mycarvablenodes}| tee -a ${mylogfile}

		# USER ACKNOWLEDGE TO CONTINUE 
		echo "Your acknowledgement is required to proceed. Do you want to continue? (y/n)"| tee -a ${mylogfile}
		read user_ack
		if [ "$user_ack" != "y" ]; then
			echo "Quiting! No changes have been made."| tee -a ${mylogfile}
			exit 1
		fi
		echo "Proceeding..."| tee -a ${mylogfile}
		echo "The following nodes have been flagged for carving:"| tee -a ${mylogfile}
		cat ${mycarvablenodes} | tee -a ${mylogfile}

		if grep -q "true" "`isi_gconfig smartpools.diskpools.manually_manage_system_flags`" > /dev/null 2>&1; then
			echo "Manual override is set"
			# carve out the nodes to be removed
			mycarvedpool="CARVEDPOOL-`cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 3 | head -n 1`"

			echo "Revising current nodepools settings prior to carving:" | tee -a ${mylogfile}
			isi storagepool nodepools list --verbose | tee -a ${mylogfile}
			isi storagepool nodepools list | tee -a ${mylogfile}
			echo "Carving the defined nodes-lnn into a separate nodepool: ${mycarvedpool}" | tee -a ${mylogfile}
			echo "Executing: isi storagepool nodepools create ${mycarvedpool} --lnns=$(echo $1 | sed 's/--carve-nodes-lnn=//g') --verbose"
			isi storagepool nodepools create ${mycarvedpool} --lnns=$(echo $1 | sed 's/--carve-nodes-lnn=//g') --verbose | tee -a ${mylogfile}

			echo "Revising the nodepools settings post carving:" | tee -a ${mylogfile}
			isi storagepool nodepools list --verbose | tee -a ${mylogfile}
			isi storagepool nodepools list | tee -a ${mylogfile}

			echo "Carving process completed!"| tee -a ${mylogfile}
			echo "Run SmartPools to drain the data on the carved nodepool prior to Smartfailing the nodes."| tee -a ${mylogfile}
			echo "You can run this script again and provide the nodes-lnn to execute smartfail activity in sequence."| tee -a ${mylogfile}
			mydatecomplete=$(date)
			echo "Timestamp of carving process completion: ${mydatecomplete}"| tee -a ${mylogfile}
			echo "-----"| tee -a ${mylogfile}					
		else
			echo "Manual override is required to proceed"
			# enabling manual configuration of nodepools
			echo "Enabling manual configuration of the nodepools.." | tee -a ${mylogfile}
			isi_gconfig smartpools.diskpools.manually_manage_system_flags=true| tee -a ${mylogfile}
		
			# carve out the nodes to be removed
			mycarvedpool="CARVEDPOOL-`cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 3 | head -n 1`"

			echo "Revising current nodepools settings prior to carving:" | tee -a ${mylogfile}
			isi storagepool nodepools list --verbose | tee -a ${mylogfile}
			isi storagepool nodepools list | tee -a ${mylogfile}

			echo "Carving the defined nodes-lnn into a separate nodepool: ${mycarvedpool}" | tee -a ${mylogfile}
			echo "executing: isi storagepool nodepools create ${mycarvedpool} --lnns=$(echo $1 | sed 's/--carve-nodes-lnn=//g') --verbose"
			isi storagepool nodepools create ${mycarvedpool} --lnns=$(echo $1 | sed 's/--carve-nodes-lnn=//g') --verbose | tee -a ${mylogfile}

			echo "Revising the nodepools settings post carving:" | tee -a ${mylogfile}
			isi storagepool nodepools list --verbose | tee -a ${mylogfile}
			isi storagepool nodepools list | tee -a ${mylogfile}

			echo "Disabling manual configuration of the nodepools.." | tee -a ${mylogfile}
			isi_gconfig smartpools.diskpools.manually_manage_system_flags=false| tee -a ${mylogfile}

			echo "Carving process completed!"| tee -a ${mylogfile}
			echo "Run SmartPools to drain the data on the carved nodepool prior to Smartfailing the nodes."| tee -a ${mylogfile}
			echo "You can run this script again and provide the nodes-lnn to execute smartfail activity in sequence."| tee -a ${mylogfile}
			mydatecomplete=$(date)
			echo "Timestamp of carving process completion: ${mydatecomplete}"| tee -a ${mylogfile}
			echo "-----"| tee -a ${mylogfile}
		fi

		echo "Activity completed!"| tee -a ${mylogfile}
		exit 0

	else
		echo "A minimum of three nodes is required for this action!"| tee -a ${mylogfile}
		exit 0
fi

else
    echo "Input string is not valid, quiting!"| tee -a ${mylogfile}
	exit 1
fi

}

##############################
# list node neighborhoods
##############################
list_neighborhoods () {

echo ""

python3 << EOF
import isi.smartpools.diskpools as spdp

dpcfg = spdp.open_config()
diskpool_db = dpcfg._get_db()
neighborhoods = dpcfg.provisioner.cluster.neighborhoods
print("Found the following", len(neighborhoods), "neighborhoods: ")
print("The neighborhoods consist of the following DEVICEID:")
for neighborhood in neighborhoods:
    print(neighborhood.contents)
EOF

echo ""
isi_nodes DEVICEID: %{devid} LNN: %{lnn} SERIAL: %{serialno}
echo ""
echo "The Node ID in the storagepool output is the LNN ID!"
isi storagepool list
echo ""

}


##############################
# Initialize variables
##############################
remove_nodes=false
add_nodes=false
carve_nodes=false
list_neighborhoods=false
remove_nodes_lnn=""
add_nodes_serials=""


##############################
# Parse command line arguments
##############################
while [ $# -gt 0 ]; do
    case "$1" in

        --remove-nodes-lnn=*)
            if $add_nodes || $remove_nodes || $carve_nodes || $list_neighborhoods; then
                echo "Error: only one option can be specified at a time"
                usage
                exit 1
            fi
            remove_nodes=true
            remove_nodes_lnn="$1"
            ;;

        --add-nodes-serials=*)
            if $add_nodes || $remove_nodes || $carve_nodes || $list_neighborhoods; then
                echo "Error: only one option can be specified at a time"
                usage
                exit 1
            fi
            add_nodes=true
            add_nodes_serials="$1"
            ;;

        --carve-nodes-lnn=*)
            if $add_nodes || $remove_nodes || $carve_nodes || $list_neighborhoods; then
                echo "Error: only one option can be specified at a time"
                usage
                exit 1
            fi
            carve_nodes=true
            carve_nodes_lnn="$1"
            ;;

        --list-node-neighborhoods)
            if $add_nodes || $remove_nodes || $carve_nodes || $list_neighborhoods; then
                echo "Error: only one option can be specified at a time"
                usage
                exit 1
            fi
            list_neighborhoods=true
            list_node_neighborhoods="$1"
            ;;

 


		--help)
            usage
            exit 0
            ;;
        *)
            usage
            exit 1
            ;;
    esac
    shift
done



# Execute actions based on command line arguments
if $remove_nodes; then
    remove_nodes "$remove_nodes_lnn"
fi

if $add_nodes; then
    add_nodes "$add_nodes_serials"
fi

if $carve_nodes; then
    carve_nodes "$carve_nodes_lnn"
fi

if $list_neighborhoods; then
    list_neighborhoods "$list_node_neighborhoods"
fi


if ! $remove_nodes && ! $add_nodes  && ! $carve_nodes && ! $list_neighborhoods ; then
    usage
    exit 1
fi
