#!/bin/bash

# Trap SIGINT and call ctrl_c
trap ctrl_c INT

# Globals
ES_HOST=""
ES_PWD=""
CERTS_PATH=""

# Banner
function banner() {
	echo $'
:::            :::     ::::::::: :::   ::: :::::::::   :::::::: ::::::::::: 
:+:          :+: :+:        :+:  :+:   :+: :+:    :+: :+:    :+:    :+:     
+:+         +:+   +:+      +:+    +:+ +:+  +:+    +:+ +:+    +:+    +:+     
+#+        +#++:++#++:    +#+      +#++:   +#++:++#+  +#+    +:+    +#+     
+#+        +#+     +#+   +#+        +#+    +#+        +#+    +#+    +#+     
#+#        #+#     #+#  #+#         #+#    #+#        #+#    #+#    #+#     
########## ###     ### #########    ###    ###         ########     ###     

~ You\'ve just entered the sweetest trap—no bees, just data! \U1F36F
	'
}

# Stop lazypot on ctrl+c
function ctrl_c() {
	echo -e "\033[34m[*]\033[0m Stopping containers ..."
	docker compose -f docker-compose-lazypot.yml down	
	verbose "Stopping filebeat ... "
	systemctl stop filebeat
	itsok $?
	verbose "Deleting 'filebeat_write' role ... "
	curl -skX DELETE -u "elastic:${ES_PWD}" "https://${ES_HOST}/_security/role/filebeat_writer" | grep -q 'true'
	itsok $?
	verbose "Deleting 'filebeat' user ... "
	curl -skX DELETE -u "elastic:${ES_PWD}" "https://${ES_HOST}/_security/user/filebeat" | grep -q 'true'	
	itsok $?
	verbose "Stopping auditbeat ... "
	systemctl stop auditbeat
	itsok $?
	verbose "Deleting 'auditbeat_setup' role ... "
	curl -skX DELETE -u "elastic:${ES_PWD}" "https://${ES_HOST}/_security/role/auditbeat_setup" | grep -q 'true'
	itsok $?
	verbose "Deleting 'auditbeat' user ... "
	curl -skX DELETE -u "elastic:${ES_PWD}" "https://${ES_HOST}/_security/user/auditbeat" | grep -q 'true'	
	itsok $?
	
	rm -rf /etc/elasticsearch "${PWD}/suricata"

	echo -e "\033[34m[*]\033[0m Lazypot undeployed"
	exit
}

# Success or failure messages
function itsok() {
	if [[ $1 -eq 0 ]];then
		echo -e "\033[32m✓\033[0m"
	else
		echo -e "\033[31m✖\033[0m"
		exit 1
	fi
}

# Verbose syntax
function verbose() {
	echo -en "\033[34m[*]\033[0m $1"
}

# Check if deependencies are intalled
function deps(){
	# Install docker
	if ! docker version &>/dev/null;then
		verbose "Installing docker ... "
  
		# Uninstall conflicting packages
		for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do apt-get remove -yq "${pkg}" &>/dev/null; done 

		# Update apt and install prerequisites
		apt-get update -yq &>/dev/null
		apt-get install -yq ca-certificates curl &>/dev/null

		# Set up Docker's official GPG key
		install -m 0755 -d /etc/apt/keyrings &>/dev/null
		curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc &>/dev/null
		chmod a+r /etc/apt/keyrings/docker.asc

		# Add Docker repository to apt sources
		echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "${VERSION_CODENAME}") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

		# Update apt again to include Docker's repo
		apt-get update -yq &>/dev/null

		# Install Docker Engine, CLI, containerd, and Docker Compose plugin
		apt-get install -yq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin &>/dev/null

		# Verify the installation
		docker run hello-world &>/dev/null
		itsok $?
	fi
	
	# Install filebeat
	if ! filebeat version &>/dev/null;then 
		verbose "Installing filebeat ... "
		curl -sLO https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.15.3-amd64.deb
		dpkg --force-confnew -i filebeat-8.15.3-amd64.deb &>/dev/null
		filebeat version &>/dev/null
		itsok $?
		rm -f filebeat-8.15.3-amd64.deb
	fi
 
	# Install auditbeat
	if ! auditbeat version &>/dev/null;then 
		verbose "Installing auditbeat ... "
		curl -sLO https://artifacts.elastic.co/downloads/beats/auditbeat/auditbeat-8.15.3-amd64.deb
		dpkg --force-confnew -i auditbeat-8.15.3-amd64.deb &>/dev/null
		auditbeat version &>/dev/null
		itsok $?
		rm -f auditbeat-8.15.3-amd64.deb
	fi

 	# Install jq
	if ! jq -V &>/dev/null;then
		verbose "Installing jq ... "
		apt-get install -y jq &>/dev/null
		jq -V &>/dev/null
		itsok $?
	fi
}

# Configure suricata to be an IDS
function configure-suricata() {
	# Download and create suricata cofiguration directory structure (https://docs.suricata.io/en/latest/quickstart.html#basic-setup)
	mkdir -p suricata/{config,logs,rules}
	wget 'https://raw.githubusercontent.com/OISF/suricata/refs/tags/suricata-6.0.0/suricata.yaml.in' -qO suricata/config/suricata.yaml
	wget 'https://raw.githubusercontent.com/OISF/suricata/refs/heads/master/etc/reference.config' -qO suricata/config/reference.config
	wget -qO suricata/config/threshold.config https://raw.githubusercontent.com/OISF/suricata/refs/heads/master/threshold.config

	# Setting suricata as IDS
	sed -i 's/@e_logdir@/\/var\/log\/suricata/' suricata/config/suricata.yaml
	sed -i 's/@e_enable_evelog@/yes/' suricata/config/suricata.yaml
	sed -i 's/@e_defaultruledir@/\/var\/lib\/suricata\/rules/' suricata/config/suricata.yaml
	sed -i 's|classification-file: @e_sysconfdir@|classification-file: \/var\/lib\/suricata\/rules\/|' suricata/config/suricata.yaml
	sed -i 's/@e_sysconfdir@/\/etc\/suricata\//' suricata/config/suricata.yaml
	sed -i 's/@e_magic_file_comment/#@e_magic_file_comment/' suricata/config/suricata.yaml
	sed -i 's/#use-mmap: yes/use-mmap: yes/' suricata/config/suricata.yaml
	sed -i 's/#mmap-locked: yes/mmap-locked: yes/' suricata/config/suricata.yaml
	sed -i 's/- alert:/- alert:\n            enabled: yes/' suricata/config/suricata.yaml
	sed -i 's/# payload: yes/payload: yes/' suricata/config/suricata.yaml
	sed -i 's/# metadata: no/metadata: yes/' suricata/config/suricata.yaml
	sed -i 's/# payload-printable: yes/payload-printable: yes/' suricata/config/suricata.yaml
	sed -i 's/# http-body: yes/http-body: yes/' suricata/config/suricata.yaml
	sed -i 's/ikev2/ike/g' suricata/config/suricata.yaml
}

# Configure filebeat to send Suricata logs to Elasticsearch
function filebeat-start() {
	# https://www.elastic.co/guide/en/beats/filebeat/8.15/keystore.html
	# https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-installation-configuration.html	
	verbose "Configuring filebeat ... "
	filebeat keystore create --force &>/dev/null
	echo "${ES_PWD}" | filebeat keystore add FB_PWD --stdin --force &>/dev/null
	
	# Configuring connection to Elasticsearch and Kibana
	wget -qO /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/elastic/beats/refs/heads/main/filebeat/filebeat.yml
	sed -i "s|localhost:9200|https:\/\/${ES_HOST}|" /etc/filebeat/filebeat.yml
	sed -i 's|#protocol: "https"|\#protocol: "https"\n  ssl:\n    enabled: true\n    certificate_authorities: ["/etc/elasticsearch/certs/ca/ca.crt"]\n    certificate: "/etc/elasticsearch/certs/client/es01.crt"\n    key: "/etc/elasticsearch/certs/client/es01.key"|' /etc/filebeat/filebeat.yml
	sed -i "s/#username: \"elastic\"/username: \"elastic\"/;s/#password: \"changeme\"/password: \"\${FB_PWD}\"/" /etc/filebeat/filebeat.yml
	sed -i "s|#host: \"localhost:5601\"|host: \"${ES_HOST%:9200}:5601\"\n  username: \"elastic\"\n  password: \"\${FB_PWD}\"|" /etc/filebeat/filebeat.yml
	sed -i 's/reload.enabled: false/reload.enabled: true/' /etc/filebeat/filebeat.yml
	sed -i 's/#reload.period: 10s/reload.period: 1m/' /etc/filebeat/filebeat.yml

	# Configuring suricata module
	wget -qO /etc/filebeat/modules.d/suricata.yml.disabled https://raw.githubusercontent.com/elastic/beats/efbc4ff65c231a9c9c7256c3f41f94bae1989991/x-pack/filebeat/modules.d/suricata.yml.disabled
	filebeat modules enable suricata &>/dev/null
	sed -i 's/false/true/' /etc/filebeat/modules.d/suricata.yml
	sed -i "s|#var.paths:|var.paths: [\"${PWD}/suricata/logs/eve.json\"]|g" /etc/filebeat/modules.d/suricata.yml
	
	# Testing config and connection
	CONF=$(filebeat test config)
	OUT=$(filebeat test output | grep -oP 'talk to server... \K.*')
	if [[ ${OUT} != "OK" || ${CONF} != "Config OK" ]];then
		itsok 1
	else
		itsok 0
	fi

	# Setup filebeat
	verbose "Setting up filebeat ... "
	filebeat setup &>/dev/null
	itsok $?
	
	# https://www.elastic.co/guide/en/beats/filebeat/current/privileges-to-publish-events.html
	verbose "Creating 'filebeat_writer' role in Elasticsearch ... "
	curl -skX POST -u "elastic:${ES_PWD}" "https://${ES_HOST}/_security/role/filebeat_writer" -H "Content-Type: application/json" -d '{ "cluster": ["monitor","read_ilm", "read_pipeline"], "indices": [ { "names": [ "filebeat-*" ], "privileges": ["create_doc","auto_configure"] } ] }' &>/dev/null
	curl -sku "elastic:${ES_PWD}" "https://${ES_HOST}/_security/role/filebeat_writer" | grep -q 'filebeat_writer'
	itsok $?

	# Create user 'filebeat' with 'filebeat_write' role to manage filebeat
	verbose "Creating 'filebeat' user in Elasticsearch ... "
	FB_PWD=$(head /dev/urandom | md5sum | awk '{print $1}')
	echo -n "${FB_PWD}" | filebeat keystore add FB_PWD --stdin --force &>/dev/null
	sed -i 's/username: "elastic"/username: "filebeat"/' /etc/filebeat/filebeat.yml
	curl -skX POST -u "elastic:${ES_PWD}" "https://${ES_HOST}/_security/user/filebeat" -H "Content-Type: application/json" -d "{\"password\" : \"${FB_PWD}\", \"roles\" : [ \"filebeat_writer\" ], \"full_name\" : \"Filebeat Suricata User\"}" &>/dev/null
	curl -sku "elastic:${ES_PWD}" "https://${ES_HOST}/_security/user/filebeat" | grep -q filebeat
	itsok $?

	# Restart filebeat service
	verbose "Starting filebeat ... "
	systemctl start filebeat && systemctl -q is-active filebeat
	itsok $?
	systemctl enable filebeat &>/dev/null
}

# Configure auditbeat to send auditd events to Elasticsearch
function auditbeat-start() {
	# https://www.elastic.co/guide/en/beats/auditbeat/current/auditbeat-installation-configuration.html
	verbose "Configuring auditbeat ... "
	auditbeat keystore create --force &>/dev/null
	echo "${ES_PWD}" | auditbeat keystore add FB_PWD --stdin --force &>/dev/null
	
	# Configuring connection to Elasticsearch and Kibana
	wget -qO /etc/auditbeat/auditbeat.yml https://raw.githubusercontent.com/elastic/beats/refs/heads/main/auditbeat/auditbeat.reference.yml
	sed -i 's/#enabled: true/enabled: true/1' /etc/auditbeat/auditbeat.yml 
	sed -i "s|localhost:9200|https:\/\/${ES_HOST}|" /etc/auditbeat/auditbeat.yml
	sed -i 's|#protocol: "https"|\#protocol: "https"\n  ssl:\n    enabled: true\n    certificate_authorities: ["/etc/elasticsearch/certs/ca/ca.crt"]\n    certificate: "/etc/elasticsearch/certs/client/es01.crt"\n    key: "/etc/elasticsearch/certs/client/es01.key"|' /etc/auditbeat/auditbeat.yml
	sed -i "s/#username: \"elastic\"/username: \"elastic\"/;s/#password: \"changeme\"/password: \"\${FB_PWD}\"/" /etc/auditbeat/auditbeat.yml
	sed -i "s|#host: \"localhost:5601\"|host: \"${ES_HOST%:9200}:5601\"\n  username: \"elastic\"\n  password: \"\${FB_PWD}\"|" /etc/auditbeat/auditbeat.yml	

 	# Configure auditbeat to check for events in the nginx_server filesystem
 	DIR=$(docker container inspect nginx_server | jq -r '.[].GraphDriver.Data.MergedDir')
	sed -i "s|- /bin|- ${DIR}/home|" /etc/auditbeat/auditbeat.yml
	sed -i "s|- /etc|- ${DIR}/etc|" /etc/auditbeat/auditbeat.yml
	sed -i "s|- /usr/bin|#- /usr/bin|" /etc/auditbeat/auditbeat.yml
	sed -i "s|- /sbin|#- /sbin|" /etc/auditbeat/auditbeat.yml
	sed -i "s|- /usr/sbin|#- /usr/sbin|" /etc/auditbeat/auditbeat.yml
	sed -i "s|- '~$'|\#- '~\$'|" /etc/auditbeat/auditbeat.yml
	sed -i 's/reload.enabled: false/reload.enabled: true/' /etc/auditbeat/auditbeat.yml
	sed -i 's/reload.period: 10s/reload.period: 1m/' /etc/auditbeat/auditbeat.yml
	sed -i 's/include_raw_message: false/include_raw_message: true/' /etc/auditbeat/auditbeat.yml

	# Testing config and connection
	CONF=$(auditbeat test config)
	OUT=$(auditbeat test output | grep -oP 'talk to server... \K.*')
	if [[ ${OUT} != "OK" || ${CONF} != "Config OK" ]];then
		itsok 1
	else
		itsok 0
	fi

	# Setup auditbeat
	verbose "Setting up auditbeat ... "
	auditbeat setup &>/dev/null
	itsok $?
	
	# https://www.elastic.co/guide/en/beats/auditbeat/current/privileges-to-setup-beats.html
	verbose "Creating 'auditbeat_setup' role in Elasticsearch ... "
	curl -skX POST -u "elastic:${ES_PWD}" "https://${ES_HOST}/_security/role/auditbeat_setup" -H "Content-Type: application/json" -d '{ "cluster": ["monitor","manage_ilm"], "indices": [ { "names": [ "auditbeat-*" ], "privileges": ["create_doc","auto_configure"] } ] }' &>/dev/null
	curl -sku "elastic:${ES_PWD}" "https://${ES_HOST}/_security/role/auditbeat_setup" | grep -q 'auditbeat_setup'
	itsok $?

	# Create user 'auditbeat' with 'auditbeat_setup' role to manage auditbeat
	verbose "Creating 'auditbeat' user in Elasticsearch ... "
	FB_PWD=$(head /dev/urandom | md5sum | awk '{print $1}')
	echo -n "${FB_PWD}" | auditbeat keystore add FB_PWD --stdin --force &>/dev/null
	sed -i 's/username: "elastic"/username: "auditbeat"/' /etc/auditbeat/auditbeat.yml
	curl -skX POST -u "elastic:${ES_PWD}" "https://${ES_HOST}/_security/user/auditbeat" -H "Content-Type: application/json" -d "{\"password\" : \"${FB_PWD}\", \"roles\" : [ \"auditbeat_setup\",\"kibana_admin\",\"ingest_admin\" ], \"full_name\" : \"Auditbeat User\"}" &>/dev/null
	curl -sku "elastic:${ES_PWD}" "https://${ES_HOST}/_security/user/auditbeat" | grep -q auditbeat
	itsok $?

	# Restart auditbeat service
	verbose "Starting auditbeat ... "
	systemctl start auditbeat && systemctl -q is-active auditbeat
	itsok $?
	systemctl enable auditbeat &>/dev/null
}

# Show suricata events after deployment
function suricata-log() {
	echo -e "\033[34m[*]\033[0m Showing Suricata logs ... "
	tail -f suricata/logs/eve.json | grep 'in_iface'
}

# Check for root privileges
function amiroot() {
	verbose "Checking root privileges ... "
	if [[ "${UID}" ]];then
		itsok 0
	else
		itsok 1
	fi
}

# Deploy lazybot
function main(){ 
	banner
	amiroot

	echo -e "\033[34m[*]\033[0m Deploying Lazypot ... "
	
	deps
	configure-suricata
	
	# Start containers
	echo -e "\033[34m[*]\033[0m Starting containers ... "
	docker compose -f docker-compose-lazypot.yml up -d 
	for c in nginx_server suricata; do
		test=$(sudo docker ps -q -f "name=^${c}\$")
		if [[ -z ${test} ]];then
			verbose "Container ${c} ... "
			itsok 1
		fi
	done

	# Input data to connect to Elasticsearch
	echo -en "\033[34m[*]\033[0m Type the host and port of Elasticsearch in the format HOST:PORT (Ex. 127.0.0.1:9200): " 
	read -r ES_HOST
	echo -en "\033[34m[*]\033[0m Type the password of 'elastic' user: " 
	read -rs ES_PWD
	echo
	echo -ne "\033[34m[*]\033[0m Type path to compressed file with PEM Certificates (/path/to/certs.tar.gz): "
	read -r CERTS_PATH

	# Create Elasticsearch Storage structure
	mkdir -p /etc/elasticsearch/certs/{ca,client}
	tar xzf "${CERTS_PATH}"
	find usr/share/elasticsearch/config/certs -type f -name 'es01*' -exec mv {} /etc/elasticsearch/certs/client \;
	mv usr/share/elasticsearch/config/certs/ca/ca.crt /etc/elasticsearch/certs/ca
	rm -rf usr/

	filebeat-start
	auditbeat-start
	suricata-log
}

main
