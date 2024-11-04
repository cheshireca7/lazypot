# lazypot

<p align="center">
  <img src="https://github.com/cheshireca7/lazypot/blob/main/lazypot.png?raw=true" alt="lazypot"/>
</p>

## Process to deploy ELK Stack in the monitoring server
1. Set vx.max_map_count according to Elasticsearch [docs](https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html#_set_vm_max_map_count_to_at_least_262144)
```bash
sudo sysctl -w vm.max_map_count=262144
```
2. Set the variables in `.env` file
3. Use `docker-compose-elasticstack.yml` to deploy the Elasticsearch + Kibana in the monitoring server
```bash
sudo docker compose -f docker-compose-elasticstack.yml up -d
```
4. Download the CA certificate, and Elasticsearch PEM certificate and key
```bash
sudo docker exec es01 tar cvzf /tmp/certs.tar.gz /usr/share/elasticsearch/config/certs/ca/ca.crt /usr/share/elasticsearch/config/certs/es01/es01.crt /usr/share/elasticsearch/config/certs/es01/es01.key
sudo docker cp es01:/tmp/certs.tar.gz .
sudo docker exec es01 rm -f /tmp/certs.tar.gz
```
## Process to deploy Lazypot in the public server
5. Download `Dockerfile`, `docker-compose-lazypot.yml`, `nginx`, `startup.sh` and `run.sh`
6. Upload `certs.tar.gz`
7. Use the `run.sh` Bash script to run suricata + nginx + filebeat + auditbeat:
```bash
chmod +x ./run.sh
chmod +x ./startup.sh
sudo ./run.sh
```
8. Follow interactive configuration:
> If setting up filebeat fails, may be due to Elasticsearch not fully deployed, wait a few minutes and run `run.sh` again

<p align="center">
  <img src="https://github.com/cheshireca7/lazypot/blob/main/run.png?raw=true alt="run"/>
</p>

9. Log in to Kibana to see Suricata logs uploaded to Elasticsearch
