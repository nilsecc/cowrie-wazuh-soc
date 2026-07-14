# Wazuh SOC

## 1. Wazuh Installation

Install Docker

```bash
sudo pacman -S docker docker-compose
```

Enable and start Docker service

```bash
sudo systemctl enable --now docker
```

Add your user to the docker group (no sudo needed). Log out and back in for the group change to take effect.

```bash
sudo usermod -aG docker $USER
```

Clone the official Wazuh Docker repository

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.2
cd wazuh-docker/single-node
```

Generate SSL/TLS certificates (required for internal component communication)

```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```

Start Wazuh (downloads images and starts all containers)

```bash
docker compose up -d
```

Verify all 3 containers are running

```bash
docker ps
```

Expected containers after installation:

| Container | . |
|---|---|
| `wazuh/wazuh-manager` | Receives and analyzes logs, generates alerts |
| `wazuh/wazuh-indexer` | Stores logs and alerts (OpenSearch inside) |
| `wazuh/wazuh-dashboard` | Web interface (Kibana-like) |

## 2. Dashboard Access

Open your browser at `https://localhost` and accept the self-signed certificate warning.

Default credentials admin:SecretPassword

## 3. Connecting the Raspberry Pi

Download the wazuh agent

```bash
nilsecc@raspberrypi:~$ curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.2-1_arm64.deb
```

Install and point the manager to the IP of your computer (the one with wazuh running)

```bash
sudo WAZUH_MANAGER='YOUR-IP' dpkg -i wazuh-agent.deb
nilsecc@raspberrypi:~$ sudo systemctl enable --now wazuh-agent
```

Check Wazuh Dashboard -> Server Management -> Endpoint Summary for the Raspberry Pi agent.

Add this block to indicate the location of the logs and the format:

```bash
sudo TERM=xterm nano /var/ossec/etc/ossec.conf
```

I use **TERM=xterm** because the container doesn't have installed nano or vi.

```xml
<localfile>
   <log_format>json</log_format>
   <location>/home/cowrie/cowrie/var/log/cowrie/cowrie.json</location>
</localfile>
```

Save and restart the agent

```bash
sudo systemctl restart wazuh-agent
```

## 4. Enable Archives Index

By default wazuh only indexes events that fire a rule (`wazuh-alerts-*`). Archives = also index raw events with no rule yet.

```bash
docker exec -it single-node-wazuh.manager-1 bash
sed -i '/archives:/{n;s/enabled: false/enabled: true/}' /etc/filebeat/filebeat.yml
systemctl restart filebeat
```

Creates index `wazuh-archives-4.x-*`. View it in Discover, index pattern `wazuh-archives-*`.

## 5. Custom Rules for Cowrie

`/var/ossec/etc` is a named volume, container has no editor (no nano/vi as I said before). Workflow: edit on host, `docker cp` in, `chown`, restart.

```bash
nano ~/local_rules.xml
docker cp ~/local_rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 chmod 640 /var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

Cowrie logs are JSON, wazuh's built-in json decoder handles them, no custom decoder needed. Just rules matching on field `eventid`.

```xml
<group name="cowrie,">
  <!-- Father rule -->
  <rule id="100000" level="0">
    <decoded_as>json</decoded_as>
    <field name="eventid">cowrie\.</field>
    <description>Event detected in Cowrie (honeypot)</description>
  </rule>
  <!-- Login successful -->
  <!-- The honeypot accepts a large list of credentials, so logging in it's not an important event, but we will follow wazuh standards -->
  <rule id="100001" level="8">
    <if_sid>100000</if_sid>
    <field name="eventid">^cowrie.login.success$</field>
    <mitre>
      <id>T1078</id>
    </mitre>
    <description>login from $(src_ip) with username:$(username) and password:$(password)</description>
  </rule>
  <!-- Login failed -->
  <rule id="100002" level="5">
    <if_sid>100000</if_sid>
    <field name="eventid">^cowrie.login.failed$</field>
    <description>login from $(src_ip) with username:$(username) and password:$(password)</description>
  </rule>
  <!-- Command input -->
  <rule id="100003" level="7">
    <if_sid>100000</if_sid>
    <field name="eventid">^cowrie.command.input$</field>
    <description>command executed from $(src_ip): $(input)</description>
    <mitre>
      <id>T1059</id>
    </mitre>
  </rule>
  <!-- File upload -->
  <rule id="100004" level="11">
    <if_sid>100000</if_sid>
    <field name="eventid">^cowrie.session.file_upload$</field>
    <description>file uploaded from $(src_ip) with filename:$(outfile)</description>
  </rule>
  <!-- File download -->
  <rule id="100005" level="10">
    <if_sid>100000</if_sid>
    <field name="eventid">^cowrie.session.file_download$</field>
    <description>file downloaded from $(src_ip) with url:$(url)</description>
    <mitre>
      <id>T1105</id>
    </mitre>
  </rule>
  <!-- Direct TCP/IP request -->
  <rule id="100006" level="12">
    <if_sid>100000</if_sid>
    <field name="eventid">^cowrie.direct-tcpip.request$</field>
    <description>TCP tunneling attempt from $(src_ip) to $(dst_ip):$(dst_port)</description>
    <mitre>
      <id>T1090</id>
    </mitre>
  </rule>

  <!-- Correlation rule: brute force -->
  <!-- brute force attacks can be scripted to wait a few seconds between each try -->
  <!-- don't take correlation rules as true, thresholds are estimates -->
  <rule id="100010" level="10" frequency="6" timeframe="60">
    <if_matched_sid>100002</if_matched_sid>
    <same_field>src_ip</same_field>
    <description>Brute force attack from $(src_ip): 6 failed logins in 60s</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
  <!-- Correlation rule: possible automated command sequence -->
  <!-- weak signal: most sessions in a honeypot run scripted commands right after login anyway -->
  <rule id="100011" level="10" frequency="5" timeframe="10">
    <if_matched_sid>100003</if_matched_sid>
    <same_field>src_ip</same_field>
    <description>Possible automated command sequence from $(src_ip): 5+ commands in 10s</description>
    <mitre>
      <id>T1059</id>
    </mitre>
  </rule>
</group>
```

Test rules against a real log line.

```bash
docker exec -it single-node-wazuh.manager-1 bash
/var/ossec/bin/wazuh-logtest
```

## 6. GeoIP (Attacker IP Location)

`GeoLocation.*` fields exist in wazuh's default mapping but are empty until an ingest pipeline fills them in.

### 6.1 Get GeoLite2 DB

Generate license key: https://www.maxmind.com/en/geolite2/signup -> Manage License Keys.

```bash
curl -L -o GeoLite2-City.tar.gz "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_KEY&suffix=tar.gz"
tar -xzf GeoLite2-City.tar.gz
ls GeoLite2-City_*/
# -> GeoLite2-City.mmdb
```

### 6.2 Copy into Indexer Container

```bash
docker cp GeoLite2-City_*/GeoLite2-City.mmdb single-node-wazuh.indexer-1:/usr/share/wazuh-indexer/GeoLite2-City.mmdb
```

### 6.3 Create Ingest Pipeline

```bash
curl -k -u admin:SecretPassword -X PUT "https://localhost:9200/_ingest/pipeline/geoip" \
  -H 'Content-Type: application/json' \
  -d '{
    "description": "geolocate data.src_ip",
    "processors": [
      { "geoip": {
          "field": "data.src_ip",
          "target_field": "GeoLocation",
          "database_file": "GeoLite2-City.mmdb",
          "ignore_missing": true
      }}
    ]
  }'
```

### 6.4 Set Pipeline as Default on the Index Template

```bash
curl -k -u admin:SecretPassword -X PUT "https://localhost:9200/_index_template/wazuh" \
  -H 'Content-Type: application/json' \
  -d '{
    "index_patterns": ["wazuh-alerts-4.x-*"],
    "template": {
      "settings": {
        "index.default_pipeline": "geoip"
      }
    },
    "priority": 500
  }'
```

Only applies to new indices. For existing ones, backfill:

```bash
curl -k -u admin:SecretPassword -X PUT "https://localhost:9200/wazuh-alerts-4.x-*,wazuh-archives-4.x-*/_settings" \
  -H 'Content-Type: application/json' -d '{"index.default_pipeline": "geoip"}'

curl -k -u admin:SecretPassword -X POST \
  "https://localhost:9200/wazuh-alerts-4.x-*,wazuh-archives-4.x-*/_update_by_query?pipeline=geoip&conflicts=proceed" \
  -H 'Content-Type: application/json' -d '{"query": {"match_all": {}}}'
```

### 6.5 Verify

```bash
curl -k -u admin:SecretPassword "https://localhost:9200/wazuh-archives-4.x-YYYY.MM.DD/_search?size=1" \
  -H 'Content-Type: application/json' \
  -d '{"query": {"match": {"rule.groups": "cowrie"}}, "_source": ["GeoLocation"]}' | jq '.hits.hits[0]._source'
```

## 7. Dashboard

Index pattern: `wazuh-alerts-*`, base filter: `rule.groups: "cowrie"`.

| Visualization | Type | Bucket / Field |
|---|---|---|
| Cowrie - Top IPs | Bar chart | Terms on `data.src_ip`, size 10 |
| Cowrie - Top Usernames | Bar chart | Terms on `data.username`, size 10 (extra filter: `data.eventid: cowrie.login.failed OR cowrie.login.success`) |
| Cowrie - Top Passwords | Bar chart | Terms on `data.password`, size 10 (same filter) |
| Cowrie - Map | Region map | see below |

`GeoLocation.country_iso_code` becomes fully searchable and aggregatable once the index field list is refreshed in OpenSearch. However, we create a scripted field called `country_code_kw` to ensure a clean visual format in the Dashboard, rendering a dash ("-") safely whenever an alert lacks geo-location data.

Stack Management -> Index Patterns -> `wazuh-alerts-*` -> Scripted fields -> Add. 
Name: `country_code_kw`, Type: `string`, Language: `painless`.

```Java
if (doc.containsKey('GeoLocation.country_iso_code') && !doc['GeoLocation.country_iso_code'].empty) {
    return doc['GeoLocation.country_iso_code'].value;
}
return "-";
```

Region map config:

| Setting | Value |
|---|---|
| Vector map | World Countries |
| Join field | ISO 3166-1 alpha-2 Code |
| Shape field | Terms on `country_code_kw` (the scripted field, not the raw one) |

All 4 panels grouped into dashboard: **Cowrie Honeypot - Overview**.

## 8. IoC enrichment

We will do a Python script to search for login and file upload alerts and search the IP in AbuseIPDB and the hash of uploaded files to inject it to wazuh and send the info to a telegram bot

First we will change our ossec.conf

```bash
docker cp single-node-wazuh.manager-1:/var/ossec/etc/ossec.conf ./ossec.conf.bak
```

Add this at the end of the file:

``` bash
<ossec_config>
  <integration>
    <name>custom-abuseipdb.py</name>
    <rule_id>100001</rule_id>
    <alert_format>json</alert_format>
  </integration>

  <integration>
    <name>custom-vt-hash.py</name>
    <rule_id>100004</rule_id>
    <alert_format>json</alert_format>
  </integration>

</ossec_config>
```

Apply changes to single-node-wazuh.manager:

```bash
docker cp ./ossec.conf.bak single-node-wazuh.manager-1:/var/ossec/etc/ossec.conf
docker exec -it single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/ossec.conf
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

Now lets create the **custom-abuseipdb.py** script. You can copy the script in **/scripts** in my github repo. Remember putting the AbuseIPDB and Telegram tokens inside the python script or it won't work.

Then move it inside the manager:

``` bash
docker cp custom-abuseipdb.py single-node-wazuh.manager-1:/var/ossec/integrations/custom-abuseipdb.py
docker exec -it single-node-wazuh.manager-1 chmod 750 /var/ossec/integrations/custom-abuseipdb.py
docker exec -it single-node-wazuh.manager-1 chown root:wazuh /var/ossec/integrations/custom-abuseipdb.py
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
docker exec -it single-node-wazuh.manager-1 mkdir -p /var/ossec/integrations/data
docker exec -it single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/integrations/data
docker exec -it single-node-wazuh.manager-1 chmod 770 /var/ossec/integrations/data
```

Also in **/scripts** you can find the **custom-vt-hash.py**, repeat the process to complete the VirusTotal implementation