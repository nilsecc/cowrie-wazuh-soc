# Cowrie Honeypot

## 1. Raspberry Pi Installation/Configuration

Update and upgrade the system

```bash
nilsecc@raspberrypi:~$ sudo apt update && sudo apt upgrade -y
```

Install Cowrie dependencies

```bash
nilsecc@raspberrypi:~$ sudo apt install -y git python3-virtualenv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind virtualenv
```

Create a dedicated user for Cowrie. For security reasons (principle of least privilege), cowrie user has no sudo access and is isolated to its own directory

```bash
nilsecc@raspberrypi:~$ sudo adduser --disabled-password cowrie
nilsecc@raspberrypi:~$ sudo su - cowrie
```

Clone the Cowrie repository

```bash
cowrie@raspberrypi:~$ git clone https://github.com/cowrie/cowrie
cowrie@raspberrypi:~$ cd cowrie/
```

Create a Python virtual environment to avoid package/version conflicts

```bash
cowrie@raspberrypi:~/cowrie$ virtualenv cowrie-env
cowrie@raspberrypi:~/cowrie$ source cowrie-env/bin/activate
```

Install Python dependencies

```bash
(cowrie-env) cowrie@raspberrypi:~/cowrie$ pip install --upgrade pip && pip install -r requirements.txt
```

Install Cowrie as a Python package (creates the cowrie command)

```bash
(cowrie-env) cowrie@raspberrypi:~/cowrie$ pip install -e .
```

Initialize Cowrie (creates etc/cowrie.cfg and log directory structure)

```bash
(cowrie-env) cowrie@raspberrypi:~/cowrie$ cowrie init
```

Edit config to display a credible hostname to attackers

```bash
(cowrie-env) cowrie@raspberrypi:~/cowrie$ TERM=xterm nano etc/cowrie.cfg
# Change: hostname = svr04 -> hostname = ubuntu-server (or any convincing name)
```

Start Cowrie

```bash
(cowrie-env) cowrie@raspberrypi:~/cowrie$ cowrie start
(cowrie-env) cowrie@raspberrypi:~/cowrie$ cowrie status
```

## 2. Router Configuration

My ISP blocks port 22 on residential lines. If it's also your case, try port 2222 externally instead (bots also scan this port).

Port forwarding rule:

| Field | Value |
|---|---|
| Name | cowrie-ssh |
| Destination IP | 192.168.1.38 (your Raspberry Pi IP) |
| Protocol | TCP |
| External port WAN | 2222 (or 22 if possible) |
| Internal port LAN | 2222 |

## 3. Verification

Check if Cowrie is running (to run it use `cowrie start`)

```bash
cowrie status
```

Test connection to honeypot (from your PC)

```bash
ssh root@YOUR_PUBLIC_IP
```

Monitor logs in real time

```bash
cat var/log/cowrie/cowrie.log
```

JSON logs for analysis (easier to parse with Wazuh later)

```bash
cat var/log/cowrie/cowrie.json
```

Cowrie accepts almost any user-pass combination by default (uses a big dictionary). `login.success` is therefore expected, not critical so don't panic. What matters more is what happens after login: commands, downloads, tunneling.
But this must be a safe environment so any command, tunnel... it's safe (should be).
