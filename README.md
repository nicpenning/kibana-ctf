To Do:
- [x] Discover challenges
- [ ] ES|QL challenges
- [ ] Dashboards challenges
- [ ] Optimize challenge scores, play through ensure good flow
- [ ] Ensure all saved objects and elasticsearch docs can be replicated with ease.
- [ ] Document deploy/setup instructions
- [ ] reate blind/self test mode to not reveal any flags or secrets during setup process
- [ ] Automate setup with PowerShell script
- [ ] Add ability to randomize flags for unqiue experience every time
- [ ] Share with community!

## How to get started
Download and start CTFd (requires internet access, docker and docker compose)
```bash
git clone https://github.com/CTFd/CTFd.git
cd CTFd
docker compose up
```

Import CTF ([challenges](https://github.com/nicpenning/kibana-ctf/blob/main/CTFd_Events/Kibana%20CTF.2024-12-13_04_17_16.zip))

Download and start Elasticsearch / Kibana (requires internet access, docker and docker compose)

Import Kibana Saved Objects [(Searches / Data Views / Dashboards / Advanced Settings / etc.) ](https://github.com/nicpenning/kibana-ctf/tree/main/Discover)

Import [Elasticsearch Docs](https://github.com/nicpenning/kibana-ctf/blob/main/CTFd_Events/solutions.txt)

Configure Space to not let participants access Saved Objects

#### Advanced Settings for CTFd access - Allow others on the network to access
Note: You can grab the Ubuntu IP by running this from your Ubuntu WSL2 host: `ip addr | grep eth0`:
```bash
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    inet **172.25.93.23**/20 brd 172.25.95.255 scope global eth0
25: veth06010d4@if24: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-765cf15dc8a1 state UP group default
```

```Powershell
netsh interface portproxy add v4tov4 listenport=31337 listenaddress=[Replace this with your local IP. Example == 192.168.86.90] connectport=8000 connectaddress=[Replace this with your WSL2 IP. Example == 172.25.93.23]
```
Doing the step above then allows access to your computer from http://192.168.86.90:31337 since it will forward any traffic from other devices to the WSL2 IP of 172.25.93.24:8000 (which you can access locally). Just becareful not to do this on public networks. Do this at your own risk.

If you have a Windows Firewall enabled, you will need to allow the port used above (ie TCP 31337).


