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

How to get started:

```bash
git clone https://github.com/CTFd/CTFd.git
cd CTFd
docker compose up
```

Allow others on the network to access:
```Powershell
netsh interface portproxy add v4tov4 listenport=31337 listenaddress=[Replace this with your local IP. Example == 192.168.86.90] connectport=8000 connectaddress=[Replace this with your WSL2 IP. Example == 172.25.93.23]
```
Above then allows access to your computer from http://192.168.86.90:31337 since it will forward any traffic from other devices to the WSL2 IP of 172.25.93.24:8000 (which you can access locally)

If you have a Windows Firewall enabled, you will need to allow the port used above (ie TCP 31337).

Import CTF ([challenges](https://github.com/nicpenning/kibana-ctf/blob/main/CTFd_Events/Kibana%20CTF.2024-12-13_04_17_16.zip))

Import Kibana Saved Objects [(Searches / Data Views / Dashboards / Advanced Settings / etc.) ](https://github.com/nicpenning/kibana-ctf/tree/main/Discover)

Import [Elasticsearch Docs](https://github.com/nicpenning/kibana-ctf/blob/main/CTFd_Events/solutions.txt)

Configure Space to not let participants access Saved Objects
