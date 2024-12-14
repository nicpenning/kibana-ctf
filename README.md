To Do:
- [ ] Discover challenges
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

Import CTF ([challenges](https://github.com/nicpenning/kibana-ctf/blob/main/CTFd_Events/Kibana%20CTF.2024-12-13_04_17_16.zip))

Import Kibana Saved Objects [(Searches / Data Views / Dashboards / Advanced Settings / etc.) ](https://github.com/nicpenning/kibana-ctf/tree/main/Discover)

Import [Elasticsearch Docs](https://github.com/nicpenning/kibana-ctf/blob/main/CTFd_Events/solutions.txt)

Configure Space to not let participants access Saved Objects
