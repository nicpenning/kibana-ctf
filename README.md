To Do:
- [x] Discover challenges
- [x] ES|QL challenges
- [x] Optimize challenge scores, play through ensure good flow
- [x] Ensure all saved objects and elasticsearch docs can be replicated with ease.
- [x] Document deploy/setup instructions
- [ ] Create blind/self test mode to not reveal any flags or secrets during setup process
- [ ] Automate setup with PowerShell 7 script
- [ ] Add ability to randomize flags for unique flags every time
- [ ] Share with community!

## Requirements
- PowerShell 7+ (For Setup [Manual/Automated])
- Elastic Stack (Kibana and Elasticsearch 8.16+)
- CTFd (Latest)

```
 ./Invoke-Kibana-CTF-Setup.ps1                                                                                                       
Welcome to the Kibana CTF Setup Script!
What would you like to do?
1. Deploy CTFd
2. Import CTFd Challenges, Flags, etc.
3. Reset CTFd
4. Deploy Elastic Stack
5. Import Objects and Index Documents for Elastic Stack
6. Reset Elastic Stack
7. Check for Requirements
8. Deploy all from scratch
Q. Quit
Enter your choice: 
```

## How to get started
1. Ensure you have PowerShell 7+ installed then download this repo to get rolling!

```bash
git clone https://github.com/nicpenning/kibana-ctf.git
cd kibana-ctf
pwsh
./Invoke-Kibana-CTF-Setup.ps1
```

2. Deploy CTFd - Use Option 1
a. Once deployed, go to the CTFd instance and navigate through the wizard with default settings (most of these will be overwritten later). Make sure to make note of your admin user/password combination and specify how long you want the CTF to last (this can easily be changed later if needed.)
![CTFd First Start Page](./images/image.png)
![Step 2 Sample](./images/image-1.png)
![Step 3 Sample](./images/image-2.png)
![Step 4 Sample](./images/image-4.png)
![Step 5 Sample](./images/image-5.png)
![Step 6 - Set Start / End Date of Challenge](./images/image-6.png)
![Finish!](./images/image-7.png)

b. Go to settings, create the API Access Token and copy for later since you will not be able to see them after dismissing that pop up window. (No worries if you forget, you can create one later.)
![API Access Token](./images/image-8.png)
![Navigate to Access Token Page](./images/image-9.png)
![Generate Token](./images/image-10.png)
![Copy Token for Usage Later](./images/image-11.png)

3. Import CTFd Challenges/Flags/etc. - Use Option 2 (This will ask for you Access Token we had you copy from the previous step!)

4. Download and start Elasticsearch / Kibana - Use Option 4

5. Import Objects and Index Documents for Elastic Stack - Use Option 5

6. Login to Kibana and go to the Kibana CTF space and good luck!

#### Advanced Settings for CTFd access - Allow others on the network to access CTF
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

#### Future Flow
Run Invoke-Kibana-CTF-Setup.ps1 -> Prompt for credentials -> Script sets up CTFd, Kibana CTF space, Import Saved Objects, Ingest Documents -> Setup Complete
