# JA3 Fingerprinting Generator

### Background Information

When a client connects to a server via HTTPS, it utilizes SSL/TLS to create the
secure connection.  Each client can complete the TLS handshake in various ways,
and the JA3 fingerprinting algorithm is meant to uniquely identify certain
clients.


JA3 was created and developed at Salesforce. More background information about
JA3 can be found
[here](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967
"JA3/JA3S Information").

### How the HTTPS Server Works
`https_server.py` contains a barebones Python concurrent HTTPS server that
maintains the minimum connection time to digest the JA3 fingerprint from the
browser client.

It utilizes Polling to create a concurrent web server.  When a client connects
to the server, it looks for the main GET request after the TLS handshake takes
place.  After this, the web server returns the JA3 fingerprint, as well as the
browser client/version that it parses from the User-Agent string along with the
GET request.

When the server gets a new client or JA3, it adds it to a DynamoDB instance on
AWS.  This database is a master list of known JA3 hashes.

### Future Development


### Running the Server
On the EC2 instance, run
```
docker run -it -u root -p 443:4443 -v /etc/letsencrypt/live/ja3.appianis.com/:/home/appuser/certs/ -v /etc/letsencrypt/archive/ja3.appianis.com:/home/archive/ja3.appianis.com https
```


This will start up the docker container to listen for HTTPS connections on its
internal port 4443, and the host will map its port 443 to forward to the
container's port 4443.  You can test that the docker container is running
successfully by going to `https://ja3.appianis.com` while on VPN or the wired
VLAN.


By visiting `https://ja3.appianis.com`, you should see a webpage with your
browser's JA3 fingerprint, browser name, and browser version.  It extracts all
of this data, except for the JA3 fingerprint, from the User-Agent string your
browser sends with the initial GET request.
