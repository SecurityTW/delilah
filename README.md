Delilah Honeypot by Novetta
===========================

Introduction
------------
Delilah is a honeypot system inspired by Jordan Wright’s Elastichoney (https://github.com/jordan-wright/elastichoney) that is designed to attract attackers who are actively exploiting the Elasticsearch Groovy vulnerability (http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2015-1427). Delilah acts as a vulnerable Elasticsearch instance that detects and identifies attack commands, recon attempts, and download commands (specifically "wget" and "curl"). Whenever an attacker issues a download command, Delilah will attempt to download the file the attacker is attempting to introduce on a victim's system to allow analysts the opportunity to analyze the files at a later date. Whenever Delilah detects an attacker's commands, a notification email is sent to one or more email addresses in order to alert analysts in real-time of incoming attacks.

Delilah provides a variety of configurable parameters to mimic Elasticsearch instances and prevent an attacker from easily determining that they are interacting with a honeypot. 

Multiple Delilah nodes can be installed to form a network of sensors. To more easily view the sensor network, analysts should use the Delilah Monitor. The Delilah Monitor is a simple web interface that will query each of the specified Delilah nodes and produce a chronological event view for the entire sensor collection. Delilah Monitor can also be used for a single node if a larger sensor network is not desired.

Delilah and Delilah Monitor are Python based and will run on operating systems that supports Python. Delilah and Deililah Monitor have been tested on Ubuntu Linux and Windows OSes.

For more information about the DDoS botnet associated with the attacks that leverage the Elasticsearch vulnerability and how Delilah was used in determining the behavior of the actors behind these attacks, please visit the following URL: http://www.novetta.com/library/downloads/#NTRG.
 

Installation
------------

Delilah has only a few external dependencies. The following packages are required in order for Delilah and the Delilah Monitor to operate:

* sqlite3
* tornado (pip install tornado)
* requests (pip install requests)

For Linux systems, screen is recommended since Delilah does not run as a daemon and will terminate if a terminal is lost.

Delilah requires a few configuration parameters to be set prior to activation. The Delilah.ini file contains the configuration for the Delilah honeypot (if the file is missing, Delilah will not run). For testing it is fine to leave the [honeypot] and [data] sections as their default values. However, the [emailacct] and [notifications] must be configured to avoid errors. 

```
[notifications]
email: user@example.com				        ; there can be as many users or as few users as needed
email: user2@example.com			        ; simply add or remove "email:" entries as necessary

[emailacct]
username: reportingaccount@example.com		; login name for Delilah to log with to send email
password: youneedapassword					; password for the email account
server: smtp.example.com:587				; email server and port
from: reportingaccount@example.com			; the email address from which the notifications will arrive
```

For each user that will receive an email notification of a Delilah event there must be an "email:" entry. If only one user will be notified of events, the second entry should be removed. If more than two users will receive the events, additional "email:" entries must be added. The [emailacct] section contains the information necessary to send the email. Note that the username and passwords are stored in plaintext therefore it is extremely important that access to the Delilah.ini file be restricted and the server upon which it is housed is secure. 

To activate Delilah simply issue the command:

```
python Delilah.py
```

Delilah Monitor is configured via the DelilahMonitor.ini file. This package provides a template (DelilahMonitor.template.ini) that one can use to construct their own DelilahMonitor.ini configuration file. The configuration of Delilah Monitor is relatively straighforward. For each Delilah sensor an analyst will be monitoring, a "sensor:" entry within the [sensors] section must exist. The name of the sensor given in a "sensor:" entry is the basis for the section that defines the sensor. For example, if the following line exists within the [sensors] section:

```
sensor: atlantic
```

then there must be a corresponding [atlantic] section within the configuration file. Each sensor section takes the following form:

```
[{sensor1name}]													; This subsection must match the name of one and only one of the `sensor:` fields
ip: {IP address of sensor1 ... do not include :9200}
timeout: {Seconds to wait for a response}
location: {Geographical location or some other identifier for the sensor}
statusURI: {URI to access to pull down intel from sensor}
```

The "ip:" field specifies the IP address of the sensor, "timeout:" specifies how long Delilah Monitor will wait before giving up on connecting to the sensor, "location:" is an arbitrary string that specifies the location of the sensor or some other identifying feature, and "statusURI:" must match the "statusURI:" within the Delilah.ini for the sensor. 

To activate the Delilah Monitor, issue the following command:

```
python DelilahMonitor.py
```

Note that Delilah Monitor has no authentication mechanism. Simply navigating to the IP address and port (as specified by the "port:" entry of [webui]) of the Delilah Monitor instance will display the events of all configured sensors. It is recommended that the Delilah Monitor be run locally or be bound to a loopback device, but never exposed directly to the Internet to avoid exposing your sensor network.

Licensing
---------

Delilah and Delilah Monitor are licensed under the Apache v2 license.

