"""
Delilah Honeypot

Copyright 2015 Novetta

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import datetime
import time
import tornado.escape
import tornado.ioloop
import tornado.web
import urllib
import json
import random
import smtplib
import ConfigParser
import requests
from collections import OrderedDict
import thread
import hashlib
import sqlite3


# from http://stackoverflow.com/questions/384076/how-can-i-color-python-logging-output ---------------------------------
BLACK = 0
RED = 1
GREEN = 2
YELLOW = 3
BLUE = 4
MAGENTA = 5
CYAN = 6
WHITE = 7
RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[1;%dm"
BOLD_SEQ = "\033[1m"

# ------------------------------------------------------------------------------------------------------------------------------
# http://stackoverflow.com/questions/15848674/how-to-configparse-a-file-keeping-multiple-values-for-identical-keys
class OrderedMultisetDict(OrderedDict):
    def __setitem__(self, key, value):
        if isinstance(value, list) and key in self:
            self[key].extend(value)
        else:
            super(OrderedDict, self).__setitem__(key, value)


# ------------------------------------------------------------------------------------------------------------------------------


# originally based on the elastichoney project by jordan wright.
# but rewritten in python and added a lot of event handlers
# https://github.com/jordan-wright/elastichoney/blob/master/main.go
class ElasticHoneyPy:
    # object for providing an interface to the recorded events
    class AttackReport(tornado.web.RequestHandler):

        def initialize(self, webservice, mode):
            self.webservice = webservice
            self.mode = mode

        def writeCell(self, data):
            self.write("<td>")
            self.write(data)
            self.write("</td>")

        def get(self):
            sql = "select * from events"
            rows = self.webservice.dbcur.execute(sql)

            if self.mode == "html":
                self.write(
                    "<html><body><table><th><td>Timestamp</td><td>Event Type</td><td>Source IP</td><td>SensorIP</td><td>Command</td><td>URI</td><td>User-Agent</td><td>Request Headers</td><td>File URL</td><td>File Saved As...</td><td>Save Successful</td></th>\n")
                for row in rows:
                    timestamp = "INVALIDENTRY:%d" % row[1]
                    try:
                        timestamp = datetime.datetime.fromtimestamp(int(row[1])).isoformat()
                    except:
                        self.webservice.log("Invalid datetime detected: %s. Be warned!" % row[1], RED)
                    color = "#FFFFFF"
                    if row[4] == "Download":
                        color = "#FF0000"
                    if row[4] == "Recon":
                        color = "#00FF00"
                    if row[4] == "Command":
                        color == "#FFFF00"
                    self.write("<tr bgcolor=\"" + color + "\">")
                    self.writeCell(str(timestamp))
                    self.writeCell(str(row[4]))
                    self.writeCell(str(row[2]))
                    self.writeCell(str(row[3]))
                    self.writeCell(tornado.escape.xhtml_escape(row[5]))
                    self.writeCell(tornado.escape.xhtml_escape(row[6]))
                    self.writeCell(tornado.escape.xhtml_escape(row[7]))
                    self.writeCell(str(row[8]))
                    self.writeCell(str(row[9]))
                    self.writeCell(str(row[10]))
                    self.writeCell(str(row[11]))
                    self.write("</tr>\n")
                self.write("</table></body></html>")

            elif self.mode == "json":
                events = []
                for row in rows:
                    events.append(row)

                eventsJson = json.dumps(events)
                self.write(eventsJson)


    class FakeBanner(tornado.web.RequestHandler):

        def initialize(self, webservice):
            self.webservice = webservice

        def get(self):
            response = {
                'name': honey.config.get("honeypot", "instancename")[0],
                'cluster_name': honey.config.get("honeypot", "clustername")[0],
                'version': {
                    'number': honey.config.get("honeypot", "esversion")[0],
                    'build_hash': "89d3241d670db65f994242c8e838b169779e2d4",
                    'build_snapshot': False,
                    'lucene_version': "4.10.2"
                },
                'tagline': "You Know, for Search"
            }

            self.webservice.events.HandleReconEvent(self.request)  # record this event
            self.write(response)

    class FakeNodes(tornado.web.RequestHandler):

        def initialize(self, webservice):
            self.webservice = webservice

        def get(self):
            response = {
                "cluster_name": honey.config.get("honeypot", "clustername")[0],
                "nodes": {
                    honey.config.get("honeypot", "nodename")[0]: {
                        "name": honey.config.get("honeypot", "instancename")[0],
                        "transport_address": "inet[/%s:9300]" % honey.config.get("honeypot", "sensorIP")[0],
                        "host": honey.config.get("honeypot", "hostname")[0],
                        "ip": honey.config.get("honeypot", "sensorIP")[0],
                        "version": honey.config.get("honeypot", "esversion")[0],
                        "build": "%s" % honey.config.get("honeypot", "buildnumber")[0],
                        "http_address": "inet[/%s:9200]" % honey.config.get("honeypot", "sensorIP")[0],
                        "os": {
                            "refresh_interval_in_millis": 1000,
                            "available_processors": int(honey.config.get("honeypot", "totalcores")[0]) / 2,
                            "cpu": {
                                "total_cores": int(honey.config.get("honeypot", "totalcores")[0]),
                                "total_sockets": int(honey.config.get("honeypot", "totalsockets")[0]),
                                "cores_per_socket": 2
                            }
                        },
                        "process": {
                            "refresh_interval_in_millis": 1000,
                            "id": random.randint(100, 40000),
                            "max_file_descriptors": 65535,
                            "mlockall": False
                        },
                        "jvm": {
                            "version": "1.7.0_65"
                        },
                        "network": {
                            "refresh_interval_in_millis": 5000,
                            "primary_interface": {
                                "address": "%s",
                                "name": "eth0",
                                "mac_address": "08:01:c7:3F:15:DD"
                            }
                        },
                        "transport": {
                            "bound_address": "inet[/0:0:0:0:0:0:0:0:9300]",
                            "publish_address": "inet[/%s:9300]" % honey.config.get("honeypot", "sensorIP")[0]
                        },
                        "http": {
                            "bound_address": "inet[/0:0:0:0:0:0:0:0:9200]",
                            "publish_address": "inet[/%s:9200]" % honey.config.get("honeypot", "sensorIP")[0],
                            "max_content_length_in_bytes": 104857600
                        }}
                }
            }
            self.webservice.events.HandleReconEvent(self.request)
            self.write(response)

    class FakeSearch(tornado.web.RequestHandler):

        def initialize(self, webservice):
            self.webservice = webservice

        def get(self):
            shardCnt = random.randint(5, 50)
            response = {
                "took": random.randint(1, 25),
                "timed_out": False,
                "_shards": {
                    "total": shardCnt,
                    "successful": shardCnt,
                    "failed": 0
                },
                "hits": {
                    "total": 1,
                    "max_score": 1.0,
                    "hits": [{
                                 "_index": ".kibana",
                                 "_type": "index-pattern",
                                 "_id": "logstash-*",
                                 "_score": 1.0,
                                 "_source": {"title": "logstash-*", "timeFieldName": "@timestamp",
                                             "customFormats": "{}",
                                             "fields": "[{\"type\":\"string\",\"indexed\":true,\"analyzed\":true,\"doc_values\":false,\"name\":\"host\",\"count\":0},{\"type\":\"string\",\"indexed\":false,\"analyzed\":false,\"name\":\"_source\",\"count\":0},{\"type\":\"string\",\"indexed\":true,\"analyzed\":false,\"doc_values\":false,\"name\":\"message.raw\",\"count\":0},{\"type\":\"string\",\"indexed\":false,\"analyzed\":false,\"name\":\"_index\",\"count\":0},{\"type\":\"string\",\"indexed\":true,\"analyzed\":false,\"doc_values\":false,\"name\":\"@version\",\"count\":0},{\"type\":\"string\",\"indexed\":true,\"analyzed\":true,\"doc_values\":false,\"name\":\"message\",\"count\":0},{\"type\":\"date\",\"indexed\":true,\"analyzed\":false,\"doc_values\":false,\"name\":\"@timestamp\",\"count\":0},{\"type\":\"string\",\"indexed\":true,\"analyzed\":false,\"name\":\"_type\",\"count\":0},{\"type\":\"string\",\"indexed\":true,\"analyzed\":false,\"name\":\"_id\",\"count\":0},{\"type\":\"string\",\"indexed\":true,\"analyzed\":false,\"doc_values\":false,\"name\":\"host.raw\",\"count\":0},{\"type\":\"geo_point\",\"indexed\":true,\"analyzed\":false,\"doc_values\":false,\"name\":\"geoip.location\",\"count\":0}]"}
                             }]
                }
            }

            self.webservice.events.HandleAttackEvent(self.request)
            self.write(response)

    class EventHandler:

        def __init__(self, config, webserver):
            self.config = config
            self.webserver = webserver

        # email notifier
        def sendEmail(self, subjectline, body):
            # set up a list of emails that made it out
            validSends = []

            # get the config
            smtpServer = self.config.get('emailacct', 'server')[0]
            username = self.config.get('emailacct', 'username')[0]
            password = self.config.get('emailacct', 'password')[0]
            fromEmail = self.config.get('emailacct', 'from')[0]
            toEmails = self.config.get('notifications', 'email')

            # write the message
            msg = "\r\n".join([
                "From: %s" % fromEmail,
                "To: %s" % ",".join(toEmails),
                "Subject: %s" % subjectline,
                "",
                str(body)
            ])

            try:
                server = smtplib.SMTP(smtpServer)
                server.starttls()
                server.login(username, password)
                for toEmail in toEmails:
                    server.sendmail(fromEmail, toEmail, msg)
                    validSends.append(toEmail)
                server.quit()
            except Exception, e:
                self.webserver.log("Failed to send email due to exception: %s" % str(e), RED)

            if len(validSends) > 0:
                self.webserver.log("Send notification to %s" % validSends, YELLOW)

        # note that timestamp is a datetime.datetime() object, request is a tornado Request object
        def recordEvent(self, eventType, timestamp, request, command="", fileURL="", filename="", fileSaves=0):
            try:
                ts = int(time.mktime(timestamp.timetuple()))
                sql = "INSERT INTO events (timestamp, sourceIP, sensorIP, opType, command, uri, useragent, allheaders, fileURL, filename, fileSaves) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"
                self.webserver.dbcur.execute(sql, (ts,
                                                   request.remote_ip,
                                                   self.config.get("honeypot", "sensorIP")[0],
                                                   eventType,
                                                   command,
                                                   request.uri,
                                                   request.headers['User-Agent'],
                                                   str(request),
                                                   fileURL,
                                                   filename,
                                                   fileSaves))
                self.webserver.db.commit()
            except Exception, e:
                self.webserver.log("Exception (%s) in recordEvent" % str(e), RED)

        # handler for basic recon requests
        def HandleReconEvent(self, request):
            eventTime = datetime.datetime.now()
            msg = "Recon Event Detected\nTime/Date: %s\nSource: %s\nURL: %s\nHeaders:%s" % (
            eventTime.isoformat(), request.remote_ip, request.uri, request.headers)

            # send the notifications to the appropriate locations
            self.sendEmail("ES Recon Event Detected", msg)
            self.recordEvent("Recon", eventTime, request)

        # handler for attack commands (those requests with "exec(" in them
        def HandleAttackEvent(self, request):
            # this is threaded because if there is a file download it could block for a while
            thread.start_new_thread(self.HandleAttackEventThread, (request,))

        # sub-handler for download commands
        def HandleDownloadCommand(self, eventTime, cmd, request):
            self.webserver.log("ES Download Event Detected: %s" % cmd, GREEN)
            fileDownloaded = True
            filename = ""
            url = ""
            urlStart = cmd.find("http")  # find the start of the URL
            if urlStart > 0:
                urlEnd = cmd[urlStart:].find(")")  # find the end of the URL
                if urlEnd < 0:
                    urlEnd = cmd[urlStart:].find("\\")  # find the end of the URL (sometimes there isn't a paran)
                if urlEnd < 0:
                    urlEnd = cmd[urlStart:].find("\"")  # maybe it just ends a "
                if urlEnd < 0:
                    urlEnd = cmd[urlStart:].find(" ")  # maybe it just ends a space
                if urlEnd < 0:
                    urlEnd = len(cmd) - urlStart

                url = cmd[urlStart:urlStart + urlEnd]
                self.webserver.log("Download URL:%s" % url, GREEN)
                try:
                    self.webserver.log("Attempting to download file from %s" % url, GREEN)
                    r = requests.get(url, timeout=int(self.config.get("data", "downloadtimeout")[0]))
                    exe = r.content
                    sha256 = hashlib.sha256(exe).hexdigest()
                    filename = "%s_%s_%s" % (request.remote_ip, sha256, eventTime.isoformat().replace(":", "_"))
                    open(filename, "wb").write(exe)
                    self.webserver.log("File %s saved to disk" % filename, GREEN)
                except Exception, e:
                    self.webserver.log("Exception trying to download %s: %s" % (url, str(e)), RED)
                    fileDownloaded = False


            else:  # we didnt actually download anything
                fileDownloaded = False

            # log the event
            msg = "Download Command Detected\nTime/Date: %s\nSource: %s\nCommand: %s\nFile URL:%s\nFile Obtained: %s\nSaved As: %s\nURL: %s\nHeaders:%s" % (
            eventTime.isoformat(), request.remote_ip, cmd, url, filename, fileDownloaded, request.uri, request.headers)
            self.sendEmail("ES Download Event Detected", msg)
            self.recordEvent("Download", eventTime, request, cmd, url, filename, fileDownloaded)

        def HandleAttackEventThread(self, request):
            eventTime = datetime.datetime.now()
            cmd = ""
            # see if we have an attack command
            uri = request.uri
            if uri.startswith("/_search?source="):  # embedded command
                uri = urllib.unquote(uri[16:])
                cmdStartPos = uri.find(".exec(\\\"")  # find start of the exec command
                if cmdStartPos > 0:
                    cmdStartPos += 8
                    cmdEndPos = uri[cmdStartPos:].find("\").getInputStream")
                    if cmdEndPos > 0:
                        cmd = uri[cmdStartPos:cmdStartPos + cmdEndPos - 1].replace("+",
                                                                                   " ")  # urllib.unquote misses + for spaces

                        # see if we have a wget or curl.. if so, download the file
                        if cmd.find("wget ") > -1 or cmd.find("curl ") > -1:
                            self.HandleDownloadCommand(eventTime, cmd, request)

                        else:  # not a file download, so just a command line instruciton
                            self.webserver.log("Attack Command Detected from %s: %s" % (request.remote_ip, cmd), YELLOW)
                            msg = "Attack Command Detected\nTime/Date: %s\nSource: %s\nCommand: %s\nURL: %s\nHeaders:%s" % (
                            eventTime.isoformat(), request.remote_ip, cmd, request.uri, request.headers)
                            self.sendEmail("ES Attack Event Detected", msg)
                            self.recordEvent("Command", eventTime, request, cmd)

                    else:  # couldn't find the end of the command, so let's just record it all
                        self.webserver.log("Attack Command Detected from %s, but unable to find end of command: %s" % (
                        request.remote_ip, uri[cmdStartPos:]), MAGENTA)
                        msg = "Attack Command Detected (unable to determine command boundaries)\nTime/Date: %s\nSource: %s\nCommand: %s\nURL: %s\nHeaders:%s" % (
                        datetime.datetime.now().isoformat(), request.remote_ip, uri[cmdStartPos:], request.uri,
                        request.headers)
                        self.sendEmail("ES Attack Event Detected (Incomplete Boundaries)", msg)
                        self.recordEvent("Command_BoundError", eventTime, request, cmd)

                else:  # ok, we really have no idea what is going on so log it and move on
                    self.webserver.log("Unknown request from %s: %s" % (request.remote_ip, uri), BLACK)
                    msg = "Possible Attack Command Detected\nTime/Date: %s\nSource: %s\nURL: %s\nHeaders:%s" % (
                    datetime.datetime.now().isoformat(), request.remote_ip, request.uri, request.headers)
                    self.sendEmail("Possible ES Attack Event Detected", msg)
                    self.recordEvent("PossibleCommand", eventTime, request, cmd)


    def __init__(self, configfile):
        # load the configuration file
        self.config = ConfigParser.RawConfigParser(dict_type=OrderedMultisetDict)
        self.config.read([configfile])

        # access the database
        self.db = sqlite3.connect(self.config.get("data", "dbFile")[0], check_same_thread=False)
        self.dbcur = self.db.cursor()  # i feel this shortcut of going straight into .cursor() might be a bad idea

        # add the table if necessary
        sql = "CREATE TABLE IF NOT EXISTS events (id INT PRIMARY KEY, timestamp INT, sourceIP TEXT, sensorIP TEXT, opType TEXT, command TEXT, uri TEXT, useragent TEXT, allheaders TEXT, fileURL TEXT, filename TEXT, fileSaves INT)"
        self.dbcur.execute(sql)
        self.db.commit()

        # add the event handler
        self.events = self.EventHandler(self.config, self)

        # initialize the webpage handlers
        self.application = tornado.web.Application([
            (r"/", self.FakeBanner, dict(webservice=self)),
            (r"/_nodes", self.FakeNodes, dict(webservice=self)),
            (r"/_search", self.FakeSearch, dict(webservice=self)),
            (
            "/%s" % self.config.get("honeypot", "statusURI")[0], self.AttackReport, dict(webservice=self, mode="html")),
            ("/%s.json" % self.config.get("honeypot", "statusURI")[0], self.AttackReport,
             dict(webservice=self, mode="json")),
        ])

        # initialize the listening port
        self.port = int(self.config.get("honeypot", "port")[0])
        self.log("Listening on port %d" % self.port, BLUE)
        self.application.listen(self.port)

    # quick and dirty logging. Feel free to replace this with the python logging subsystem if you like
    def log(self, entry, color=BLACK):
        colorStart = COLOR_SEQ % (30 + color)
        colorEnd = RESET_SEQ
        print "%s[%s] %s%s" % (colorStart, datetime.datetime.now().isoformat(), entry, colorEnd)

    # call this to make the magic!
    def run(self):
        tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    honey = ElasticHoneyPy("Delilah.ini")
    honey.run()
