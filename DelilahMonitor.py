"""
Delilah Honeypot Monitor

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
import tornado.escape
import tornado.ioloop
import tornado.web
import json
import ConfigParser
import requests
from collections import OrderedDict

# http://stackoverflow.com/questions/15848674/how-to-configparse-a-file-keeping-multiple-values-for-identical-keys
class OrderedMultisetDict(OrderedDict):
    def __setitem__(self, key, value):
        if isinstance(value, list) and key in self:
            self[key].extend(value)
        else:
            super(OrderedDict, self).__setitem__(key, value)


class sensorMonitor:
    class Dashboard(tornado.web.RequestHandler):

        def initialize(self, config):
            self.config = config

        def get(self):
            # all events
            allEvents = {}

            # ip to sensor map
            ipSensor = {}

            # get the sensor list
            sensorList = self.config.get("sensors", "sensor")
            sensors = {}
            for sensor in sensorList:
                sensors[sensor] = {"ip": self.config.get(sensor, "ip")[0],
                                   "timeout": int(self.config.get(sensor, "timeout")[0]),
                                   "location": self.config.get(sensor, "location")[0],
                                   "statusURI": self.config.get(sensor, "statusURI")[0],
                                   "online": False
                                   }
                ipSensor[self.config.get(sensor, "ip")[0]] = sensor

            # query each sensor
            for sensor in sensors:
                events = []
                url = "http://%s:9200/%s.json" % (sensors[sensor]['ip'], sensors[sensor]['statusURI'])
                try:
                    r = requests.get(url, timeout=sensors[sensor]['timeout'])
                    datablob = r.content
                    events = json.loads(datablob)
                except Exception, e:
                    print "Exception (%s) trying to query %s" % (str(e), sensor)
                    continue

                # set the sensor as online
                sensors[sensor]['online'] = True

                # add entries to global list of events
                for event in events:
                    if event[1] not in allEvents:  # using timestamp as our index here
                        allEvents[event[1]] = []
                    allEvents[event[1]].append(event)

            # generate a list of timestamps, sorted
            eventKeys = sorted(allEvents.keys())

            # display the results
            html = "<html><body>"
            html += "<table>"
            html += "<tr><th>Sensor Name</th><th>IP</th><th>Location</th><th>Status</th></tr>\n"
            for sensor in sensors:
                html += "<tr><td>" + sensor + "</td>"
                html += "<td>" + sensors[sensor]['ip'] + "</td>"
                html += "<td>" + sensors[sensor]['location'] + "</td>"
                if sensors[sensor]['online'] == True:
                    html += "<td bgcolor=#00FF00>Online</td>"
                else:
                    html += "<td bgcolor=#FF0000>Offline</td>"
                html += "</tr>\n"
            html += "</table>"

            html += "<br><hr><br>"
            html += "<h2>Events</h2><p>\n"
            html += "<table>\n"
            html += "<tr><th>Timestamp</th><th>Event Type</th><th>Source IP</th><th>SensorIP</th><th>Command</th><th>URI</th><th>User-Agent</th><th>Request Headers</th><th>File URL</th><th>File Saved As...</th><th>Save Successful</th></tr>\n"

            for ts in eventKeys:
                events = allEvents[ts]
                for row in events:
                    timestamp = "INVALIDENTRY:%d" % row[1]
                    try:
                        timestamp = datetime.datetime.fromtimestamp(int(row[1])).isoformat()
                    except:
                        print "Invalid datetime detected: %s. Be warned!" % row[1]
                    color = "#FFFFFF"
                    if row[4] == "Download":
                        color = "#FF0000"
                    if row[4] == "Recon":
                        color = "#00FF00"
                    if row[4] == "Command":
                        color = "#FFFF00"
                    html += "<tr bgcolor=\"" + color + "\">"
                    html += "<td>"
                    html += str(timestamp)
                    html += "</td><td>"
                    html += str(row[4])
                    html += "</td><td>"
                    html += str(row[2])
                    html += "</td><td>"
                    if row[3] in ipSensor:
                        html += ipSensor[row[3]]
                    else:
                        html += str(row[3])
                    html += "</td><td>"
                    html += tornado.escape.xhtml_escape(row[5])
                    html += "</td><td>"
                    html += tornado.escape.xhtml_escape(row[6])
                    html += "</td><td>"
                    html += tornado.escape.xhtml_escape(row[7])
                    html += "</td><td>"
                    html += str(row[8])
                    html += "</td><td>"
                    html += str(row[9])
                    html += "</td><td>"
                    html += str(row[10])
                    html += "</td><td>"
                    html += str(row[11])
                    html += "</td></tr>\n"

            html += "</table></body></html>"

            # display results
            self.write(html)


    def __init__(self, configfile):

        # load the configuration file
        self.config = ConfigParser.RawConfigParser(dict_type=OrderedMultisetDict)
        self.config.read([configfile])

        # initialize the webpage handlers
        self.application = tornado.web.Application([
            (r"/", self.Dashboard, dict(config=self.config)),
        ])

        # initialize the listening port
        self.port = int(self.config.get("webui", "port")[0])
        print "Listening on port %d" % self.port
        self.application.listen(self.port)

    # call this to make the magic!
    def run(self):
        tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    monitor = sensorMonitor("DelilahMonitor.ini")
    monitor.run()
