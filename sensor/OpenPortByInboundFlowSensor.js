/*    Copyright 2020 Firewalla INC 
 *
 *    This program is free software: you can redistribute it and/or  modify
 *    it under the terms of the GNU Affero General Public License, version 3,
 *    as published by the Free Software Foundation.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU Affero General Public License for more details.
 *
 *    You should have received a copy of the GNU Affero General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
'use strict';

const log = require('../net2/logger.js')(__filename)

const Sensor = require('./Sensor.js').Sensor

const sem = require('./SensorEventManager.js').getInstance()

const fc = require('../net2/config.js');

const Alarm = require('../alarm/Alarm.js');
const AM2 = require('../alarm/AlarmManager2.js');
const am2 = new AM2();
const execAsync = require('child-process-promise').exec
const util = require('util');
const Firewalla = require('../net2/Firewalla');
const xml2jsonBinary = Firewalla.getFirewallaHome() + "/extension/xml2json/xml2json." + Firewalla.getPlatform();
const _ = require('lodash');
const ExternalScanSensor = require('../sensor/ExternalScanSensor');
const rclient = require('../util/redis_manager.js').getRedisClient();
const redisIpKey = "sys:network:info";
const redisIpField = "publicIp";

class OpenPortByInboundFlowSensor extends Sensor {
  constructor() {
    super();
  }

  run() {
    sem.on("NewOutPortConn", async (event) => {
      const flow = event.flow;
      if(!flow) {
        return;
      }

      if (fc.isFeatureOn("alarm_openport")) {
        const nmapResult = await this.nmapConfirmOpenPort(flow.lh, flow.dp);
        if (nmapResult.state !== "open")
          return;

        let publicIP = await rclient.hgetAsync(redisIpKey, redisIpField);
        if (!publicIP)
          return;

        try {
          publicIP = JSON.parse(publicIP);
        } catch (err) {
          return;
        }

        let isOpen = await ExternalScanSensor.cloudConfirmOpenPort(publicIP, flow.dp);
        if (isOpen) {
          let alarm = new Alarm.OpenPortAlarm(
            flow.ts,
            flow.mac,
            {
              'p.source': 'OpenPortByInboundFlowSensor',
              'p.device.ip': flow.lh,
              'p.device.mac': flow.mac,
              'p.open.port': flow.dp.toString(),
              'p.open.protocol': flow.pr,
              'p.open.servicename': nmapResult.serviceName
            }
          );
          await am2.enrichDeviceInfo(alarm);
          await am2.enqueueAlarm(alarm);
        }
      }
    });
  }

  async nmapConfirmOpenPort(localIP, port) {
    let result = {state: "", serviceName: "unknown"};
    let cmd = util.format('sudo nmap -p%s %s -oX - | %s', port, localIP, xml2jsonBinary);

    log.info("Running command:", cmd);
    try {
      const cmdResult = await execAsync(cmd);
      let findings = JSON.parse(cmdResult.stdout);
      result.state = _.get(findings, `nmaprun.host.ports.port.state.state`, "");
      result.serviceName = _.get(findings, `nmaprun.host.ports.port.service.name`, "");
    } catch (err) {
      log.error("Failed to nmap scan:", err);
    }

    return result;
  }
}

module.exports = OpenPortByInboundFlowSensor;
