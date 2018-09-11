try {
    console.log('Require: ZwiftPacketMonitor')
    var ZwiftPacketMonitor = require('../ZwiftPacketMonitor.js')
    console.log('Create monitor')
} catch(e) {
    console.log(e)
}

try {
    var Cap = require('cap').Cap;
} catch(e) {
    console.log(e)
}

const ip = require('internal-ip').v4.sync();



if (ZwiftPacketMonitor && Cap) {

    console.log('Listening on: ', ip, JSON.stringify(Cap.findDevice(ip),null,4));
    
    // determine network interface associated with external IP address
    interface = Cap.findDevice(ip);
    // ... and setup monitor on that interface:
    const monitor = new ZwiftPacketMonitor(interface)
    

        
    monitor.on('incomingPayload2', (playerUpdate, payload, serverWorldTime, dstPort, dstAddr) => {
        console.log(serverWorldTime, dstPort, dstAddr, payload)
    })
    
    monitor.start()
}

