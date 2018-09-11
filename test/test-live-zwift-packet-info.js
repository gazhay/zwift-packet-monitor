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
    

    
    // monitor.on('outgoingPlayerState', (playerState, serverWorldTime) => {
    //     console.log(serverWorldTime, dstPort, dstAddr, playerState)
    // })
    
    // monitor.on('incomingPlayerState', (playerState, serverWorldTime, dstPort, dstAddr) => {
    //     console.log(serverWorldTime, dstPort, dstAddr, playerState)
    // })
    
    // monitor.on('incomingPlayerGaveRideOn', (playerUpdate, payload, serverWorldTime, dstPort, dstAddr) => {
    //     console.log(serverWorldTime, dstPort, dstAddr, payload)
    // })

    // monitor.on('incomingPlayerSentMessage', (playerUpdate, payload, serverWorldTime, dstPort, dstAddr) => {
    //     console.log(serverWorldTime, dstPort, dstAddr, payload)
    // })
    
    // monitor.on('incomingPlayerEnteredWorld', (playerUpdate, payload, serverWorldTime, dstPort, dstAddr) => {
    //     console.log(serverWorldTime, dstPort, dstAddr, payload)
    // })
    
    // monitor.on('incomingPayload2', (playerUpdate, payload, serverWorldTime, dstPort, dstAddr) => {
    //     console.log(serverWorldTime, dstPort, dstAddr, payload)
    // })
    
    // monitor.on('incomingPayload3', (playerUpdate, payload, serverWorldTime, dstPort, dstAddr) => {
    //     console.log(serverWorldTime, dstPort, dstAddr, payload)
    // })
    
    // // The Zwift server sends states in batches. This event is emitted at the end of each incoming batch
    // monitor.on('endOfBatch', () => {
    //   console.log('end of batch')
    // })
    
    monitor.start()
}

