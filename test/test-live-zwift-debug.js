try {
    console.log('Require: ZwiftPacketMonitorDebug')
    var ZwiftPacketMonitor = require('../ZwiftPacketMonitorDebug.js')
    console.log('Create monitor')
} catch(e) {
    console.log(e)
}

try {
    console.log('Require: cap')
    var Cap = require('cap').Cap;
    console.log('cap required')
    console.log(Cap, Cap.deviceList())
} catch(e) {
    console.log(e)
}


/*
var route = require('default-network');
route.collect(function(error, data) {
    var ip
    console.log(data);
    names = Object.keys(data);
    try {
        var ifs = os.networkInterfaces()[names[0]]  ;
        ip = ifs.filter(x => x.family === 'IPv4' && !x.internal)[0].address
    } catch (e) {
        // 
    }
    start(ip)
});
*/

const ip = require('internal-ip').v4.sync();
start(ip);

// console.log('require internal-ip')
// const ip = require('internal-ip').v4.sync();
// console.log('internal-ip required')


function start(ip) {

    if (ZwiftPacketMonitor && Cap && ip) {
        
        console.log('Listening on: ', ip); //, JSON.stringify(Cap.findDevice(ip),null,4));
        
        // determine network interface associated with external IP address
        // interface = Cap.findDevice(ip);
        // ... and setup monitor on that interface:
        // const monitor = new ZwiftPacketMonitor(interface)
        
        const monitor = new ZwiftPacketMonitor(ip)
        
        
        
        monitor.on('outgoingPlayerState', (playerState, serverWorldTime) => {
            console.log('outgoingPlayerState');
            console.log(serverWorldTime, dstPort, dstAddr, playerState)
        })
        
        monitor.on('incomingPlayerState', (playerState, serverWorldTime, dstPort, dstAddr) => {
            // console.log('incomingPlayerState');
            // console.log(serverWorldTime, dstPort, dstAddr, playerState)
        })
        
        monitor.on('incomingPlayerGaveRideOn', (playerUpdate, payload, serverWorldTime, dstPort, dstAddr) => {
            console.log('incomingPlayerGaveRideOn');
            console.log(serverWorldTime, dstPort, dstAddr, payload)
        })
        
        monitor.on('incomingPlayerSentMessage', (playerUpdate, payload, serverWorldTime, dstPort, dstAddr) => {
            console.log('incomingPlayerSentMessage');
            console.log(serverWorldTime, dstPort, dstAddr, payload)
        })
        
        monitor.on('incomingPlayerEnteredWorld', (playerUpdate, payload, serverWorldTime, dstPort, dstAddr) => {
            //console.log('incomingPlayerEnteredWorld');
            //console.log(serverWorldTime, dstPort, dstAddr, payload)
        })
        
        monitor.on('incomingPayload2', (playerUpdate, payload, serverWorldTime, dstPort, dstAddr) => {
            //console.log('incomingPayload2');
            //console.log(serverWorldTime, dstPort, dstAddr, payload)
        })
        
        monitor.on('incomingPayload3', (playerUpdate, payload, serverWorldTime, dstPort, dstAddr) => {
            //console.log('incomingPayload3');
            //console.log(serverWorldTime, dstPort, dstAddr, payload)
        })
        
        // The Zwift server sends states in batches. This event is emitted at the end of each incoming batch
        monitor.on('endOfBatch', () => {
            console.log('end of batch')
        })
        
        monitor.start()
    }
    
    
}