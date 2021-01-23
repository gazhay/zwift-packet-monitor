try {
    console.log('Require: ZwiftPacketMonitorLogger')
    var ZwiftPacketMonitorLogger = require('../ZwiftPacketMonitorLogger.js')
    console.log('Create monitor')
} catch(e) {
    console.log(e)
}

// try {
//     console.log('Require: cap')
//     var Cap = require('cap').Cap;
//     console.log('cap required')
//     // console.log(Cap, Cap.deviceList())
// } catch(e) {
//     console.log(e)
// }

const ip = require('internal-ip').v4.sync();
start(ip);


function start(ip) {

    // if (ZwiftPacketMonitorLogger && Cap && ip) {
    if (ZwiftPacketMonitorLogger  && ip) {
        
        console.log('Listening on: ', ip); //, JSON.stringify(Cap.findDevice(ip),null,4));
       
        var now = new Date()
        var subdir = `${now.getFullYear()}-${now.getMonth()+1}-${now.getDate()}-${now.getHours()}-${now.getMinutes()}-${now.getSeconds()}`
        
        const monitor = new ZwiftPacketMonitorLogger(ip, {
            dir: `c:/temp/${subdir}`,
            incoming: true,
            outgoing: true,
            payload: true
        })
        
        monitor.on('outgoingPlayerState', (playerState, serverWorldTime, dstPort, dstAddr) => {
            console.log('outgoingPlayerState');
        })
        
        monitor.on('incomingPlayerState', (playerState, serverWorldTime, dstPort, dstAddr) => {
            console.log('incomingPlayerState');
        })
      
        monitor.start()
    }
    
    
}