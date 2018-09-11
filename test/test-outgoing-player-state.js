const dgram = require('dgram');
// const message = Buffer.from('Some bytes');
const client = dgram.createSocket('udp4');


const interface = require('internal-ip').v4.sync();

console.log('Require: ZwiftPacketMonitor')
const ZwiftPacketMonitor = require('../ZwiftPacketMonitor.js')
console.log('Create monitor')


// const monitor = new ZwiftPacketMonitor('127.0.0.1')
// const monitor = new ZwiftPacketMonitor(interface)
// const monitor = new ZwiftPacketMonitor('\\Device\\NPF_{8A803BAC-27E3-4404-9D5B-C2C58315920B}')
const monitor = new ZwiftPacketMonitor('127.0.0.1')

console.log('Create event listeners')
monitor.on('outgoingPlayerState', (playerState, serverWorldTime) => {
  console.log(playerState)

})


const protobuf = require('protobufjs')
// const zwiftProtoRoot = protobuf.parse(fs.readFileSync(`${__dirname}/../zwiftMessages.proto`), { keepCase: true }).root

// const buffer = new Buffer(65535)



var LOCALPORT = 30221;
var ZWIFTPORT = 3022;

var TESTING_OUTGOING_MESSAGES = true;
var TESTING_INCOMING_MESSAGES = false;

var PORT

if (TESTING_OUTGOING_MESSAGES) {
    PORT = ZWIFTPORT;  // test messages are sent TO this port
    // the server emulates Zwift
    client.bind(LOCALPORT, interface); 
    // the client emulates the game client
} else {
    PORT = LOCALPORT; 
    // the server emulates the game client
    client.bind(ZWIFTPORT);
    // the client emulates the Zwift server
}


var server = dgram.createSocket('udp4');

server.on('listening', function () {
    var address = server.address();
    console.log('UDP Server listening on ' + address.address + ":" + address.port);
});

server.on('message', function (message, remote) {
    console.log(remote.address + ':' + remote.port +' - ' + message);

});

server.bind(PORT, interface);




protobuf.load(`${__dirname}/../zwiftMessages.proto`, function(err, root) {
    if (err)
        throw err;

    // Obtain a message type
    var ClientToServer = root.lookupType("ClientToServer");

    // Exemplary payload
    var payload = { rider_id: 99999, state: {id: 99999}};

    // Verify the payload if necessary (i.e. when possibly incomplete or invalid)
    var errMsg = ClientToServer.verify(payload);
    if (errMsg)
        throw Error(errMsg);

    // Create a new message
    var message = ClientToServer.create(payload); // or use .fromObject if conversion is necessary

    // Encode a message to an Uint8Array (browser) or Buffer (node)
    var buffer = ClientToServer.encode(message).finish();
    // ... do something with buffer


    client.send(buffer, PORT, interface, (err) => {
        // client.close();
      });
      
    client.send(buffer, PORT, interface, (err) => {
        // client.close();
      });
      
    client.send(buffer, PORT, interface, (err) => {
        client.close();
      });
      


});
