const EventEmitter = require('events')

try {
  var Cap = require('cap').Cap;
  var decoders=require('cap').decoders, PROTOCOL=decoders.PROTOCOL
} catch (e) {
  throw new Error('Probably missing WinPcap/Win10PCap/Npcap/libpcap')
}

const fs = require('fs')
const protobuf = require('protobufjs')
const zwiftProtoRoot = protobuf.parse(fs.readFileSync(`${__dirname}/zwiftMessages.proto`), { keepCase: true }).root

const buffer = new Buffer(65535)
const clientToServerPacket = zwiftProtoRoot.lookup('ClientToServer')
const serverToClientPacket = zwiftProtoRoot.lookup('ServerToClient')

const payload105Packet = zwiftProtoRoot.lookup('Payload105')
const payload5Packet = zwiftProtoRoot.lookup('Payload5')
const payload4Packet = zwiftProtoRoot.lookup('Payload4')
const payload3Packet = zwiftProtoRoot.lookup('Payload3')
const payload2Packet = zwiftProtoRoot.lookup('Payload2')


class ZwiftPacketMonitor extends EventEmitter {
  constructor (interfaceName) {
    super()
    this._cap = new Cap()
    this._linkType = null
    this._sequence = 0
    if (interfaceName.match(/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) {
      this._interfaceName = Cap.findDevice(interfaceName)
    } else {
      this._interfaceName = interfaceName
    }
  }

  start () {
    // this._linkType = this._cap.open(this._interfaceName, 'port 3022', 10 * 1024 * 1024, buffer)
    this._linkType = this._cap.open(this._interfaceName, 'udp port 3022 or tcp port 3023', 10 * 1024 * 1024, buffer)
    this._cap.setMinBytes && this._cap.setMinBytes(0)
    this._cap.on('packet', this.processPacket.bind(this))
  }

  stop () {
    this._cap.close()
  }

  static deviceList () {
    return  Cap.deviceList()
  }

  processPacket () {
    // console.log('ZwiftPacketMonitor: processPacket()')
    if (this._linkType === 'ETHERNET') {
      let ret = decoders.Ethernet(buffer)

      if (ret.info.type === PROTOCOL.ETHERNET.IPV4) {
        ret = decoders.IPV4(buffer, ret.offset)
        if (ret.info.protocol === PROTOCOL.IP.UDP) {
          // console.log('Decoding UDP ...');
          ret = decoders.UDP(buffer, ret.offset)
          try {
            if (ret.info.srcport === 3022) {
              let packet = serverToClientPacket.decode(buffer.slice(ret.offset, ret.offset + ret.info.length))
              /*
              if (this._sequence) {
                if (packet.seqno > this._sequence + 1) {
                  console.warn(`Missing packets - expecting ${this._sequence + 1}, got ${packet.seqno}`)
                } else if (packet.seqno < this._squence) {
                  console.warn(`Delayed packet - expecting ${this._sequence + 1}, got ${packet.seqno}`)
                  return
                }
              }
              this._sequence = packet.seqno
              */
              for (let player_state of packet.player_states) {
                this.emit('incomingPlayerState', player_state, packet.world_time, ret.info.dstport, ret.info.dstaddr)
              }
              for (let player_update of packet.player_updates) {
                // console.log('incomingPlayerUpdate', player_update, packet.world_time)
                let payload = {};
                switch (player_update.tag3) {
                    case 105: // player entered world
                      payload = payload105Packet.decode(new Uint8Array(player_update.payload))
                      this.emit('incomingPlayerEnteredWorld', player_update, payload, packet.world_time, ret.info.dstport, ret.info.dstaddr)
                      break
                    case 5: // chat message
                      payload = payload5Packet.decode(new Uint8Array(player_update.payload))
                      this.emit('incomingPlayerSentMessage', player_update, payload, packet.world_time, ret.info.dstport, ret.info.dstaddr)
                      break
                    case 4: // ride on
                      payload = payload4Packet.decode(new Uint8Array(player_update.payload))
                      this.emit('incomingPlayerGaveRideOn', player_update, payload, packet.world_time, ret.info.dstport, ret.info.dstaddr)
                      break
                    case 2:
                      // payload = payload2Packet.decode(new Uint8Array(player_update.payload))
                      // this.emit('incomingPayload2', player_update, payload, packet.world_time, ret.info.dstport, ret.info.dstaddr)
                      break
                    case 3:
                      // payload = payload3Packet.decode(new Uint8Array(player_update.payload))
                      // this.emit('incomingPayload3', player_update, payload, packet.world_time, ret.info.dstport, ret.info.dstaddr)
                      break
                    case 109:
                      // nothing
                      break
                    case 110:
                      // nothing
                      break
                    default:
                      //
                      // console.log(`unknown type ${player_update.tag3}`)
                      // console.log(player_update)
                      // a bit of code to pick up data for analysis of unknown payload types:
                      // fs.writeFileSync(`/temp/playerupdate_${player_update.tag1}_${player_update.tag3}.raw`, new Uint8Array(player_update.payload))
                }
                // if (payload) {
                    // console.log('payload of incomingPlayerUpdate', payload)
                    this.emit('incomingPlayerUpdate', player_update, payload, packet.world_time, ret.info.dstport, ret.info.dstaddr)
                // }
              }  
              if (packet.num_msgs === packet.msgnum) {
                this.emit('endOfBatch')
              }
            } else if (ret.info.dstport === 3022) {
              let packet = clientToServerPacket.decode(buffer.slice(ret.offset, ret.offset + ret.info.length - 4))
              if (packet.state) {
                this.emit('outgoingPlayerState', packet.state, packet.world_time, ret.info.srcport, ret.info.srcaddr)
              }
            }
          } catch (ex) {
            console.log(ex)
          }
        } else if (ret.info.protocol === PROTOCOL.IP.TCP) {
          var datalen = ret.info.totallen - ret.hdrlen;
          // console.log('Decoding TCP ...');
          // console.log(JSON.stringify(ret));
          ret = decoders.TCP(buffer, ret.offset);
          // console.log(' from port: ' + ret.info.srcport + ' to port: ' + ret.info.dstport);
          // console.log(JSON.stringify(ret));
          datalen -= ret.hdrlen;
          // console.log(buffer.toString('binary', ret.offset, ret.offset + datalen));
          try {
            if (ret.info.srcport === 3023) {
              // if ((ret.info.flags & 0x18)) // Flags: 0x018 (PSH, ACK)
					// final package in sequence
				// if first package in sequence: First 2 bytes contain total size
				// if intermediate package: first 2 bytes are part of content, too
				// if final package (which is not the first): first 2 bytes are part of content
        // 
              let b = buffer.slice(ret.offset, ret.offset + 2)
              let l = b.readInt16BE()
              console.log(`ACK ${((ret.info.flags & 0x10) !== 0)} PSH  ${((ret.info.flags & 0x08) !== 0)} datalen ${datalen} ${l}`)
              let packet = serverToClientPacket.decode(buffer.slice(ret.offset + 2, ret.offset + datalen - 2))
              for (let player_state of packet.player_states) {
                this.emit('incomingPlayerState', player_state, packet.world_time, ret.info.dstport, ret.info.dstaddr)
              }
              for (let player_update of packet.player_updates) {
                // console.log('incomingPlayerUpdate', player_update, packet.world_time)
                let payload = {};
                switch (player_update.tag3) {
                    case 105: // player entered world
                      payload = payload105Packet.decode(new Uint8Array(player_update.payload))
                      this.emit('incomingPlayerEnteredWorld', player_update, payload, packet.world_time, ret.info.dstport, ret.info.dstaddr)
                      break
                    case 5: // chat message
                      payload = payload5Packet.decode(new Uint8Array(player_update.payload))
                      this.emit('incomingPlayerSentMessage', player_update, payload, packet.world_time, ret.info.dstport, ret.info.dstaddr)
                      break
                    case 4: // ride on
                      payload = payload4Packet.decode(new Uint8Array(player_update.payload))
                      this.emit('incomingPlayerGaveRideOn', player_update, payload, packet.world_time, ret.info.dstport, ret.info.dstaddr)
                      break
                    case 2:
                      // payload = payload2Packet.decode(new Uint8Array(player_update.payload))
                      // this.emit('incomingPayload2', player_update, payload, packet.world_time, ret.info.dstport, ret.info.dstaddr)
                      break
                    case 3:
                      // payload = payload3Packet.decode(new Uint8Array(player_update.payload))
                      // this.emit('incomingPayload3', player_update, payload, packet.world_time, ret.info.dstport, ret.info.dstaddr)
                      break
                    case 109:
                      // nothing
                      break
                    case 110:
                      // nothing
                      break
                    default:
                      //
                      // console.log(`unknown type ${player_update.tag3}`)
                      // console.log(player_update)
                      // a bit of code to pick up data for analysis of unknown payload types:
                      // fs.writeFileSync(`/temp/playerupdate_${player_update.tag1}_${player_update.tag3}.raw`, new Uint8Array(player_update.payload))
                }
                // if (payload) {
                    // console.log('payload of incomingPlayerUpdate', payload)
                    this.emit('incomingPlayerUpdate', player_update, payload, packet.world_time, ret.info.dstport, ret.info.dstaddr)
                // }
              }  
              if (packet.num_msgs === packet.msgnum) {
                this.emit('endOfBatch')
              }
            }
          } catch (ex) {
            // console.log(ex)
          }

        }
      } 
    }
  }
}

module.exports = ZwiftPacketMonitor