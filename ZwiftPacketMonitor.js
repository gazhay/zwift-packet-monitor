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
    this._linkType = this._cap.open(this._interfaceName, 'port 3022', 10 * 1024 * 1024, buffer)
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
    if (this._linkType === 'ETHERNET') {
      let ret = decoders.Ethernet(buffer)

      if (ret.info.type === PROTOCOL.ETHERNET.IPV4) {
        ret = decoders.IPV4(buffer, ret.offset)
        if (ret.info.protocol === PROTOCOL.IP.UDP) {
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
                    case 2:
                      payload = payload2Packet.decode(new Uint8Array(player_update.payload))
                      break
                    case 3:
                      // nothing
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
        }
      }
    }
  }
}

module.exports = ZwiftPacketMonitor