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
    // this._tcpSeqNo = 0
    this._tcpAssembledLen = 0
    this._tcpBuffer = null
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
                }
                this.emit('incomingPlayerUpdate', player_update, payload, packet.world_time, ret.info.dstport, ret.info.dstaddr)
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
          }
        } else if (ret.info.protocol === PROTOCOL.IP.TCP) {
          var datalen = ret.info.totallen - ret.hdrlen;
          ret = decoders.TCP(buffer, ret.offset);
          datalen -= ret.hdrlen;
          try {
            if (ret.info.srcport === 3023 && datalen > 0) {
              let packet = null
        
              let flagPSH = ((ret.info.flags & 0x08) !== 0)
              let flagACK = ((ret.info.flags & 0x10) !== 0)

              let flagsPshAck = (ret.info.flags == 0x18)

              let flagsAck = (ret.info.flags == 0x10)

              let b = buffer.slice(ret.offset, ret.offset + 2)
              let l = 0
              if (b) {
                l = b.readUInt16BE() // total length of the message is stored in first two bytes of first TCP packet
                // if intermediate packet: first 2 bytes are part of content, too
                // if final packet (which is not the first): first 2 bytes are part of content
              }

              if (flagsPshAck && this._tcpAssembledLen == 0) {
                if (l == datalen -2) {
                  // complete message in a single packet
                  

                  packet = serverToClientPacket.decode(buffer.slice(ret.offset + 2, ret.offset + datalen - 2))
                }
                // reset _tcpAssembledLen for next sequence to assemble
                this._tcpAssembledLen = 0
              } else if (flagsAck && this._tcpAssembledLen == 0  && l > datalen - 2) {
                // first packet of a sequence to be assembled
                this._tcpBuffer = Buffer.concat([buffer.slice(ret.offset + 2, ret.offset + datalen - 2)], l)
                this._tcpAssembledLen = datalen - 2
              } else if ((flagsAck && this._tcpAssembledLen > 0) || (flagsPshAck && this._tcpAssembledLen > 0 && this._tcpAssembledLen < this._tcpBuffer.length)) {
                // could be both the last or an intermediate packet
                if (this._tcpAssembledLen + datalen >= this._tcpBuffer.length) {
                  // HOPEFULLY DEAD CODE !!!!!
                  // probably last packet in sequence anyway (despite no PSH flag) 
                  // first 2 bytes are part of content, too
                  let b = buffer.slice(ret.offset, ret.offset + datalen)
                  b.copy(this._tcpBuffer, this._tcpAssembledLen)

                  packet = serverToClientPacket.decode(this._tcpBuffer)

                  // reset _tcpAssembledLen for next sequence to assemble
                  this._tcpAssembledLen = 0

                } else {
                  // intermediate packet of a sequence to be assembled
                  // first 2 bytes are part of content, too
                  let b = buffer.slice(ret.offset, ret.offset + datalen)
                  b.copy(this._tcpBuffer, this._tcpAssembledLen)
                  this._tcpAssembledLen += datalen
                }
              } else if (flagsPshAck && this._tcpAssembledLen > 0 && this._tcpAssembledLen + datalen >= this._tcpBuffer.length) {  
                // LAST PART OF CONDITION is necessary because there can be PSH flag on intermediate packets when the total message is very long
                // e.g. right after Zwift launches it sends a large message (60k+ bytes)

                // last packet of a sequence to be assembled
                // first 2 bytes are part of content, too
                let b = buffer.slice(ret.offset, ret.offset + datalen)
                b.copy(this._tcpBuffer, this._tcpAssembledLen)
                
                packet = serverToClientPacket.decode(this._tcpBuffer)

                // reset _tcpAssembledLen for next sequence to assemble
                this._tcpAssembledLen = 0
              }


              if (packet) {
                for (let player_state of packet.player_states) {
                  this.emit('incomingPlayerState', player_state, packet.world_time, ret.info.dstport, ret.info.dstaddr)
                }
                for (let player_update of packet.player_updates) {
                  let payload = {};
                  try {
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
                    }
                  } catch (ex) {
                    // most likely an exception during decoding of payload

                  }
                  this.emit('incomingPlayerUpdate', player_update, payload, packet.world_time, ret.info.dstport, ret.info.dstaddr)
                }  
                if (packet.num_msgs === packet.msgnum) {
                  this.emit('endOfBatch')
                }
              }
            }
          } catch (ex) {
            // reset _tcpAssembledLen and _tcpBuffer for next sequence to assemble in case of an exception
            this._tcpAssembledLen = 0
            this._tcpBuffer = null
          }

        }
      } 
    }
  }
}

module.exports = ZwiftPacketMonitor
