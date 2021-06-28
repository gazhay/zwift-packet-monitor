const { time } = require('console');
const EventEmitter = require('events')

try {
  var Cap = require('cap').Cap;
  var decoders=require('cap').decoders, PROTOCOL=decoders.PROTOCOL
} catch (e) {
  throw new Error('Probably missing Npcap/libpcap')
}

const fs = require('fs')
const protobuf = require('protobufjs')
const zwiftProtoRoot = protobuf.parse(fs.readFileSync(`${__dirname}/zwiftMessages.proto`), { keepCase: true }).root

const buffer = new Buffer.alloc(65535)
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

    try{
        if (!interfaceName){ this._interfaceName = Cap.findDevice() } else
        if (interfaceName.match(/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) { this._interfaceName = Cap.findDevice(interfaceName) }
    } catch {
        this._interfaceName = interfaceName
    }

  }

  start () {
    try {
      this._linkType = this._cap.open(this._interfaceName, 'udp port 3022 or tcp port 3023', 10 * 1024 * 1024, buffer)
      this._cap.setMinBytes && this._cap.setMinBytes(0)
      this._cap.on('packet', this.processPacket.bind(this))
    } catch (e) {
      throw new Error('Error in cap.open - probably insufficient access rights')
    }
  }

  stop () {
    this._cap.close()
  }

  static deviceList () {
    return  Cap.deviceList()
  }

  _decodeIncoming(buffer) {
    try {
      let packet = serverToClientPacket.decode(buffer)
      return packet
    } catch (err) {
    }
  }

  _decodeOutgoing(buffer) {
    try {
      let packet = clientToServerPacket.decode(buffer)
      return packet
    } catch (err) {
    }
  }

  _incomingPacketEmit(packet, info) {
    if (!packet || !info) return;

    for (let player_state of packet.player_states) {
      this.emit('incomingPlayerState', player_state, packet.world_time, info.dstport, info.dstaddr)
    }

    for (let player_update of packet.player_updates) {
      let payload = {};
      try {
        switch (player_update.tag3) {
          case 105: // player entered world
            payload = payload105Packet.decode(new Uint8Array(player_update.payload))
            this.emit('incomingPlayerEnteredWorld', player_update, payload, packet.world_time, info.dstport, info.dstaddr)
            break
          case 5: // chat message
            payload = payload5Packet.decode(new Uint8Array(player_update.payload))
            this.emit('incomingPlayerSentMessage', player_update, payload, packet.world_time, info.dstport, info.dstaddr)
            break
          case 4: // ride on
            payload = payload4Packet.decode(new Uint8Array(player_update.payload))
            this.emit('incomingPlayerGaveRideOn', player_update, payload, packet.world_time, info.dstport, info.dstaddr)
            break
          case 2:
            // payload = payload2Packet.decode(new Uint8Array(player_update.payload))
            // this.emit('incomingPayload2', player_update, payload, packet.world_time, info.dstport, info.dstaddr)
            break
          case 3:
            // payload = payload3Packet.decode(new Uint8Array(player_update.payload))
            // this.emit('incomingPayload3', player_update, payload, packet.world_time, info.dstport, info.dstaddr)
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
      this.emit('incomingPlayerUpdate', player_update, payload, packet.world_time, info.dstport, info.dstaddr)
    }

    if (packet.num_msgs === packet.msgnum) {
      this.emit('endOfBatch')
    }

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
              // let packet = serverToClientPacket.decode(buffer.slice(ret.offset, ret.offset + ret.info.length))
              let packet = this._decodeIncoming(buffer.slice(ret.offset, ret.offset + ret.info.length))
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
              this._incomingPacketEmit(packet, ret.info)
            } else if (ret.info.dstport === 3022) {
              try {
                // 2020-11-14 extra handling added to handle what seems to be extra information preceeding the protobuf
                let skip = 5; // uncertain if this number should be fixed or
                // ...if the first byte(so far only seen with value 0x06)
                // really is the offset where protobuf starts, so add some extra checks just in case:
                if (buffer.slice(ret.offset + skip, ret.offset + skip + 1).equals(Buffer.from([0x08]))) {
                  // protobuf does seem to start after skip bytes
                } else if (buffer.slice(ret.offset, ret.offset + 1).equals(Buffer.from([0x08]))) {
                  // old format apparently, starting directly with protobuf instead of new header
                  skip = 0
                } else {
                  // use the first byte to determine how many bytes to skip
                  skip = buffer.slice(ret.offset, ret.offset + 1).readUIntBE(0, 1) - 1
                }
                let packet = this._decodeOutgoing(buffer.slice(ret.offset + skip, ret.offset + ret.info.length - 4))
                if (packet && packet.state) {
                  this.emit('outgoingPlayerState', packet.state, packet.world_time, ret.info.srcport, ret.info.srcaddr)
                }
              } catch (ex) {
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

              let tcpPayloadComplete = false

              if (flagsPshAck && !this._tcpBuffer) {
                // this TCP packet does not require assembling
                this._tcpBuffer = buffer.slice(ret.offset, ret.offset + datalen)
                this._tcpAssembledLen = datalen
                tcpPayloadComplete = true
              } else if (flagsPshAck) {
                // This is the last TCP packet in a sequence
                this._tcpBuffer = Buffer.concat([this._tcpBuffer, buffer.slice(ret.offset, ret.offset + datalen)])
                this._tcpAssembledLen += datalen
                tcpPayloadComplete = true
              } else if (flagsAck && !this._tcpBuffer) {
                // This is the first TCP packet in a sequence
                this._tcpBuffer = Buffer.concat([buffer.slice(ret.offset, ret.offset + datalen)])
                this._tcpAssembledLen = datalen
              } else if (flagsAck) {
                // This is an intermediate TCP packet in a sequence
                this._tcpBuffer = Buffer.concat([this._tcpBuffer, buffer.slice(ret.offset, ret.offset + datalen)])
                this._tcpAssembledLen += datalen
              }

              if (tcpPayloadComplete) {
                // all payloads were assembled, now extract and process all messages in this._tcpBuffer
                // The assembled TCP payload contains one or more messages
                // <msg len> <msg> [<msg len> <msg>]*

                let offset = 0
                let l = 0

                while (offset + l < this._tcpAssembledLen) {
                  let b = this._tcpBuffer.slice(offset, offset + 2)
                  if (b) {
                    l = b.readUInt16BE() // total length of the message is stored in first two bytes
                  }

                  try {
                    packet = this._decodeIncoming(this._tcpBuffer.slice(offset + 2, offset + 2 + l))
                  } catch (ex) {
                  }

                  if (packet) {
                    this._incomingPacketEmit(packet, ret.info)
                  }

                  offset = offset + 2 + l
                  l = 0
                } // end while
                // all packets in assembled _tcpBuffer are processed now

                // reset _tcpAssembledLen and _tcpBuffer for next sequence to assemble
                this._tcpBuffer = null
                this._tcpAssembledLen = 0
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
