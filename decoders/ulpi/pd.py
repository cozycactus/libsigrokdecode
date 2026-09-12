##
## This file is part of the libsigrokdecode project.
##
## Copyright (C) 2026 Ruslan Migirov <trapi78@gmail.com>
##
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program.  If not, see <http://www.gnu.org/licenses/>.
##

'''
Decodes the ULPI bus between a USB link and a ULPI PHY.

The FX3 USB3300 analyzer firmware captures one sample per rising CLKOUT
edge: DATA[7:0] on D0..D7, STP on D8, NXT on D9 and DIR on D10.

Bus rules used here:

- DIR low means the link drives the bus. The link sends a command byte
  (register read/write, or a USB transmit command) followed by data bytes.
- DIR high means the PHY drives the bus. A byte is valid while NXT is high;
  DIR going low again ends the transfer.
- STP high while the link drives the bus ends a USB transmit.

Received USB packets are decoded into tokens, data and handshake packets and
also emitted in the usb_packet python format, so the usb_request decoder can
be stacked directly on top of this one.
'''

import sigrokdecode as srd

# PID byte -> (name, category). The low nibble is the complement of the
# high nibble; PIDS is keyed by the full byte as seen on the wire.
PIDS = {
    0xE1: ('OUT', 'TOKEN'),
    0x69: ('IN', 'TOKEN'),
    0xA5: ('SOF', 'TOKEN'),
    0x2D: ('SETUP', 'TOKEN'),
    0xC3: ('DATA0', 'DATA'),
    0x4B: ('DATA1', 'DATA'),
    0x87: ('DATA2', 'DATA'),
    0x0F: ('MDATA', 'DATA'),
    0xD2: ('ACK', 'HANDSHAKE'),
    0x5A: ('NAK', 'HANDSHAKE'),
    0x1E: ('STALL', 'HANDSHAKE'),
    0x96: ('NYET', 'HANDSHAKE'),
    0x3C: ('PRE/ERR', 'SPECIAL'),
    0x78: ('SPLIT', 'SPECIAL'),
    0xB4: ('PING', 'SPECIAL'),
    0xF0: ('Reserved', 'SPECIAL'),
}

# ULPI command byte classes, bits [7:6].
CMD_USB = 0x00
CMD_WRITE = 0x80
CMD_READ = 0xC0


def _reverse(value, bits):
    out = 0
    for i in range(bits):
        if value & (1 << i):
            out |= 1 << (bits - 1 - i)
    return out


def _crc(bits, width, poly):
    '''USB CRC over bits in wire order (LSB first), complemented result.'''
    mask = (1 << width) - 1
    top = 1 << (width - 1)
    crc = mask
    for bit in bits:
        msb = 1 if crc & top else 0
        crc = (crc << 1) & mask
        if msb ^ bit:
            crc ^= poly
    return _reverse(crc ^ mask, width)


def crc5_field(value):
    '''CRC5 over an 11 bit token/SOF field, as transmitted on the wire.'''
    bits = [(value >> i) & 1 for i in range(0, 11)]
    return _crc(bits, 5, 0x05)


def crc16_field(payload):
    '''CRC16 over the payload bytes in transmit order.'''
    bits = []
    for byte in payload:
        bits.extend([(byte >> i) & 1 for i in range(0, 8)])
    return _crc(bits, 16, 0x8005)


class Decoder(srd.Decoder):
    api_version = 3
    id = 'ulpi'
    name = 'ULPI'
    longname = 'UTMI+ Low Pin Interface'
    desc = 'USB 2.0 transceiver bus between a link and a ULPI PHY.'
    license = 'gplv2+'
    inputs = []
    outputs = ['usb_packet']
    tags = ['USB']
    channels = (
        {'id': 'D0', 'name': 'DATA0', 'desc': 'ULPI data bus bit 0'},
        {'id': 'D1', 'name': 'DATA1', 'desc': 'ULPI data bus bit 1'},
        {'id': 'D2', 'name': 'DATA2', 'desc': 'ULPI data bus bit 2'},
        {'id': 'D3', 'name': 'DATA3', 'desc': 'ULPI data bus bit 3'},
        {'id': 'D4', 'name': 'DATA4', 'desc': 'ULPI data bus bit 4'},
        {'id': 'D5', 'name': 'DATA5', 'desc': 'ULPI data bus bit 5'},
        {'id': 'D6', 'name': 'DATA6', 'desc': 'ULPI data bus bit 6'},
        {'id': 'D7', 'name': 'DATA7', 'desc': 'ULPI data bus bit 7'},
        {'id': 'D8', 'name': 'STP', 'desc': 'Link stop'},
        {'id': 'D9', 'name': 'NXT', 'desc': 'PHY next / flow control'},
        {'id': 'D10', 'name': 'DIR', 'desc': 'PHY drives the bus'},
    )
    options = ()
    annotations = (
        ('bus', 'ULPI bus event'),
        ('packet', 'USB packet'),
        ('field', 'Packet field'),
        ('error', 'Error'),
    )
    annotation_rows = (
        ('bus', 'ULPI', (0,)),
        ('packets', 'Packets', (1,)),
        ('fields', 'Fields', (2,)),
        ('errors', 'Errors', (3,)),
    )

    def __init__(self):
        self.reset()

    def reset(self):
        self.rx = []
        self.rx_start = None
        self.tx_register = None
        self.eop_seen = False
        self.state = None

    def start(self):
        self.out_python = self.register(srd.OUTPUT_PYTHON)
        self.out_ann = self.register(srd.OUTPUT_ANN)

    def put_field(self, ss, es, name, value, texts):
        self.put(ss, es, self.out_python, [name, value])
        self.put(ss, es, self.out_ann, [2, [texts[0], texts[1]]])

    def annotate(self, ss, es, row, texts):
        self.put(ss, es, self.out_ann, [row, texts])

    def check_crc5(self, ss, es, field, observed):
        if crc5_field(field) == observed:
            self.put_field(ss, es, 'CRC5', observed,
                           ['CRC5 0x%02x' % observed, 'CRC5', 'C'])
        else:
            self.put(ss, es, self.out_python, ['CRC5 ERROR', observed])
            self.annotate(ss, es, 3, [
                'CRC5 error: 0x%02x' % observed, 'CRC5 ERR', 'CE'])

    def decode_packet(self, ss, es):
        data = self.rx
        self.rx = []
        self.rx_start = None
        self.eop_seen = False
        start = ss if ss is not None else es

        pid = data[0]
        if (pid ^ (pid >> 4)) & 0x0f != 0x0f:
            self.annotate(start, es, 3, [
                'PID 0x%02x: complement nibble mismatch' % pid,
                'PID 0x%02x error' % pid, 'PID ERR'])
            return

        name, category = PIDS.get(pid, ('UNKNOWN', 'INVALID'))
        if name == 'UNKNOWN':
            self.annotate(start, es, 3, [
                'Unknown PID 0x%02x' % pid, 'PID 0x%02x' % pid, 'PID?'])
            return

        self.put(start, es, self.out_python, ['PID', name])
        self.annotate(start, es, 1, ['%s packet' % name, name])

        if name in ('IN', 'OUT', 'SETUP') and len(data) >= 3:
            addr = data[1] & 0x7f
            ep = ((data[1] >> 7) & 1) | ((data[2] & 0x07) << 1)
            crc5 = data[2] >> 3
            self.put_field(start, es, 'ADDR', addr,
                           ['Address %d' % addr, 'Addr %d' % addr, 'A%d' % addr])
            self.put_field(start, es, 'EP', ep,
                           ['Endpoint %d' % ep, 'EP %d' % ep, 'E%d' % ep])
            self.check_crc5(start, es, addr | (ep << 7), crc5)
        elif name == 'SOF' and len(data) >= 3:
            framenum = ((data[2] & 0x07) << 8) | data[1]
            crc5 = data[2] >> 3
            self.put_field(start, es, 'FRAMENUM', framenum,
                           ['Frame %d' % framenum, 'Frm %d' % framenum, 'F%d' % framenum])
            self.check_crc5(start, es, framenum, crc5)
        elif category == 'DATA' and len(data) >= 3:
            payload = data[1:-2]
            for i, byte in enumerate(payload):
                self.put_field(start, es, 'DATABYTE', byte,
                               ['Data byte %d: 0x%02x' % (i, byte), '0x%02x' % byte])
            crc16 = data[-2] | (data[-1] << 8)
            if crc16_field(payload) == crc16:
                self.put_field(start, es, 'CRC16', crc16,
                               ['CRC16 0x%04x' % crc16, 'CRC16', 'C'])
            else:
                self.put(start, es, self.out_python, ['CRC16 ERROR', crc16])
                self.annotate(start, es, 3, [
                    'CRC16 error: 0x%04x' % crc16, 'CRC16 ERR', 'CE'])

        self.put(start, es, self.out_python, ['PACKET', [category, name, data]])

    def handle_state(self, data, dir_high, nxt, stp):
        ss = self.samplenum

        # PHY drives the bus: collect received bytes.
        if dir_high:
            if self.rx_start is None:
                self.rx_start = ss
            if nxt:
                # The first clock after the link releases the bus is the
                # turnaround cycle: it carries no byte until the PHY drives.
                if not self.rx and data == 0x00:
                    return
                self.rx.append(data)
                self.annotate(ss, ss, 0, ['RX byte 0x%02x' % data, 'RX 0x%02x' % data])
            elif data and not self.eop_seen:
                self.eop_seen = True
                self.annotate(ss, ss, 0, [
                    'End of receive (0x%02x)' % data, 'EOP'])
            return

        # Link drives the bus.
        if data:
            cls = data & 0xC0
            if cls == CMD_WRITE:
                self.tx_register = data & 0x3F
                self.annotate(ss, ss, 0, [
                    'Register write 0x%02x' % self.tx_register,
                    'WR 0x%02x' % self.tx_register])
            elif cls == CMD_READ:
                self.tx_register = data & 0x3F
                self.annotate(ss, ss, 0, [
                    'Register read 0x%02x' % self.tx_register,
                    'RD 0x%02x' % self.tx_register])
            elif self.tx_register is not None:
                self.annotate(ss, ss, 0, [
                    'Register data 0x%02x' % data, 'DATA 0x%02x' % data])
                self.tx_register = None
            else:
                self.annotate(ss, ss, 0, [
                    'USB transmit command 0x%02x' % data, 'TX 0x%02x' % data])
        if stp:
            self.annotate(ss, ss, 0, ['STP asserted', 'STP'])

    def decode(self):
        # DIR is the transfer boundary: remember the last sample of a receive.
        last_rx_sample = None
        while True:
            pins = self.wait()
            data = 0
            for i in range(8):
                if pins[i]:
                    data |= 1 << i
            stp, nxt, dir_high = pins[8], pins[9], pins[10]
            state = (data << 3) | (dir_high << 2) | (nxt << 1) | stp

            if state == self.state:
                if dir_high and nxt:
                    last_rx_sample = self.samplenum
                continue

            # Leaving the PHY-driven phase finishes the packet.
            was_dir = (self.state >> 2) & 1 if self.state is not None else 0
            if was_dir and not dir_high and self.rx:
                self.decode_packet(self.rx_start, last_rx_sample or self.samplenum)

            self.state = state
            self.handle_state(data, dir_high, nxt, stp)

            if dir_high and nxt:
                last_rx_sample = self.samplenum


def _hex(value):
    return '0x%02x' % value
