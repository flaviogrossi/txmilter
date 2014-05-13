import struct

from . import constants
from .message import MilterMessage


class MilterCodecError(Exception):
    """ Encoder/Decoder error """


class MilterEncoder(object):
    def encode(self, msg):
        if msg.cmd not in constants.VALID_CMDS:
            raise MilterCodecError('invalid command %s' % msg.cmd)
        method = getattr(self, '_encode_%s' % msg.cmd.lower())
        return method(msg)

    def _pack(self, cmd, *args):
        data = ''.join(args)
        return '%s%s' % (struct.pack('!Ic', len(data) + 1, cmd), data)

    def _encode_str(self, s):
        if not isinstance(s, basestring):
            raise MilterCodecError('expected string but got %s' % s)
        return '%s\0' %s

    def _encode_buf(self, b):
        if not isinstance(b, basestring):
            raise MilterCodecError('expected string but got %s' % b)
        return b

    def _encode_u32(self, n):
        try:
            return struct.pack('!I', n)
        except struct.error:
            raise MilterCodecError('error packing u32 %s' % n)

    def _encode_u16(self, n):
        try:
            return struct.pack('!H', n)
        except struct.error:
            raise MilterCodecError('error packing u16 %s' % n)

    def _encode_char(self, c):
        try:
            return struct.pack('c', c)
        except struct.error:
            raise MilterCodecError('error packing char %s' % c)

    def _encode_3chars(self, s):
        if not isinstance(s, basestring) or len(s) != 3:
            raise MilterCodecError('expected string  of length 3 but got %s'
                                   % s)
        return struct.pack('3s', s)

    def _encode_char_array(self, l):
        if len(l) == 0:
            raise MilterCodecError('got empty string array')
        return ''.join(self._encode_str(i) for i in l)

    def _encode_smfic_abort(self, msg):
        return self._pack('A')

    def _encode_smfic_body(self, msg):
        return self._pack('B', self._encode_buf(msg.data.get('buf')))

    def _encode_smfic_connect(self, msg):
        family = msg.data.get('family').value
        return self._pack('C', self._encode_str(msg.data.get('hostname')),
                               self._encode_char(family),
                               self._encode_u16(msg.data.get('port')),
                               self._encode_str(msg.data.get('address')))

    def _encode_smfic_macro(self, msg):
        # TODO
        raise NotImplementedError

    def _encode_smfic_bodyeob(self, msg):
        return self._pack('E')

    def _encode_smfic_helo(self, msg):
        return self._pack('H', self._encode_str(msg.data.get('helo')))

    def _encode_smfic_quit_nc(self, msg):
        return self._pack('K')  # TODO: check this

    def _encode_smfic_header(self, msg):
        return self._pack('L', self._encode_str(msg.data.get('name')),
                               self._encode_str(msg.data.get('value')))

    def _encode_smfic_mail(self, msg):
        return self._pack('M', self._encode_char_array(msg.data.get('args')))

    def _encode_smfic_eoh(self, msg):
        return self._pack('N')

    def _encode_smfic_optneg(self, msg):
        return self._pack('O', self._encode_u32(msg.data.get('version')),
                               self._encode_u32(msg.data.get('actions')),
                               self._encode_u32(msg.data.get('protocol')))

    def _encode_smfic_quit(self, msg):
        return self._pack('Q')

    def _encode_smfic_rcpt(self, msg):
        return self._pack('R', self._encode_char_array(msg.data.get('args')))

    def _encode_smfic_data(self, msg):
        return self._pack('T')

    def _encode_smfic_unknown(self, msg):
        return self._pack('U')

    def _encode_smfir_addrcpt(self, msg):
        return self._pack('+', self._encode_str(msg.data.get('rcpt')))

    def _encode_smfir_delrcpt(self, msg):
        return self._pack('-', self._encode_str(msg.data.get('rcpt')))

    def _encode_smfir_addrcpt_par(self, msg):
        return self._pack('2', self._encode_str(msg.data.get('rcpt')),
                               self._encode_str(msg.data.get('esmpt_arg')))

    def _encode_smfir_shutdown(self, msg):
        return self._pack('4')

    def _encode_smfir_accept(self, msg):
        return self._pack('a')

    def _encode_smfir_replbody(self, msg):
        return self._pack('b', self._encode_buf(msg.data.get('buf')))

    def _encode_smfir_continue(self, msg):
        return self._pack('c')

    def _encode_smfir_discard(self, msg):
        return self._pack('d')

    def _encode_smfir_chgfrom(self, msg):
        return self._pack('e', self._encode_str(msg.data.get('from')),
                               self._encode_str(msg.data.get('esmtp_arg')))

    def _encode_smfir_conn_fail(self, msg):
        return self._pack('f')

    def _encode_smfir_addheader(self, msg):
        return self._pack('h', self._encode_str(msg.data.get('name')),
                               self._encode_str(msg.data.get('value')))

    def _encode_smfir_chgheader(self, msg):
        return self._pack('m',self._encode_u32(msg.data.get('index')),
                              self._encode_str(msg.data.get('name')),
                              self._encode_str(msg.data.get('value')))

    def _encode_smfir_progress(self, msg):
        return self._pack('p')

    def _encode_smfir_quarantine(self, msg):
        return self._pack('q', self._encode_str(msg.data.get('reason')))

    def _encode_smfir_reject(self, msg):
        return self._pack('r')

    def _encode_smfir_skip(self, msg):
        return self._pack('s')

    def _encode_smfir_tempfail(self, msg):
        return self._pack('t')

    def _encode_smfir_replycode(self, msg):
        return self._pack('y', self._encode_3chars(msg.data.get('smtpcode')),
                               ' ',
                               self._encode_str(msg.data.get('text')))


class MilterDecoder(object):
    def __init__(self):
        self._data = []
        self._buf = ''

    def feed(self, data):
        self._data.append(data)
        return self

    def _decode(self, buf, fmt):
        try:
            fmt_len = struct.calcsize(fmt)
            if len(buf) < fmt_len:
                return None, buf
            else:
                return (struct.unpack(fmt, buf[:fmt_len])[0],
                        buf[fmt_len:])
        except Exception:
            raise MilterCodecError('error while decoding data ("%r")' % buf)

    def decode(self):
        # a milter message is
        # uint32    len           Size of data to follow
        # char      cmd           Command/response code
        # char      data[len-1]   Code-specific data (may be empty)

        while True:
            length, rest = self._decode(''.join(self._data), '!I')
            if length is None or length == 0:
                break

            cmd, rest = self._decode(rest, 'c')
            if cmd is None:
                break

            data_len = length - 1
            if len(rest) < data_len:
                break

            self._data = [rest[data_len:]]
            data = rest[:data_len]

            yield self._create_message(cmd, data)

    def _create_message(self, cmd, data):
        decoded_data = {}
        cmds = { 'A': 'SMFIC_ABORT',
                 'B': 'SMFIC_BODY',
                 'C': 'SMFIC_CONNECT',
                 'D': 'SMFIC_MACRO',
                 'E': 'SMFIC_BODYEOB',
                 'H': 'SMFIC_HELO',
                 'K': 'SMFIC_QUIT_NC',
                 'L': 'SMFIC_HEADER',
                 'M': 'SMFIC_MAIL',
                 'N': 'SMFIC_EOH',
                 'O': 'SMFIC_OPTNEG',
                 'R': 'SMFIC_RCPT',
                 'T': 'SMFIC_DATA',
                 'Q': 'SMFIC_QUIT',
                 'U': 'SMFIC_UNKNOWN',
                 '+': 'SMFIR_ADDRCPT',
                 '-': 'SMFIR_DELRCPT',
                 '2': 'SMFIR_ADDRCPT_PAR',
                 '4': 'SMFIR_SHUTDOWN',
                 'a': 'SMFIR_ACCEPT',
                 'b': 'SMFIR_REPLBODY',
                 'c': 'SMFIR_CONTINUE',
                 'd': 'SMFIR_DISCARD',
                 'e': 'SMFIR_CHGFROM',
                 'f': 'SMFIR_CONN_FAIL',
                 'h': 'SMFIR_ADDHEADER',
                 'm': 'SMFIR_CHGHEADER',
                 'p': 'SMFIR_PROGRESS',
                 'q': 'SMFIR_QUARANTINE',
                 'r': 'SMFIR_REJECT',
                 's': 'SMFIR_SKIP',
                 't': 'SMFIR_TEMPFAIL',
                 'y': 'SMFIR_REPLYCODE',
                }
        command = cmds.get(cmd, None)
        if command is None:
            raise MilterCodecError('got invalid command %s' % cmd)

        method = getattr(self, '_decode_%s_data' % command.lower())
        decoded_data = method(data)

        return MilterMessage(command, decoded_data)

    def _decode_buf(self, data):
        return data

    def _decode_str(self, data):
        return data.split('\0', 1)

    def _decode_char(self, data):
        return data

    def _decode_strs(self, data):
        return list(i for i in data.split('\0') if i)

    def _decode_u16(self, data):
        try:
            return ( struct.unpack('!H', data[:2])[0], data[2:] )
        except:
            raise MilterCodecError('invalid u16 data')

    def _decode_smfic_abort_data(self, data):
        return {}

    def _decode_smfic_body_data(self, data):
        return {'buf': self._decode_buf(data)}

    def _decode_smfic_connect_data(self, data):
        hostname, rest = self._decode_str(data)
        if not rest:
            raise MilterCodecError('not enough data for connect command')

        family, rest = self._decode_char(rest[0]), rest[1:]
        family = constants.ProtocolFamily.lookupByValue(family)

        port, rest = self._decode_u16(rest)

        if not rest:
            raise MilterCodecError('not enough data for connect command')
        address, _ = self._decode_str(rest)

        return dict(hostname=hostname, family=family, port=port,
                    address=address)

    def _decode_smfic_macro_data(self, data):
        # TODO
        cmdcode, rest = self._decode_char(data[0]), data[1:]
        nameval = self._decode_strs(rest)
        return {'cmdcode': cmdcode, 'nameval': nameval}

    def _decode_smfic_bodyeob_data(self, data):
        return {}

    def _decode_smfic_helo_data(self, data):
        return {'helo': self._decode_str(data)[0]}

    def _decode_smfic_header_data(self, data):
        args = self._decode_strs(data)
        if len(args) != 2:
            raise MilterCodecError('invalid data for header response')
        return dict(name=args[0], value=args[1])

    def _decode_smfic_mail_data(self, data):
        return {'args': self._decode_strs(data)}

    def _decode_smfic_eoh_data(self, data):
        return {}

    def _decode_smfic_rcpt_data(self, data):
        return {'args': self._decode_strs(data)}

    def _decode_smfic_quit_data(self, data):
        return {}

    def _decode_smfir_addrcpt_data(self, data):
        return {'rcpt': self._decode_str(data)[0]}

    def _decode_smfir_delrcpt_data(self, data):
        return {'rcpt': self._decode_str(data)[0]}

    def _decode_smfir_accept_data(self, data):
        return {}

    def _decode_smfir_replbody_data(self, data):
        return {'buf': self._decode_buf(data)}

    def _decode_smfir_continue_data(self, data):
        return {}

    def _decode_smfir_discard_data(self, data):
        return {}

    def _decode_smfir_addheader_data(self, data):
        args = self._decode_strs(data)
        if len(args) != 2:
            raise MilterCodecError('invalid data for addheader response')
        return {'name': args[0], 'value': args[1]}

    def _decode_smfir_chgheader_data(self, data):
        index, rest = self._decode(data, '!I')
        args = self._decode_strs(rest)
        if len(args) != 2:
            raise MilterCodecError('invalid data for chgheader response')
        return {'index': index, 'name': args[0], 'value': args[1]}

    def _decode_smfir_progress_data(self, data):
        return {}

    def _decode_smfir_quarantine_data(self, data):
        args = self._decode_strs(data)
        if len(args) != 1:
            raise MilterCodecError('invalid data for quarantine response')
        return {'reason': args[0]}

    def _decode_smfir_reject_data(self, data):
        return {}

    def _decode_smfir_tempfail_data(self, data):
        return {}

    def _decode_smfir_replycode_data(self, data):
        code, rest = self._decode(data, '3s')
        space, rest = self._decode(rest, 'c')
        args = self._decode_strs(rest)
        if len(args) != 1:
            raise MilterCodecError('invalid data for replycode response')
        return {'smtpcode': code, 'text': args[0]}

    def _decode_smfic_optneg_data(self, data):
        version, rest = self._decode(data, '!I')
        actions, rest = self._decode(rest, '!I')
        protocol, rest = self._decode(rest, '!I')
        return {'version': version, 'actions': actions, 'protocol': protocol}

    def _decode_smfic_data_data(self, data):
        return {}


