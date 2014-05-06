import itertools
import struct

from twisted.internet.protocol import Factory, Protocol
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet import reactor
from twisted.internet import defer
from twisted.python.constants import Values
from twisted.python.constants import ValueConstant

# actions
SMFIF_ADDHDRS = 1
SMFIF_CHGBODY = 2
SMFIF_ADDRCPT = 2**2
SMFIF_DELRCPT = 2**3
SMFIF_CHGHDRS = 2**4
SMFIF_QUARANTINE = 2**5

# protocols
SMFIP_NOCONNECT = 1
SMFIP_NOHELO = 2
SMFIP_NOMAIL = 2**2
SMFIP_NORCPT = 2**3
SMFIP_NOBODY = 2**4
SMFIP_NOHDRS = 2**5
SMFIP_NOEOH = 2**6
SMFIP_NR_HDR = 2**7
SMFIP_NOHREPL = 2**7
SMFIP_NOUNKNOWN = 2**8
SMFIP_NODATA = 2**9
SMFIP_SKIP = 2*10
SMFIP_RCPT_REJ = 2*11
SMFIP_NR_CONN = 2**12
SMFIP_NR_HELO = 2**13
SMFIP_NR_MAIL = 2**14
SMFIP_NR_RCPT = 2**15
SMFIP_NR_DATA = 2**16
SMFIP_NR_UNKN = 2**17
SMFIP_NR_EOH = 2**18
SMFIP_NR_BODY = 2**19
SMFIP_HDR_LEADSPC = 2**20


class ProtocolFamily(Values):
    """ Protocol return codes for callbacks """
    SMFIA_UNKNOWN = ValueConstant('U')
    SMFIA_UNIX = ValueConstant('L')
    SMFIA_INET = ValueConstant('4')
    SMFIA_INET6 = ValueConstant('6')

    @classmethod
    def lookupByName(cls, name):
        try:
            return super(ProtocolFamily, cls).lookupByName(name)
        except ValueError:
            return cls.SMFIA_UNKNOWN

    @classmethod
    def lookupByValue(cls, value):
        try:
            return super(ProtocolFamily, cls).lookupByValue(value)
        except ValueError:
            return cls.SMFIA_UNKNOWN


class MilterCodec(object):
    # https://github.com/rothsa/ruby-milter/blob/master/lib/milter.rb
    # http://cpansearch.perl.org/src/AVAR/Sendmail-PMilter-0.98/doc/milter-protocol.txt

    VALID_CMDS = set(['SMFIC_ABORT', 'SMFIC_BODY', 'SMFIC_CONNECT',
                      'SMFIC_MACRO', 'SMFIC_BODYEOB', 'SMFIC_HELO',
                      'SMFIC_QUIT_NC', 'SMFIC_HEADER', 'SMFIC_MAIL',
                      'SMFIC_EOH', 'SMFIC_OPTNEG', 'SMFIC_RCPT', 'SMFIC_DATA',
                      'SMFIC_QUIT', 'SMFIC_UNKNOWN',
                      'SMFIR_ADDRCPT', 'SMFIR_DELRCPT', 'SMFIR_ADDRCPT_PAR',
                      'SMFIR_ACCEPT', 'SMFIR_REPLBODY', 'SMFIR_CONTINUE',
                      'SMFIR_DISCARD', 'SMFIR_CHGFROM', 'SMFIR_CONN_FAIL',
                      'SMFIR_ADDHEADER', 'SMFIR_CHGHEADER', 'SMFIR_PROGRESS',
                      'SMFIR_QUARANTINE', 'SMFIR_REJECT', 'SMFIR_SKIP',
                      'SMFIR_TEMPFAIL', 'SMFIR_REPLYCODE', 'SMFIR_SHUTDOWN',
                     ])


class MilterCodecError(Exception):
    """ Encoder/Decoder error """


class MilterMessage(MilterCodec):
    def __init__(self, cmd, data=None):
        if cmd not in self.VALID_CMDS:
            raise ValueError('invalid command %s' % cmd)
        self.cmd = cmd
        self.data = data or {}

    def __str__(self):
        return '%s<%s, %s>' % (self.__class__.__name__, self.cmd, self.data)

    __repr__ = __str__

    def __eq__(self, other):
        return (self.cmd == other.cmd
                and (sorted(self.data.iteritems())
                     == sorted(other.data.iteritems())
                    )
               )

    def __ne__(self, other):
        return (self.cmd != other.cmd
                or (sorted(self.data.iteritems())
                    != sorted(other.data.iteritems())
                   )
               )


ACCEPT = MilterMessage(cmd='SMFIR_ACCEPT')
CONTINUE = MilterMessage(cmd='SMFIR_CONTINUE')
REJECT = MilterMessage(cmd='SMFIR_REJECT')
DISCARD = MilterMessage(cmd='SMFIR_DISCARD')
TEMPFAIL = MilterMessage(cmd='SMFIR_TEMPFAIL')
SKIP = MilterMessage(cmd='SMFIR_SKIP')
CONN_FAIL = MilterMessage('SMFIR_CONN_FAIL')
SHUTDOWN = MilterMessage('SMFIR_SHUTDOWN')


class MilterEncoder(MilterCodec):
    def encode(self, msg):
        if msg.cmd not in self.VALID_CMDS:
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


class MilterDecoder(MilterCodec):
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
            raise MilterCodec('error while decoding data ("%r")' % buf)

    def decode(self):
        # a milter message is
        # uint32    len           Size of data to follow
        # char      cmd           Command/response code
        # char      data[len-1]   Code-specific data (may be empty)

        while True:
            length, rest = self._decode(''.join(self._data), '!I')
            if length is None or length == 0:
                self._data = [rest]
                break

            cmd, rest = self._decode(rest, 'c')
            if cmd is None:
                self._data = [rest]
                break

            data_len = length - 1
            if len(rest) < data_len:
                self._data = [cmd, rest]
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
        family = ProtocolFamily.lookupByValue(family)

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


class MilterProtocol(Protocol):
    def connectionMade(self):
        self.id = self.factory.getId()

    def connectionLost(self, reason):
        pass

    def onConnect(self, hostname, family, port, address):
        """ Called for each connection to the MTA. """
        return CONTINUE

    def onHelo(self, helo):
        """ Called when the SMTP client says HELO. """
        return CONTINUE

    def onOptneg(self, version, actions, protocol):
        """ Called for option negotiation. Only override if you now what you're
            doing """
        self._mta_protocols = protocol
        self._mta_actions = actions
        self._mta_version = version
        data = dict(version=self.factory.version,
                    protocol=self.factory.protocols & self._mta_protocols,
                    actions=self.factory.actions & self._mta_actions)
        return MilterMessage(cmd='SMFIC_OPTNEG', data=data)

    def onHeader(self, name, value):
        """ Called for each header field in the message body. """
        return CONTINUE

    def onEoh(self):
        """ Called at the blank line that terminates the header fields. """
        return CONTINUE

    def onBody(self, buf):
        """ Called to supply the body of the message to the Milter by chunks.
        """
        return CONTINUE

    def onEob(self):
        return CONTINUE

    def onMail(self, args):
        return CONTINUE

    def onRcpt(self, args):
        return CONTINUE

    def onMacro(self, cmdcode, nameval):
        return

    def onAbort(self):
        """ Called when the connection is abnormally terminated. """
        return CONTINUE

    def onData(self):
        return CONTINUE

    def onUnknown(self, data):
        """ Called when an unknown command is received. """
        return CONTINUE

    def onQuit(self):
        """ Called when the connection is closed. """
        return CONTINUE

    def onQuitNewConnection(self):
        """ Called when the connection is closed but a new connection follows.
        """
        return CONTINUE

    def protocol_mask(self, msg):
        """ Return mask of SMFIP_N* protocol option bits to clear for this
            class The @nocallback and @noreply decorators set the
            milter_protocol function attribute to the protocol mask bit to pass
            to libmilter, causing that callback or its reply to be skipped. """
        return CONTINUE

    def getsymval(self, msg):
        """ Return the value of an MTA macro. """
        return CONTINUE

    def setreply(self, msg):
        """ Set the SMTP reply code and message. """
        return CONTINUE

    def setsymlist(self, msg):
        """ Tell the MTA which macro names will be used. """
        return CONTINUE

    def addheader(self, msg):
        """ Add a mail header field. """
        return CONTINUE

    def chgheader(self, msg):
        """ Change the value of a mail header field. """
        return CONTINUE

    def addrcpt(self, msg):
        """ Add a recipient to the message. """
        return CONTINUE

    def delrcpt(self, msg):
        """ Delete a recipient from the message. """
        return CONTINUE

    def replacebody(self, msg):
        """ Replace the message body. """
        return CONTINUE

    def chgfrom(self, msg):
        """ Change the SMTP sender address. """
        return CONTINUE

    def quarantine(self, msg):
        """ Quarantine the message. """
        return CONTINUE

    def progress(self, msg):
        """ Tell the MTA to wait a bit longer. """
        return CONTINUE

    def _send(self, msg):
        if isinstance(msg, MilterMessage):
            data = self.factory.encoder.encode(msg)
            self.transport.write(data)
        print '---> sent %r' % msg

    def dataReceived(self, data):
        self.factory.decoder.feed(data)
        for msg in self.factory.decoder.decode():
            if msg is None:
                continue
            print '<--- received %r' % msg
            method_name = self.factory.handlerMap.get(msg.cmd, 'onUnknown')
            method = getattr(self, method_name, None)
            if method is not None:
                defer.maybeDeferred(method, **msg.data).addCallback(self._send)


class MilterFactory(Factory):

    protocol = MilterProtocol

    def __init__(self, actions=0, protocols=0):
        self.idCounter = itertools.count()
        self.actions = actions
        self.protocols = protocols
        self.version = 6
        self.encoder = MilterEncoder()
        self.decoder = MilterDecoder()

        self.handlerMap = dict(SMFIC_ABORT='onAbort',
                               SMFIC_BODY='onBody',
                               SMFIC_CONNECT='onConnect',
                               SMFIC_MACRO='onMacro',
                               SMFIC_BODYEOB='onEob',
                               SMFIC_HELO='onHelo',
                               SMFIC_QUIT_NC='onQuitNewConnection',
                               SMFIC_HEADER='onHeader',
                               SMFIC_MAIL='onMail',
                               SMFIC_EOH='onEoh',
                               SMFIC_OPTNEG='onOptneg',
                               SMFIC_RCPT='onRcpt',
                               SMFIC_DATA='onData',
                               SMFIC_QUIT='onQuit',
                               SMFIC_UNKNOWN='onUnknown',
                              )

    def getId(self):
        return next(self.idCounter)


if __name__ == '__main__':
    import sys
    from twisted.python import log

    log.startLogging(sys.stdout)
    endpoint = TCP4ServerEndpoint(reactor, 8000)
    #from twisted.internet.endpoints import UNIXServerEndpoint
    #endpoint = UNIXServerEndpoint(reactor, './collect-master.sock')

    class MyProto(MilterProtocol):
        def onHeader(self, name, value):
            print 'header received: <%s><%s>' % (name, value)
            if name == 'To' and value.startswith('discardme'):
                return DISCARD
            elif name == 'To' and value.startswith('rejectme'):
                return REJECT
            else:
                return CONTINUE
        def onBody(self, buf):
            print 'got body chunk <%s>' % buf
            return CONTINUE
        def onEob(self):
            print 'eob'
            return CONTINUE

    factory = MilterFactory()
    factory.protocol = MyProto
    endpoint.listen(factory)
    reactor.run()
