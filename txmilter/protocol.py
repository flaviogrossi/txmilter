import itertools

from twisted.internet.protocol import Factory, Protocol
from twisted.internet import defer

from .message import MilterMessage
from .codec import MilterEncoder
from .codec import MilterDecoder


ACCEPT = MilterMessage(cmd='SMFIR_ACCEPT')
CONTINUE = MilterMessage(cmd='SMFIR_CONTINUE')
REJECT = MilterMessage(cmd='SMFIR_REJECT')
DISCARD = MilterMessage(cmd='SMFIR_DISCARD')
TEMPFAIL = MilterMessage(cmd='SMFIR_TEMPFAIL')
SKIP = MilterMessage(cmd='SMFIR_SKIP')
CONN_FAIL = MilterMessage('SMFIR_CONN_FAIL')
SHUTDOWN = MilterMessage('SMFIR_SHUTDOWN')


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

    def onEom(self):
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

    def dataReceived(self, data):
        self.factory.decoder.feed(data)
        for msg in self.factory.decoder.decode():
            if msg is None:
                continue
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
                               SMFIC_BODYEOB='onEom',
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
