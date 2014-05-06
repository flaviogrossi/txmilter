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
SMFIP_SKIP = 2**10
SMFIP_RCPT_REJ = 2**11
SMFIP_NR_CONN = 2**12
SMFIP_NR_HELO = 2**13
SMFIP_NR_MAIL = 2**14
SMFIP_NR_RCPT = 2**15
SMFIP_NR_DATA = 2**16
SMFIP_NR_UNKN = 2**17
SMFIP_NR_EOH = 2**18
SMFIP_NR_BODY = 2**19
SMFIP_HDR_LEADSPC = 2**20


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

