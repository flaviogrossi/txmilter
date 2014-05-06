import unittest

from txmilter import MilterMessage
from txmilter.codec import MilterEncoder
from txmilter.codec import MilterDecoder
from txmilter.constants import ProtocolFamily


class MilterCodecTest(unittest.TestCase):
    msgs = [( MilterMessage('SMFIC_ABORT'), '\x00\x00\x00\x01A' ),
            ( MilterMessage('SMFIC_BODY', dict(buf='mybody')),
              '\x00\x00\x00\x07Bmybody' ),
            ( MilterMessage('SMFIC_CONNECT',
                            dict(hostname='example.com',
                                 family=ProtocolFamily.SMFIA_INET, port=1234,
                                 address='127.0.0.1')),
              '\x00\x00\x00\x1aCexample.com\x004\x04\xd2127.0.0.1\x00' ),
            ( MilterMessage('SMFIC_BODYEOB'), '\x00\x00\x00\x01E' ),
            ( MilterMessage('SMFIC_HEADER', dict(name='to', value='me')),
              '\x00\x00\x00\x07Lto\x00me\x00' ),
            ( MilterMessage('SMFIC_HELO', dict(helo='me')),
              '\x00\x00\x00\x04Hme\x00' ),
            ( MilterMessage('SMFIC_MAIL', dict(args=['one', 'two'])),
              '\x00\x00\x00\tMone\x00two\x00' ),
            ( MilterMessage('SMFIC_EOH'), '\x00\x00\x00\x01N' ),
            ( MilterMessage('SMFIC_RCPT', dict(args=['one', 'two'])),
              '\x00\x00\x00\tRone\x00two\x00' ),
            ( MilterMessage('SMFIC_QUIT'), '\x00\x00\x00\x01Q' ),

            ( MilterMessage('SMFIR_ADDRCPT',
                            dict(rcpt='test@example.com')),
              '\x00\x00\x00\x12+test@example.com\x00' ),
            ( MilterMessage('SMFIR_DELRCPT',
                            dict(rcpt='test@example.com')),
              '\x00\x00\x00\x12-test@example.com\x00' ),
            ( MilterMessage('SMFIR_ACCEPT'), '\x00\x00\x00\x01a' ),
            ( MilterMessage('SMFIR_REPLBODY',
                            dict(buf='new\nbody\n')),
              '\x00\x00\x00\nbnew\nbody\n' ),
            ( MilterMessage('SMFIR_CONTINUE'), '\x00\x00\x00\x01c' ),
            ( MilterMessage('SMFIR_DISCARD'), '\x00\x00\x00\x01d' ),
            ( MilterMessage('SMFIR_ADDHEADER',
                            dict(name='to', value='test@example.com')),
              '\x00\x00\x00\x15hto\x00test@example.com\x00' ),
            ( MilterMessage('SMFIR_CHGHEADER',
                            dict(index=1,
                                 name='to',
                                 value='test@example.com')),
              '\x00\x00\x00\x19m\x00\x00\x00\x01to\x00test@example.com\x00'
            ),
            ( MilterMessage('SMFIR_PROGRESS'), '\x00\x00\x00\x01p' ),
            ( MilterMessage('SMFIR_QUARANTINE',
                            dict(reason='reason')),
              '\x00\x00\x00\x08qreason\x00' ),
            ( MilterMessage('SMFIR_REJECT'), '\x00\x00\x00\x01r' ),
            ( MilterMessage('SMFIR_TEMPFAIL'), '\x00\x00\x00\x01t' ),
            ( MilterMessage('SMFIR_REPLYCODE',
                            dict(smtpcode='333', text='text')),
              '\x00\x00\x00\ny333 text\x00' ),
            ( MilterMessage('SMFIC_OPTNEG',
                            dict(version=1, actions=2, protocol=3)),
              '\x00\x00\x00\rO\x00\x00\x00\x01'
              '\x00\x00\x00\x02\x00\x00\x00\x03' ),
           ]


class MilterMessageTest(unittest.TestCase):
    def test_invalid_raises_valueerror(self):
        self.assertRaises(ValueError, MilterMessage, 'NONEXISTANT')

    def test_no_data_uses_emtpy_dict(self):
        self.assertEquals(MilterMessage('SMFIC_ABORT').data, {})

    def test_messages_equality(self):
        self.assertEquals(MilterMessage('SMFIC_ABORT'),
                          MilterMessage('SMFIC_ABORT'))

        self.assertEquals(MilterMessage('SMFIC_HEADER',
                                        {'name': 'to', 'value': 'me'}),
                          MilterMessage('SMFIC_HEADER',
                                        {'value': 'me', 'name': 'to'}))

    def test_messages_inequality(self):
        self.assertNotEquals(MilterMessage('SMFIC_ABORT'),
                             MilterMessage('SMFIC_QUIT'))

        self.assertNotEquals(MilterMessage('SMFIC_HEADER',
                                           {'name': 'to', 'value': 'me'}),
                             MilterMessage('SMFIC_HEADER',
                                           {'value': 'you', 'name': 'to'}))


class MilterProtocolFamilyTest(unittest.TestCase):
    def test_lookupByName_returns_unknown_by_default(self):
        self.assertTrue(ProtocolFamily.lookupByName('NONEXISTANT')
                        is ProtocolFamily.SMFIA_UNKNOWN)

    def test_lookupByValue_returns_unknown_by_default(self):
        self.assertTrue(ProtocolFamily.lookupByValue('NONEXISTANT')
                        is ProtocolFamily.SMFIA_UNKNOWN)


class MilterDecoderTest(MilterCodecTest):
    def setUp(self):
        self.decoder = MilterDecoder()

    def test_encode_messages(self):
        for msg, encoded in self.msgs:
            self.decoder.feed(encoded)
            self.assertEquals(next(self.decoder.decode()), msg)

    def test_multiple_messages(self):
        messages = [ x[0] for x in self.msgs ]
        self.decoder.feed(''.join(x[1] for x in self.msgs))

        res = []
        for m in self.decoder.decode():
            res.append(m)

        self.assertEquals(messages, res)


class MilterEncoderTest(MilterCodecTest):
    def setUp(self):
        self.encoder = MilterEncoder()

    def test_encode_messages(self):
        for msg, encoded in self.msgs:
            self.assertEquals(self.encoder.encode(msg), encoded)
