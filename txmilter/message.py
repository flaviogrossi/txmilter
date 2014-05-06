from . import constants


class MilterMessage(object):
    def __init__(self, cmd, data=None):
        if cmd not in constants.VALID_CMDS:
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
