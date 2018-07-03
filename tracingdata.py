

class TracingData(object):
    def __init__(self, granularity, binaries_to_diagnose, breakpoints_addrs):
        self.granularity = granularity
        self.binaries_to_diagnose = binaries_to_diagnose
        self.breakpoints_addrs = breakpoints_addrs
