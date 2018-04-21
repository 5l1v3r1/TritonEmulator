import logging


"""
Define basic exception class
"""
class UnsupportArchException(Exception):
    def __init__(self, arch):
        Exception.__init__(self, "Architecture %s is not supported yet" % arch)


##############################################################################
"""
Define some basic functions
"""
def get_logger(module_name, log_level=logging.DEBUG):
    global gLoglevel

    fmt = '{} %(levelname)s: %(message)s'.format(module_name)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(fmt))
    logger = logging.getLogger(module_name)
   
    logger.setLevel(log_level)
    if not logger.handlers:
        logger.addHandler(console_handler)

    return logger


"""
Just for local debug
"""
def connectPycharm(ip, port=4444):
    try:
        import sys
        sys.path.append('/data/pydev')
        import pydevd
        pydevd.settrace(ip, port=port, stdoutToServer=True, stderrToServer=True)
    except Exception as e:
        print(e)
        print("failed to load pycharm debugger")
