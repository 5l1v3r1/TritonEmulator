import logging

# gLoglevel = logging.WARN
gLoglevel = None


def get_logger(module_name, log_level=logging.DEBUG):
    global gLoglevel

    fmt = '{} %(levelname)s: %(message)s'.format(module_name)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(fmt))
    logger = logging.getLogger(module_name)
   
    if gLoglevel:
        logger.setLevel(gLoglevel)
    else:
        logger.setLevel(log_level)
    logger.addHandler(console_handler)
    return logger
