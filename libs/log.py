# -*- coding: utf-8 -*-​
import logging
from logging.handlers import TimedRotatingFileHandler


log_format = "%(asctime)s [%(levelname)s][%(threadName)s]:%(message)s"


def init_logging():
    logging.basicConfig(level=logging.INFO, format=log_format)
    logging.info("Initializing...")


def critical_errors(message):
    logging.critical(message)
    raise ValueError(message)


def debug_level(level):
    level = int(level)
    if level < 0 or level > 5:
        critical_errors("Wrong debug level.")
    if level == 0:
        level = logging.NOTSET
    elif level == 1:
        level = logging.CRITICAL
    elif level == 2:
        level = logging.ERROR
    elif level == 3:
        level = logging.WARNING
    elif level == 4:
        level = logging.INFO
    elif level == 5:
        level = logging.DEBUG
    logging.getLogger().setLevel(level)


def config_log(config):
    debug_level(config["general"]["debug"])
    if config.has_option("general", "log_file"):
        file_handler = TimedRotatingFileHandler(config["general"]["log_file"], when="w0", interval=1, backupCount=5)
        file_handler.setFormatter(logging.Formatter(log_format))
        logging.getLogger().addHandler(file_handler)
        logging.info("Using %s file to log calls" % config["general"]["log_file"])
