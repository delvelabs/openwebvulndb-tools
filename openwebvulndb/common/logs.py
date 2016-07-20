import logging

# create logger
logger = logging.getLogger('openwebvulndb')

logging.basicConfig(format='%(asctime)s ' + logging.BASIC_FORMAT,
                    level=logging.INFO)
