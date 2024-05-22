import logging
import os

def setup_logger():
    log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    logging.basicConfig(level=log_level, format=log_format)
    logger = logging.getLogger(__name__)

    return logger

logger = setup_logger()