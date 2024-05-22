from scheduler import start_scheduler, job
from logger import logger

if __name__ == "__main__":
    logger.info("Starting the vulnerability fetcher service")
    job()
    start_scheduler()