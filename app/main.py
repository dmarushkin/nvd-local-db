from scheduler import start_scheduler, job
from logger import logger

if __name__ == "__main__":
    logger.info("Starting the vulnerability fetcher service")
    
    logger.info("Run job on start")
    job()

    logger.info("Scheduling job")
    start_scheduler()