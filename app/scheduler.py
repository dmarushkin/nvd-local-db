import schedule
import time
from db import engine, Base, get_db
from nvd_fetcher import load_all
from logger import logger

Base.metadata.create_all(bind=engine)

def job():
    logger.info("Starting scheduled job to fetch vulnerabilities")
    db = next(get_db())
    load_all(db)
    logger.info("Scheduled job completed")

schedule.every().day.at("20:04").do(job)

def start_scheduler():
    logger.info("Starting the scheduler")
    while True:
        schedule.run_pending()
        time.sleep(1)