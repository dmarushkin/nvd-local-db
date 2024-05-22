import schedule
import time
from db import engine, Base, get_db
from models import Vulnerability
from nvd_fetcher import load_all, load_last
from logger import logger

Base.metadata.create_all(bind=engine)

def job():
    logger.info("Starting scheduled job to fetch vulnerabilities")
    db = next(get_db())

    if db.query(Vulnerability.cve_id).count():
        load_last(db)
    else:
        load_all(db)

    logger.info("Scheduled job completed")

schedule.every().day.at("01:00").do(job)

def start_scheduler():
    logger.info("Starting the scheduler")
    while True:
        schedule.run_pending()
        time.sleep(1)