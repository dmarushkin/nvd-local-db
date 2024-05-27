import time
from datetime import datetime, timedelta
import nvdlib
from sqlalchemy.orm import Session
from models import Vulnerability
from logger import logger


def generate_month_ranges(start_year=1990, end_year=None):
    if end_year is None:
        end_year = datetime.now().year
        
    current_date = datetime(start_year, 1, 1)
    end_date = datetime(end_year + 1, 1, 1)
    
    month_ranges = []
    while current_date < end_date:
        from_date = current_date.strftime('%Y-%m-%d')
        next_month = current_date.month + 3
        next_year = current_date.year
        if next_month > 12:
            next_month = 1
            next_year += 1
        to_date = current_date.replace(year=next_year, month=next_month).strftime('%Y-%m-%d')
        month_ranges.append((from_date, to_date))
        current_date = current_date.replace(year=next_year, month=next_month)
        
    return month_ranges

def load_all(db: Session):

    date_ranges = generate_month_ranges()

    for from_date, to_date in reversed(date_ranges):
        fetch_and_store_vulnerabilities(db, from_date, to_date, load_all=True)
        time.sleep(30)

def load_last(db: Session):

    from_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
    to_date = datetime.now().strftime('%Y-%m-%d')

    fetch_and_store_vulnerabilities(db, from_date, to_date)

def fetch_and_store_vulnerabilities(db: Session, from_date: str, to_date: str, load_all: bool = False):

    logger.info(f"Fetching vulnerabilities from {from_date} to {to_date}")
    
    results = []
    
    for i in range(3):
        while True:
            try:
                if load_all:
                    results = nvdlib.searchCVE(
                        pubStartDate=f'{from_date} 00:00',
                        pubEndDate=f'{to_date} 00:00'
                    )
                else:
                    results = nvdlib.searchCVE(
                        lastModStartDate=f'{from_date} 00:00',
                        lastModEndDate=f'{to_date} 00:00'
                    )
            except Exception as e:
                logger.error(f"Error in fetch results for {from_date} {to_date}, attempt {i}")
                continue
            break

    for item in results:

        logger.debug(f"Processing CVE {item.id}")

        existing_vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == item.id).first()
        
        if existing_vuln:

            existing_vuln.description = item.descriptions[0].value
            existing_vuln.url = item.url
            existing_vuln.published_date = item.published
            existing_vuln.last_modified_date = item.lastModified
            existing_vuln.weaknesses = [e.description[0].value for e in getattr(item, 'weaknesses', [])]
            existing_vuln.references = [e.url for e in getattr(item, 'references', [])]
            existing_vuln.cpe = [e.criteria for e in getattr(item, 'cpe', [])]
            existing_vuln.score = item.score[1]
            existing_vuln.severity = item.score[2]
            existing_vuln.v31score = getattr(item, 'v31score', None)
            existing_vuln.v30score = getattr(item, 'v30score', None)
            existing_vuln.v2score = getattr(item, 'v2score', None)
            existing_vuln.cvssV2Severity = getattr(item, 'v2severity', None)
            existing_vuln.cvssV3Severity = getattr(item, 'v31severity', None)
            existing_vuln.cisaExploitAdd = getattr(item, 'cisaExploitAdd', None) 
            existing_vuln.cisaRequiredAction = getattr(item, 'cisaRequiredAction', None)
            existing_vuln.cisaActionDue = getattr(item, 'cisaActionDue', None)
            existing_vuln.v31impactScore = getattr(item, 'v31impactScore', None)
            existing_vuln.v30impactScore = getattr(item, 'v30impactScore', None)
            existing_vuln.v2impactScore = getattr(item, 'v2impactScore', None)
            existing_vuln.v31exploitability = getattr(item, 'v31exploitability', None)
            existing_vuln.v2exploitability = getattr(item, 'v2exploitability', None)
            existing_vuln.v31attackVector = getattr(item, 'v31attackVector', None)
            existing_vuln.v2accessVector = getattr(item, 'v2accessVector', None)
            existing_vuln.v31attackComplexity = getattr(item, 'v31attackComplexity', None)
            existing_vuln.v2accessComplexity = getattr(item, 'v2accessComplexity', None)
            existing_vuln.v31privilegesRequired = getattr(item, 'v31privilegesRequired', None)
            existing_vuln.v31userInteraction = getattr(item, 'v31userInteraction', None)
            existing_vuln.v31scope = getattr(item, 'v31scope', None)
            existing_vuln.v2authentication = getattr(item, 'v2authentication', None)
            existing_vuln.v31confidentialityImpact = getattr(item, 'v31confidentialityImpact', None)
            existing_vuln.v2confidentialityImpact = getattr(item, 'v2confidentialityImpact', None)
            existing_vuln.v31integrityImpact = getattr(item, 'v31integrityImpact', None)
            existing_vuln.v2integrityImpact = getattr(item, 'v2integrityImpact', None)
            existing_vuln.v31availabilityImpact = getattr(item, 'v31availabilityImpact', None)
            existing_vuln.v2availabilityImpact=getattr(item, 'v2availabilityImpact', None)

            logger.info(f"Updated CVE {item.id}")

        else: 


            vuln = Vulnerability(
                cve_id=item.id,
                description=item.descriptions[0].value,
                url=item.url,
                published_date=item.published,
                last_modified_date=item.lastModified,
                weaknesses=[e.description[0].value for e in getattr(item, 'weaknesses', [])],
                references=[e.url for e in getattr(item, 'references', [])],
                cpe=[e.criteria for e in getattr(item, 'cpe', [])],
                score=item.score[1],
                severity=item.score[2],
                v31score=getattr(item, 'v31score', None),
                v30score=getattr(item, 'v30score', None),
                v2score=getattr(item, 'v2score', None),
                cvssV2Severity=getattr(item, 'v2severity', None),
                cvssV3Severity=getattr(item, 'v31severity', None),
                cisaExploitAdd=getattr(item, 'cisaExploitAdd', None), 
                cisaRequiredAction=getattr(item, 'cisaRequiredAction', None),
                cisaActionDue=getattr(item, 'cisaActionDue', None),
                v31impactScore=getattr(item, 'v31impactScore', None),
                v30impactScore=getattr(item, 'v30impactScore', None),
                v2impactScore=getattr(item, 'v2impactScore', None),
                v31exploitability=getattr(item, 'v31exploitability', None),
                v2exploitability=getattr(item, 'v2exploitability', None),
                v31attackVector=getattr(item, 'v31attackVector', None),
                v2accessVector=getattr(item, 'v2accessVector', None),
                v31attackComplexity=getattr(item, 'v31attackComplexity', None),
                v2accessComplexity=getattr(item, 'v2accessComplexity', None),
                v31privilegesRequired=getattr(item, 'v31privilegesRequired', None),
                v31userInteraction=getattr(item, 'v31userInteraction', None),
                v31scope=getattr(item, 'v31scope', None),
                v2authentication=getattr(item, 'v2authentication', None),
                v31confidentialityImpact=getattr(item, 'v31confidentialityImpact', None),
                v2confidentialityImpact=getattr(item, 'v2confidentialityImpact', None),
                v31integrityImpact=getattr(item, 'v31integrityImpact', None),
                v2integrityImpact=getattr(item, 'v2integrityImpact', None),
                v31availabilityImpact=getattr(item, 'v31availabilityImpact', None),
                v2availabilityImpact=getattr(item, 'v2availabilityImpact', None)
            )

            db.add(vuln)

            logger.info(f"Added new CVE {item.id}")
    
    db.commit()
    logger.info(f"Completed fetching and storing {len(results)} vulnerabilities ")