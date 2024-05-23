# NVD Vulnerabilities Store Service

Get CVE vulnerabilities info from NVD api and store in local postgres db 
On first start it loads all CVEs from 1990, next runs update insert only CVEs created or changed last week.

# Build and start service

To run it local you just need docker compose. Set your DB private DB password in .env file and start services (app and db docker conteiners):

```
docker-compose up --build
```

For prod environments feel free to bake Docker image from app folder as you like ;)
