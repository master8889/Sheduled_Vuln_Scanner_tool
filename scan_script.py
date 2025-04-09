from zapv2 import ZAPv2
import time

# === ZAP Setup ===
API_KEY = '9o9j2b1ppa6vshug5r1u4lm0h6'
ZAP_PROXY = 'http://127.0.0.1:8080'
TARGET = 'http://juice-shop.herokuapp.com'

zap = ZAPv2(apikey=API_KEY, proxies={'http': ZAP_PROXY, 'https': ZAP_PROXY})

# === ZAP Scan ===
print(f"Starting scan for: {TARGET}")
zap.urlopen(TARGET)
time.sleep(2)

zap.spider.set_option_max_depth(3) 
zap.spider.exclude_from_scan(["*.jpg", "*.css", "*.png"])

# Spider scan
print("Running spider scan...")
spider_id = zap.spider.scan(TARGET)
while int(zap.spider.status(spider_id)) < 100:
    print(f"Spider progress: {zap.spider.status(spider_id)}%")
    time.sleep(2)
print("Spider scan completed.")

# Active scan
print("Running active scan...")
scan_id = zap.ascan.scan(TARGET)
while int(zap.ascan.status(scan_id)) < 100:
    print(f"Active scan progress: {zap.ascan.status(scan_id)}%")
    time.sleep(2)
print("Active scan completed.")

# Get alerts and call other modules
alerts = zap.core.alerts(baseurl=TARGET)

# Import and use other modules
from database import save_to_database
from report_generator import save_to_pdf

# Save results
save_to_database(alerts, TARGET)
save_to_pdf(alerts)