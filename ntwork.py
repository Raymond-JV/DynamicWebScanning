#!/usr/bin/env python3

import argparse
import json
import sys
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

def process_browser_log_entry(entry):
    log = json.loads(entry["message"])["message"]
    return log

def setup_chrome():
    caps = DesiredCapabilities.CHROME.copy()
    caps["goog:loggingPrefs"] = {"performance": "ALL"}
    chrome_options = Options()
    chrome_options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
    driver = webdriver.Chrome(options=chrome_options)
    return driver

def capture_network_requests(url):
    driver = setup_chrome()
    driver.get(url)
    browser_log = driver.get_log('performance')
    events = [process_browser_log_entry(entry) for entry in browser_log]
    sys.stdout.write(json.dumps(events))
    network_events = [event for event in events if event['method'] == 'Network.responseReceived']
    
    responses = []
    for event in network_events:
        response = event.get("params", {}).get("response", {})
        
        http_info = {'url' : response['url'], 'status' : response['status']}
        responses.append(http_info)
    return responses

def main():
    parser = argparse.ArgumentParser(description="Capture network requests using performance logs")
    parser.add_argument("url", help="The URL of the webpage to monitor network activity")
    args = parser.parse_args()
    responses = capture_network_requests(args.url)
    for response in responses:
        pass
        """
        print(f'{response["url"]} {response["status"]}')
        """

if __name__ == "__main__":
    main()
