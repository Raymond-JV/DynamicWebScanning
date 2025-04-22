#!/usr/bin/env python3
import argparse
import json
import logging
import queue
import sys
from concurrent.futures import ThreadPoolExecutor
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from seleniumbase import Driver

# https://gist.github.com/alanEG/cedc7a360300a1e49b0a3c98ec30db3c#file-postmessaged-py-L4
# decorator to detect when post message listeners are added to a page 
init_script = """
    // Override addEventListener to detect 'message' handlers
    const originalAddEventListener = window.addEventListener;
    window.addEventListener = function(type, listener, options){
        if (typeof type == 'string' && type.toLowerCase() === 'message'){

            const stack = new Error();
            const stacker = stack.stack.split('\\n');
            const scriptLocation = stacker.find(line =>
                line.includes('.js') || line.includes('://')
            ) || 'Unknown location';

            console.warn(JSON.stringify({
                'type': 'detected_event_message',
                "script": scriptLocation,
                "file": window.document.currentScript.src
            }));
        }
        return originalAddEventListener.call(this, type, listener, options);
    };
"""

def setup_chrome():
    caps = DesiredCapabilities.CHROME.copy()
    caps['goog:loggingPrefs'] = {'performance': 'ALL', 'browser': 'ALL'}

    chrome_options = Options()
    chrome_options.set_capability('goog:loggingPrefs', caps['goog:loggingPrefs'])

    driver = Driver(uc=True, incognito=True, log_cdp_events=True, headless=True)
    driver.execute_cdp_cmd('Debugger.enable', {})
    driver.execute_cdp_cmd('Log.enable', {})
    driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {'source': init_script})
    driver.set_page_load_timeout(10)
    return driver

def get_network_requests(driver, filter_codes=[]):
    requests = []
    logs = driver.get_log('performance')
    events = [json.loads(entry['message'])['message'] for entry in logs]
    network_events = [event for event in events if event['method'] == 'Network.responseReceived']

    for event in network_events:
        response = event['params']['response']
        if response['status'] in filter_codes:
            continue
        requests.append({
            'url' : response['url'],
            'mime_type': response['mimeType'],
            'status' : response['status']
        })
    return requests

# https://chromedevtools.github.io/devtools-protocol/tot/Runtime/#type-ScriptId 
def get_post_message_listener_ids(driver):
    driver.execute_cdp_cmd('DOM.enable', {})
    element_info = driver.execute_cdp_cmd('Runtime.evaluate', {
        'expression': 'window'
    })
    object_id = element_info['result']['objectId']
    event_listeners = driver.execute_cdp_cmd('DOMDebugger.getEventListeners', {
        'objectId': object_id,
        'depth': -1,  # Unlimited depth
        'pierce': True  # Include shadow DOM listeners
    })
    post_message_listeners = [e for e in event_listeners['listeners'] if e['type'] == 'message']
    for listener in post_message_listeners:
        script_id = listener.get('scriptId')
        yield script_id

# returns unpacked source code
def get_script_source(driver, script_id):
    script_source = driver.execute_cdp_cmd('Debugger.getScriptSource', {
        'scriptId': script_id
    })
    return script_source

def get_post_message_listeners(driver):
    listeners = []
    logs = driver.get_log('browser')
    for log in logs:
        if 'detected_event_message' in log['message']:
            message = ''.join(log['message'].split(' ')[2:])
            message = json.loads(message)
            listeners.append(json.loads(message))
    return listeners

def capture_events(url, drivers):
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'
    logging.debug(f'capture_events {url}')
    try:
        driver = drivers.get()
        driver.get(url)
        requests = get_network_requests(driver, filter_codes=[200,201,202,204,206])
        listeners = get_post_message_listeners(driver)
        return { 'url': url, 'network_requests': requests, 'post_message_listeners': listeners }
    except TimeoutException:
        logging.info(f'{url} timed out.')
    finally: 
        driver.quit()
        driver = setup_chrome()
        drivers.put(driver)

def analyze_url_and_print(url, drivers):
    output = capture_events(url, drivers)
    if output:
        output = json.dumps(output)
        print(output)

def create_drivers(count):
    q = queue.Queue()
    for _ in range(count):
        driver = setup_chrome()
        q.put(driver)
    return q

def check_for_errors(future, url):
    try:
        result = future.result()  
    except Exception as e:
        logging.exception(f'Scanning "{url}" raised an exception: {e}')

def parse_args():
    parser = argparse.ArgumentParser(description='dynamic analysis of web pages')
    parser.add_argument('urls', nargs='?', type=argparse.FileType('r'), default=sys.stdin, help='accepts list of URLs via file or STDIN')
    parser.add_argument('-u', '--url', type=str, required=False, help='Scan single URL')
    parser.add_argument('-t', '--threads', type=int, default=1, help='Thread count defaults to 1')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    
    if args.url:
        args.urls = [args.url.strip()]
    else:
        args.urls = (url.strip() for url in args.urls)
    return args

def main():
    args = parse_args()
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        drivers = create_drivers(args.threads)
        for url in args.urls:
            future = executor.submit(analyze_url_and_print, url, drivers)
            future.add_done_callback(lambda future: check_for_errors(future, url))

if __name__ == '__main__':
    main()
