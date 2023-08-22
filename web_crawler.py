import logging
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor
import argparse
import requests
from bs4 import BeautifulSoup
import os
import hashlib

PROCESSED_URLS_FILE = "processed_urls.txt"
DUPLICATE_CONTENT_CACHE_FILE = "duplicate_content_cache.txt"
keyword_found = False
KEYWORD = None  # Keyword to look for in pages
#write processed url to file
def add_to_processed_urls(url):
    with open(PROCESSED_URLS_FILE, "a") as file:
        file.write(url + "\n")
#avoid processing contents which are already processed
def add_to_duplicate_content_cache(content_hash):#hashing the content for easier comparision
    with open(DUPLICATE_CONTENT_CACHE_FILE, "a") as file:
        file.write(content_hash + "\n")

#queue for processing urls
class URLFrontier:
    def __init__(self):
        self.queue = [] #list of urls waiting to be crawled 
    
    def add(self, urls):
        for url in urls:
            if not self.is_url_processed(url):
                self.queue.append(url)#add if url not been processed 

    def get_next_url(self):
        return self.queue.pop(0) if self.queue else None #FIFO ; if queue empty return null

    @staticmethod
    def is_url_processed(url):
        if not os.path.exists(PROCESSED_URLS_FILE):
            return False #url not processed,file doesnt exist
        with open(PROCESSED_URLS_FILE, "r") as file:
            return url in file.read() #true if url in file

# Link Extractor
#parse html content and extract links
class LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        #if anchor tag , it contains hyperlinks
        if tag == "a":
            #loop thru atrributes of <a> tag
            for attr in attrs:
                #if href it contains link
                if attr[0] == "href":
                    self.links.append(attr[1])

# HTML Fetcher to fetch content
def html_fetcher(url):
    try:
        logging.info(f"Fetching content from {url}")
        #GET req
        response = requests.get(url)
        response.raise_for_status()  # Check if the request was successful
        #return response.text
        soup = BeautifulSoup(response.text, 'html.parser')
        #extract parsed HTML,concatenate with space
        text_content = soup.get_text(separator=' ')
        return text_content
    
    except requests.RequestException as e:
        logging.error(f"Error fetching {url}: {e}")
        return ""
    
#hash duplicate detection
#what is detected:exact match
#what is not:same content but diff timestamp/dynamic ad,semantic duplicates
def is_duplicate(content):
    content_hash = hashlib.md5(content.encode()).hexdigest() 
    if not os.path.exists(DUPLICATE_CONTENT_CACHE_FILE):
        return False
    with open(DUPLICATE_CONTENT_CACHE_FILE, "r") as file:
        return content_hash in file.read()
#md5-message digest algorithm hash functn that produces 16 byte hash value from ip data;but cant handle collision
DANGEROUS_DOMAINS = [
    "dangerous-example1.com",
    "malicious-example2.net",
    "phishing-example3.org"
]
def url_filter(urls):
    safe_urls = [url for url in urls if not any(dangerous_domain in url for dangerous_domain in DANGEROUS_DOMAINS)]
    return safe_urls
    


file_counter = 0
def save_to_file(url, content):
    global file_counter
    file_counter += 1
    filename = f"content_{file_counter}.txt"
    with open(filename, "w", encoding="utf-8") as file:
        file.write(url + "\n")
        file.write(content)


def worker_thread(url, max_depth, current_depth=1):
    if current_depth > max_depth:
        return

    content = html_fetcher(url)
    if is_duplicate(content):
        return

    if KEYWORD and KEYWORD in content:
        save_to_file(url, content)
        add_to_duplicate_content_cache(hashlib.md5(content.encode()).hexdigest())
    add_to_processed_urls(url)




    parser = LinkExtractor()
    parser.feed(content)
    links = url_filter(parser.links)

    with ThreadPoolExecutor() as executor:
        for link in links:
            executor.submit(worker_thread, link, max_depth, current_depth + 1)

def main():
    parser = argparse.ArgumentParser(description="Web Crawler Command Line Client")
    parser.add_argument("url", type=str, help="Starting URL for the web crawler")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Maximum depth to crawl")
    parser.add_argument("-k", "--keyword", type=str, default=None, help="Keyword to search for in pages")
    parser.add_argument("-l", "--log", action="store_true", help="Enable logging")

    args = parser.parse_args()

    global KEYWORD
    KEYWORD = args.keyword
    if KEYWORD and not keyword_found:
        print("Keyword not found.")

    if args.log:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.WARNING)

    worker_thread(args.url, max_depth=args.depth)
    #print(PAGE_CONTENT_STORAGE)

if __name__ == "__main__":
    main()

