import requests
from bs4 import BeautifulSoup
import logging
import re
import os
import json

DESIRED_CONDITION = 'aws:RequestTag/${TagKey}'
TOPICS_URL = "https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html"
BASE_URL = "https://docs.aws.amazon.com/en_us/service-authorization/latest/reference/"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fetch_page(url):
    """
    Fetches a web page and returns the response object.

    Args:
    url (str): The URL of the web page to fetch.

    Returns:
    requests.Response or None: The response object if the request is successful, otherwise None.
    """
    response = requests.get(url)
    return response if response.status_code == 200 else None

def extract_topics_and_links(soup):
    """
    Extracts topics and links from a BeautifulSoup object representing a web page.

    Args:
    soup (BeautifulSoup): The BeautifulSoup object representing a web page.

    Returns:
    list of str: A list of topic URLs.
    """
    topics = []
    
    for h6 in soup.find_all('h6'):
        ul = h6.find_next('ul')
        logger.debug(ul)
        
        if ul:
            topics.extend([a['href'] for a in ul.find_all('a')])
            logger.debug(topics)
    
    return topics

def process_topic_page(topic_url, desired_condition):
    """
    Processes a topic page, extracts service-related information, and filters actions.

    Args:
    topic_url (str): The URL of the topic page to process.
    desired_condition (str): The desired condition to filter actions.

    Returns:
    tuple of str, str, list of str: A tuple containing the service name, service prefix, and filtered actions.
    """
    response = fetch_page(topic_url)
    logger.debug(f"Processing {topic_url}")
    pattern = r'list_(.*?)\.html'
    logger.info(topic_url)
    match = re.search(pattern, topic_url)
    service = match.group(1)
    logger.debug(service)

    if response:
        soup = BeautifulSoup(response.text, 'html.parser')
        code_block = soup.find('code')
        service_prefix = code_block.text.strip()
        logger.debug(f"Filtering actions for {service_prefix} with desired condition {desired_condition}")
        tables = soup.find_all('table')
        filtered_actions = []

        def process_row(cells):
            for cell in cells:
                if desired_condition in cell.text:
                    logger.debug(f"Service: {service_prefix} Actions: {action}")
                    filtered_actions.append(f"{service_prefix}:{action}")
        
        if tables:
            table = tables[0]
            rows = table.find_all('tr')
            
            i = 1  # Skipping table header
            while i < len(rows):
                cells = rows[i].find_all('td')
                action = cells[0].text.strip().split()[0]
                
                if 'rowspan' in cells[0].attrs:
                    rowspan = int(cells[0]['rowspan'])
                    for _ in range(rowspan - 1):
                        cells = rows[i].find_all('td')
                        process_row(cells)
                        i += 1
                else:
                    process_row(cells)
                i += 1
        return service, service_prefix, filtered_actions

def generate_policy(resource, action):
    """
    Generates an AWS policy based on a resource and a list of actions.

    Args:
    resource (str): The AWS resource.
    action (list of str): A list of AWS actions.

    Returns:
    str: The JSON representation of the generated policy.
    """
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": f"Deny{resource}",
                "Effect": "Deny",
                "Action": action,
                "Resource": "*",
                "Condition": {
                    "Null": {
                        "aws:RequestTag/team": "true",
                        "aws:RequestTag/cost-centre": "true"
                    }
                }
            }
        ]
    }
    return json.dumps(policy, indent=2)

def create_file(file_name, content, file_extention='.json', folder_name='policies'):
    """
    Create a file with the given name and content inside a subfolder.

    Args:
    folder_name (str): Name of the subfolder.
    file_name (str): Name of the file to be created.
    content (str): Content to be written to the file.

    Returns:
    str: The path to the created file.
    """
    # Create the subfolder if it doesn't exist
    subfolder_path = os.path.join(os.getcwd(), folder_name)
    if not os.path.exists(subfolder_path):
        os.makedirs(subfolder_path)
        logger.debug(f'Created folder: {subfolder_path}')

    # Create and write to the file
    file_path = os.path.join(subfolder_path, f'{file_name}{file_extention}')
    with open(file_path, 'w') as file:
        file.write(content)

    return file_path

def main():
    page_response = fetch_page(TOPICS_URL)

    if page_response:
        soup = BeautifulSoup(page_response.text, 'html.parser')
        topics = extract_topics_and_links(soup)

        service_actions_filtered = {}
        combined_actions =[]
        topics()
        for index, topic in enumerate(topics):
            # if index >= 15:
            #     break

            topic_url = f'{BASE_URL}{topic}'
            service, service_prefix, actions = process_topic_page(topic_url, DESIRED_CONDITION)
            logger.debug(f"Service: {service} Actions: {actions}")
            service_actions_filtered[service] = {'prefix': service_prefix, 'actions': actions}
            combined_actions += actions
            print("---------------------START---------------------")
            print(f"{service}, {service_prefix}, {actions}")
            print("---------------------END---------------------")
        logger.debug(service_actions_filtered)
        # actions = [action for value in service_actions_filtered.values() for action in value["actions"]]
        create_file("_actions", json.dumps(combined_actions, indent=2), folder_name='.')
        for resource, value in service_actions_filtered.items():
            actions = value['actions']
            service_prefix = value['prefix']
            if actions:
                policy = generate_policy(service_prefix, actions)
                create_file(resource, policy, folder_name='policies')

    else:
        logger.error(f"Failed to retrieve the page (Status Code: {page_response.status_code})")

if __name__ == "__main__":
    main()

