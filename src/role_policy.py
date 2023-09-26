import logging
import os
import json
from copy import deepcopy

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def slice_list(actions, char_limit):
    """
    Slice a list based on a specified character count

    Args:
    actions (list[str]): A list of AWS actions.
    char_limit (num): Charachter limit

    Returns:
    list: Sliced list of lists
    """

    current_slice = []
    current_length = 0
    result = []

    for action in actions:
        if current_length + len(f'"{action}, "') <= char_limit:
            current_slice.append(action)
            current_length += len(f'"{action}, "')
        else:
            result.append(current_slice)
            current_slice = [action]
            current_length = len(action)

    if current_slice:
        result.append(current_slice)

    return result

def generate_policy(resource, actions, max_char_count=6144 ,return_json=False):
    """
    Generates an AWS policy based on a resource and a list of actions.

    Args:
    resource (str): The AWS resource.
    action (list of str): A list of AWS actions.

    Returns:
    str: The JSON representation of the generated policy.
    """
    policy_template = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": f"Deny{resource}",
                "Effect": "Deny",
                "Action": [],
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
    estimated_json = len(json.dumps(policy_template))
    max_action_char = max_char_count - estimated_json
    print(f"Char Max {max_action_char}")
    trimmed_action_list = slice_list(actions, max_action_char)

    policies = []
    for trimmed_actions in trimmed_action_list:
        policy = deepcopy(policy_template)  # Make a copy of the template
        policy["Statement"][0]["Action"] = trimmed_actions
        policies.append(policy)

    return json.dumps(policies, indent=0) if return_json else policies

def create_policy_file(file_name, content, file_extention='.json', folder_name='policies'):
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
    with open('_actions.json', 'r') as f:
        actions = json.load(f)
        policies = generate_policy('all', actions, return_json=False)
        for index, policy in enumerate(policies):
            create_policy_file(index, json.dumps(policy, indent=None))
        for policy in policies:
            print(len(json.dumps(policy, indent=0)))

if __name__ == "__main__":
    main()
