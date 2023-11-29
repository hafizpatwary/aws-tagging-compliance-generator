import logging
import os
import json
from copy import deepcopy

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get all services `jq '.[]' _actions.json -r | cut -d ':' -f 1 | sort -u | sed 's/.*/"&",/'`
INCLUDE_SERVICES = [
    # "a4b",
    # "access-analyzer",
    "acm",
    "acm-pca",
    # "airflow",
    "amplify",
    "amplifyuibuilder",
    # "aoss",
    "apigateway",
    # "app-integrations",
    "appconfig",
    # "appfabric",
    # "appflow",
    # "application-autoscaling",
    "applicationinsights",
    # "appmesh",
    # "apprunner",
    # "appstream",
    # "appsync",
    # "aps",
    "athena",
    "auditmanager",
    "autoscaling",
    "aws-marketplace",
    "backup",
    "backup-gateway",
    "batch",
    "bedrock",
    # "billingconductor",
    # "braket",
    # "bugbust",
    # "cases",
    # "cassandra",
    # "ce",
    # "chime",
    # "cleanrooms",
    # "cloud9",
    "cloudformation",
    "cloudfront",
    # "cloudhsm",
    "cloudtrail",
    "cloudwatch",
    # "codeartifact",
    # "codebuild",
    # "codecatalyst",
    "codecommit",
    "codedeploy",
    # "codeguru-profiler",
    # "codeguru-reviewer",
    # "codeguru-security",
    # "codepipeline",
    # "codestar",
    # "codestar-connections",
    # "codestar-notifications",
    # "codewhisperer",
    # "cognito-identity",
    # "cognito-idp",
    # "comprehend",
    # "config",
    # "connect",
    # "connect-campaigns",
    # "databrew",
    # "dataexchange",
    # "datapipeline",
    "datasync",
    # "datazonecontrol",
    # "deepcomposer",
    # "deepracer",
    # "detective",
    # "devicefarm",
    # "directconnect",
    # "dlm",
    # "dms",
    # "docdb-elastic",
    # "drs",
    # "ds",
    "ebs",
    "ec2",
    "ecr",
    "ecr-public",
    "ecs",
    "eks",
    "elasticache",
    "elasticbeanstalk",
    "elasticfilesystem",
    "elasticloadbalancing",
    # "elasticmapreduce",
    # "elemental-activations",
    # "elemental-appliances-software",
    # "emr-containers",
    # "emr-serverless",
    # "entityresolution",
    "es",
    "events",
    # "evidently",
    # "finspace",
    "firehose",
    # "fis",
    # "fms",
    # "forecast",
    # "frauddetector",
    # "freertos",
    # "fsx",
    # "gamelift",
    # "gamesparks",
    # "geo",
    "glacier",
    # "globalaccelerator",
    "glue",
    "grafana",
    # "greengrass",
    # "groundstation",
    "guardduty",
    # "healthlake",
    "iam",
    # "imagebuilder",
    # "inspector2",
    # "internetmonitor",
    # "iot",
    # "iot1click",
    # "iotanalytics",
    # "iotdeviceadvisor",
    # "iotevents",
    # "iotfleethub",
    # "iotfleetwise",
    # "iotsitewise",
    # "iottwinmaker",
    # "iotwireless",
    # "ivs",
    # "ivschat",
    # "kafka",
    # "kendra",
    # "kendra-ranking",
    "kinesisanalytics",
    "kinesisvideo",
    "kms",
    "lambda",
    # "lex",
    # "license-manager",
    # "lightsail",
    "logs",
    # "lookoutequipment",
    # "lookoutmetrics",
    # "lookoutvision",
    # "m2",
    # "macie2",
    # "managedblockchain",
    # "mediaconvert",
    # "medialive",
    # "mediapackage",
    # "mediapackage-vod",
    # "mediapackagev2",
    # "mediastore",
    # "mediatailor",
    # "medical-imaging",
    # "memorydb",
    # "mgn",
    # "migrationhub-orchestrator",
    # "mobiletargeting",
    # "monitron",
    # "mq",
    # "network-firewall",
    # "networkmanager",
    # "nimble",
    # "notifications",
    # "notifications-contacts",
    # "oam",
    # "omics",
    # "organizations",
    # "osis",
    # "outposts",
    # "panorama",
    # "payment-cryptography",
    # "pca-connector-ad",
    # "pi",
    # "pipes",
    # "private-networks",
    # "profile",
    # "proton",
    # "purchase-orders",
    # "qldb",
    "quicksight",
    "ram",
    # "rbin",
    "rds",
    "redshift",
    "redshift-serverless",
    # "refactor-spaces",
    # "rekognition",
    # "resiliencehub",
    # "resource-explorer-2",
    # "resource-groups",
    # "robomaker",
    # "rolesanywhere",
    # "route53-recovery-control-config",
    # "route53-recovery-readiness",
    # "route53resolver",
    # "rum",
    "s3",
    "sagemaker",
    # "sagemaker-geospatial",
    # "savingsplans",
    # "scheduler",
    # "schemas",
    # "scn",
    "secretsmanager",
    # "securityhub",
    # "securitylake",
    # "servicecatalog",
    # "servicediscovery",
    # "servicequotas",
    # "ses",
    # "shield",
    # "signer",
    # "simspaceweaver",
    # "sms-voice",
    # "snow-device-management",
    "sns",
    "sqlworkbench",
    "sqs",
    "ssm",
    # "ssm-contacts",
    # "ssm-incidents",
    # "ssm-sap",
    "sso",
    "states",
    "storagegateway",
    "sts",
    "swf",
    # "synthetics",
    # "timestream",
    # "tnb",
    # "transcribe",
    # "transfer",
    # "translate",
    # "vendor-insights",
    # "voiceid",
    "vpc-lattice",
    "waf",
    "waf-regional",
    "wafv2",
    # "wellarchitected",
    # "wickr",
    # "wisdom",
    # "worklink",
    # "workmail",
    # "workspaces",
    # "workspaces-web",
    "xray"
]

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
                        "aws:RequestTag/CostCentre": "true",
                        "aws:PrincipalTag/ByassTaggingScp": "true"
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
        filtered_actions = [
            action for action in actions
            if any(action.startswith(prefix) for prefix in INCLUDE_SERVICES)
            and "Create" in action
        ]
        policies = generate_policy('all', filtered_actions, return_json=False, max_char_count=5000)
        for index, policy in enumerate(policies):
            create_policy_file(f"TagEnforcement-{index}", json.dumps(policy, indent=None), folder_name='.')
        for policy in policies:
            print(len(json.dumps(policy, indent=0)))

if __name__ == "__main__":
    main()
