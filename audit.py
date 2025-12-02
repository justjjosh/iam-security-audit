"""
IAM Security Audit Tool
Checks AWS account for common IAM security misconfigurations
"""

import boto3
from datetime import datetime,timedelta,timezone
import json
import os
from config import MAX_ACCESS_KEY_AGE_DAYS,INACTIVE_KEY_DAYS,REPORT_FOLDER,Colors

#Initialize AWS clients
iam_client = boto3.client('iam')

# Store findings
findings = {
    'timestamp': datetime.now(timezone.utc).isoformat(),
    'users_without_mfa': [],
    'old_access_keys': [],
    'unused_access_keys': [],
    'users_with_inline_policies': [],
    'root_account_usage': []
}

#Check MFA
def check_users_without_mfa():
    """ 
    Check for IAM users without MFA enabled
    Returns:
      list: Users without MFA devices
    """
    print(f"{Colors.HEADER}Checking for users without MFA...{Colors.ENDC}")

    users_without_mfa = []

    try: 
        #Get all IAM users
        response = iam_client.list_users()
        users = response['Users']

        #Check each user
        for user in users:
            username = user['UserName']

            #Get MFA devices for this user
            mfa_devices = iam_client.list_mfa_devices(UserName=username)

            #if no MFA devices found
            if len(mfa_devices['MFADevices']) == 0:
                users_without_mfa.append({
                    'username': username,
                    'created_date': user['CreateDate'].isoformat(),
                    'severity': 'HIGH'
                })
                print(f" {Colors.WARNING}⚠{username}- No MFA{Colors.ENDC}")

        print(f"{Colors.OKGREEN}✓ MFA check complete: {len(users_without_mfa)} users without MFA{Colors.ENDC}\n")

    except Exception as e:
        print(f"{Colors.FAIL}✗Error checking MFA: {str(e)}{Colors.ENDC}\n")

    return users_without_mfa

#CHECKING FOR OLD ACCESS KEYS
def check_old_access_keys():
    """
    Find access keys older than MAX_ACCESS_KEY_AGE_DAYS
    Why this matters:
    - Old keys are security risks
    - Regular rotation limits exposure if keys are compromised - Compliance requirements often mandate key rotation
    Returns:
    list: Access keys that should be rotated
    """
    print(f"{Colors.HEADER}Checking for old access keys...{Colors.ENDC}")

    old_keys = []
    current_time = datetime.now(timezone.utc)

    try:
        #Get all users
        response = iam_client.list_users()
        users = response['Users']

        for user in users:
            username = user['UserName']

            # Get access keys for this user
            keys_response = iam_client.list_access_keys(UserName=username)
            access_keys = keys_response['AccessKeyMetadata']

            for key in access_keys:
                key_id = key['AccessKeyId']
                created_date = key['CreateDate']

                #calculate age in days
                age = current_time - created_date
                age_in_days = age.days

                if age_in_days > MAX_ACCESS_KEY_AGE_DAYS:
                    old_keys.append({
                        'username': username,
                        'access_key_id': key_id,
                        'age_days': age_in_days,
                        'created_date': created_date.isoformat(),
                        'status': key['Status'],
                        'severity': 'MEDIUM'
                    })
                    print(f" {Colors.WARNING}⚠ {username} - Key {key_id[-6:]} is {age_in_days} days old{Colors.ENDC}")

        print(f"{Colors.OKGREEN}✓ Access key age check complete: {len(old_keys)} old keys{Colors.ENDC}\n")
    
    except Exception as e:
        print(f"{Colors.FAIL}✗ Error checking access keys: {str(e)}{Colors.ENDC}\n")

    return old_keys


def check_unused_access_keys():
    """
    Find access keys not used in INACTIVE_KEY_DAYS
    Why this matters:
    - Unused keys might be forgotten/orphaned
    - If unused, should be deleted (reduce attack surface) - Indicates potential cleanup opportunity
    Returns:
    list: Access keys that haven't been used recently
    """

    print(f"{Colors.HEADER}Checking for unused access keys...{Colors.ENDC}")
    
    unused_keys = []
    current_time = datetime.now(timezone.utc)

    try:
        response = iam_client.list_users()
        users = response['Users']

        for user in users:
            username = user['UserName']

            keys_response = iam_client.list_access_keys(UserName=username)
            access_keys = keys_response['AccessKeyMetadata']

            for key in access_keys:
                key_id = key['AccessKeyId']

                #Get when key was last used
                last_used_response = iam_client.get_access_key_last_used(AccessKeyId=key_id)
                last_used_data = last_used_response.get('AccessKeyLastUsed', {})

                # Check if key has ever been used
                if 'LastUsedDate' in last_used_data:
                    last_used = last_used_data['LastUsedDate']
                    days_since_use = (current_time - last_used).days

                    if days_since_use > INACTIVE_KEY_DAYS:
                        unused_keys.append({
                            'username': username,
                            'access_key_id': key_id,
                            'last_used': last_used.isoformat(),
                            'days_since_use': days_since_use,
                            'severity': 'LOW'
                        })
                        print(f"{Colors.WARNING}⚠ {username} - Key {key_id[-6:]} unused for {days_since_use} days{Colors.ENDC}")
                    else:
                        unused_keys.append({
                            'username': username,
                            'access_key_id': key_id,
                            'last_used': 'Never',
                            'days_since_use': 'N/A',
                            'severity': 'LOW'
                        })
                        print(f" {Colors.WARNING}⚠ {username} - Key {key_id[-6:]} has never been used{Colors.ENDC}")


        print(f"{Colors.OKGREEN}✓ Unused key check complete: {len(unused_keys)} unused keys{Colors.ENDC}\n")

    except Exception as e:
        print(f"{Colors.FAIL}✗ Error checking unused keys: {str(e)}{Colors.ENDC}\n")

    return unused_keys

def generate_html_report(findings):
    """
    Generate HTML report from findings

    Args:
        findings (dict): Dictionary of all security findings

    Returns:
        str: Path to generated report file
    """
    print(f"{Colors.HEADER}Generating HTML report...{Colors.ENDC}")

    # Create reports folder if it doesn't exist
    os.makedirs(REPORT_FOLDER, exist_ok=True)

    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"{REPORT_FOLDER}/iam_audit_{timestamp}.html"

    # Count total issues
    total_issues = (
        len(findings['users_without_mfa']) +
        len(findings['old_access_keys']) +
        len(findings['unused_access_keys'])
    )

    # HTML template
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>IAM Security Audit Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background-color: #f5f5f5;
        }}
        .container {{
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #232f3e;
            border-bottom: 3px solid #ff9900;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #232f3e;
            margin-top: 30px;
        }}
        .summary {{
            background-color: #f0f0f0;
            padding: 16px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .severity-high {{
            color: #d13212;
            font-weight: bold;
        }}
        .severity-medium {{
            color: #f89000;
            font-weight: bold;
        }}
        .severity-low {{
            color: #1e8900;
            font-weight: bold;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th {{
            background-color: #232f3e;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        td {{
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .timestamp {{
            color: #666;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 IAM Security Audit Report</h1>
        <p class="timestamp">Generated: {findings['timestamp']}</p>
        
        <div class="summary">
            <h3>📊 Summary</h3>
            <p><strong>Total Issues Found:</strong> {total_issues}</p>
            <ul>
                <li>Users without MFA: {len(findings['users_without_mfa'])}</li>
                <li>Old Access Keys: {len(findings['old_access_keys'])}</li>
                <li>Unused Access Keys: {len(findings['unused_access_keys'])}</li>
            </ul>
        </div>
"""
    
    # Add MFA section
    if findings['users_without_mfa']:
        html_content += """
        <h2>❌ Users Without MFA</h2>
        <p>These users should enable MFA immediately for enhanced security.</p>
        <table>
            <tr>
                <th>Username</th>
                <th>Created Date</th>
                <th>Severity</th>
            </tr>
"""
        for user in findings['users_without_mfa']:
            html_content += f"""
            <tr>
                <td>{user['username']}</td>
                <td>{user['created_date']}</td>
                <td class="severity-high">{user['severity']}</td>
            </tr>
"""
        html_content += "</table>"
    
    # Add old keys section
    if findings['old_access_keys']:
        html_content += """
        <h2>⏰ Old Access Keys</h2>
        <p>These access keys should be rotated.</p>
        <table>
            <tr>
                <th>Username</th>
                <th>Key ID</th>
                <th>Age (days)</th>
                <th>Status</th>
                <th>Severity</th>
            </tr>
"""
        for key in findings['old_access_keys']:
            html_content += f"""
            <tr>
                <td>{key['username']}</td>
                <td>...{key['access_key_id'][-6:]}</td>
                <td>{key['age_days']}</td>
                <td>{key['status']}</td>
                <td class="severity-medium">{key['severity']}</td>
            </tr>
"""
        html_content += "</table>"
    
    # Add unused keys section
    if findings['unused_access_keys']:
        html_content += """
        <h2>🗑️ Unused Access Keys</h2>
        <p>Consider deleting these unused keys.</p>
        <table>
            <tr>
                <th>Username</th>
                <th>Key ID</th>
                <th>Last Used</th>
                <th>Days Since Use</th>
                <th>Severity</th>
            </tr>
"""
        for key in findings['unused_access_keys']:
            html_content += f"""
            <tr>
                <td>{key['username']}</td>
                <td>...{key['access_key_id'][-6:]}</td>
                <td>{key['last_used']}</td>
                <td>{key['days_since_use']}</td>
                <td class="severity-low">{key['severity']}</td>
            </tr>
"""
        html_content += "</table>"
    
    # Close HTML
    html_content += """
    </div>
</body>
</html>
"""

    # Write to file
    with open(report_filename, 'w') as f:
        f.write(html_content)
    
    print(f"{Colors.OKGREEN}✓ Report generated: {report_filename}{Colors.ENDC}")
    return report_filename

def main():
    """ 
    Main function that runs all security checks
    """
    print(f"\n{Colors.BOLD}{'='*60}{Colors.ENDC}")
    print(f"{Colors.BOLD}{'AWS IAM Security Audit Tool':^60}{Colors.ENDC}")
    print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}\n")

    #Run all checks
    findings['users_without_mfa'] = check_users_without_mfa()
    findings['old_access_keys'] = check_old_access_keys()
    findings['unused_access_keys'] = check_unused_access_keys()

    #Generate report
    report_file = generate_html_report(findings)

    #print summary
    total_issues = (
        len(findings['users_without_mfa']) +
        len(findings['old_access_keys']) +
        len(findings['unused_access_keys'])
    )

    print(f"\n{Colors.BOLD}{'='*60}{Colors.ENDC}")
    print(f"{Colors.BOLD}Audit Complete!{Colors.ENDC}")
    print(f"Total Issues Found: {total_issues}")
    print(f"Report saved to: {report_file}")
    print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}\n")

    #Also save as JSON
    json_filename = report_file.replace('.html', '.json')
    with open(json_filename, 'w') as f:
        json.dump(findings, f, indent=2)
    
    print(f"JSON report also saved to: {json_filename}\n")

#Run the script
if __name__ == "__main__":
    main()