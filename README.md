# IAM Security Audit Tool

Automated security auditing tool for AWS IAM configurations. Identifies common security misconfigurations and generates comprehensive reports.

## Features

- ✅ Detects users without MFA enabled
- ✅ Identifies access keys older than 90 days
- ✅ Finds unused access keys (30+ days inactive)
- ✅ Generates professional HTML and JSON reports
- ✅ Color-coded terminal output for easy reading
- ✅ Configurable security thresholds
- ✅ Error handling for AWS API calls

## Prerequisites

- Python 3.7 or higher
- AWS Account with IAM access
- AWS credentials configured locally
- Git (for version control)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/YOUR-USERNAME/iam-security-audit.git 
cd iam-security-audit
```

2. Create virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate # On Windows: venv\Scripts\activate
 ```

3. Install dependencies: 
```bash
pip install -r requirements.txt
```

4. Configure AWS credentials: 
```bash
aws configure
```

## Usage
Run the audit: 
python audit.py

view the report:
open reports/iam_audit_*.html

## Configuration

Edit 'config.py' to customise:

MAX_ACCESS_KEY_AGE_DAYS = 90 # Maximum age for access keys

NACTIVE_KEY_DAYS = 30 # Days before key considered inactive

## Required IAM Permissions

The AWS credentials need these permissions: json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:ListUsers",
                "iam:ListMFADevices",
                "iam:ListAccessKeys",
                "iam:GetAccessKeyLastUsed"
            ],
            "Resource": "*"
        }
    ]
}

## Contributing
Contributions welcome! Please open an issue or submit a pull request.

## Author
RAJI OLATUBOSUN JOSHUA
- GitHub: [justjjosh](https://github.com/justjjosh)
- LinkedIn: [Raji Olatubosun Joshua](https://www.linkedin.com/in/olatubosun-joshua-raji-25a561254/)


## Acknowledgments
- Built as part of AWS security learning journey
- Inspired by AWS security best practices