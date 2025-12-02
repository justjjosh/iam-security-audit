"""
Configuration settings for IAM Security Audit
"""
#Security thresholds
MAX_ACCESS_KEY_AGE_DAYS = 90 #Flag keys older than this
INACTIVE_KEY_DAYS = 30 #Flag keys not used in this many days

#Report settings
REPORT_FOLDER = "reports"
REPORT_FORMAT = "html"

# Colors for terminal output (optional) 
class Colors:
    """ANSI color codes for terminal output""" 
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m' 
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m' # Reset to default 
    BOLD = '\033[1m'
