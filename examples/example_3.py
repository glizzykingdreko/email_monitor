
# Search for emails with a specific subject and text using regex

import re
from email_monitor import EmailMonitor

monitor = EmailMonitor(credentials_file="credentials.json")

email = monitor.search_mail(
    query={
        "subject": "Monthly Report",
        "text": re.compile("Total Sales: \\d+")
    },
    wait_for_match=True
)

print("Found email:", email)
