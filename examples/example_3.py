
# Search for emails with a specific subject and text using regex

import re
from mail_reader import IMAPMailMonitor

monitor = IMAPMailMonitor(credentials_file="credentials.json")

email = monitor.search_mail(
    query={
        "subject": "Monthly Report",
        "text": re.compile("Total Sales: \\d+")
    },
    wait_for_match=True
)

print("Found email:", email)
