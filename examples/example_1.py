
# Search for unread emails with a specific subject and wait for a match

from email_monitor import EmailMonitor

monitor = EmailMonitor(credentials_file="credentials.json")

email = monitor.search_mail(
    query={"subject": "Important Meeting"},
    wait_for_match=True,
    unread=True
)

print("Found email:", email)
