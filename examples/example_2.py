
# Search for emails from a specific sender and wait for a match

from email_monitor import EmailMonitor

monitor = EmailMonitor(credentials_file="credentials.json")

email = monitor.search_mail(
    query={"from": "jane.doe@example.com"},
    wait_for_match=True
)

print("Found email:", email)
