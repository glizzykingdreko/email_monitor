
# Wait for an OTP code from a specific website and prints it

import re
from email_monitor import EmailMonitor

monitor = EmailMonitor(credentials_file="credentials.json")

email = monitor.search_mail(
    query={
        "from": "no-reply@your-website.com",
        # "to": "your_mail@gmail.com", # In case u are using a catchall xD
        "subject": "Your OTP Code",
        "text": re.compile("Your OTP Code is: \\d{6}")
    },
    wait_for_match=True
)

# Extract the OTP code using regex
otp_code = re.search("Your OTP Code is: (\\d{6})", email).group(1)

print("Found OTP code:", otp_code)
