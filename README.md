# Email Monitor

![Banner](https://i.imgur.com/pFl6QI0.png)
![PyPI](https://img.shields.io/pypi/v/email-monitor)

Email Monitor is a Python module designed for monitoring and searching emails using the IMAP protocol. It is particularly useful for tasks such as OTP code scraping for web automation, email parsing, and email notifications. 

This module is primarily focused on Gmail using OAuth2 for authentication, but it can also work with other IMAP email providers. It is currently in beta, so please report any bugs or issues you encounter, I would greatly appreciate it!

## Installation

You can install the Email Monitor module using pip:
```bash
pip install email-monitor
```

## What is this module?

The Email Monitor module is a Python library that enables you to efficiently search, parse, and monitor emails in your mailbox. By providing an intuitive interface for email handling, this module simplifies the process of obtaining specific information from your emails, such as OTP codes, notifications, or important updates.

## Use Cases

Some of the key use cases for this module include:

- **Automatically retrieving OTP codes** sent to your email for web automation tasks
- **Parsing email content** to extract relevant data or notifications
- **Monitoring your mailbox for specific emails**, such as those containing a particular subject, sender, or content

## Supported IMAP Providers

Email Monitor is primarily designed to work with Gmail using OAuth2 authentication, but it can also support other IMAP email providers. To set up Gmail OAuth2 authentication, follow these steps:

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Navigate to "APIs & Services" > "Library" and enable the "Gmail API"
4. Navigate to "APIs & Services" > "Credentials" and create a new "OAuth 2.0 Client ID"
5. Download the `credentials.json` file for your newly created OAuth 2.0 client

## Example

Here's a quick example of how to use the Email Monitor module:

```python
from email_monitor import EmailMonitor
import re

monitor = EmailMonitor(credentials_file="credentials.json")
email = monitor.search_mail(
    query={
        "subject": "Your OTP Code",
        "from": "noreply@example.com",
        "text": re.compile("OTP: \d{6}")
    },
    wait_for_match=True,
    unread=True,
    labels=["INBOX"],
    delay=10
)
print(email)
```
Take a look at the [examples](./examples/) folder for more examples of how to use this module.

## Search Mail Parameters

The `search_mail` function has several parameters that can be used to customize your search:

- `query` (dict): A dictionary containing the search query. The keys are the search parameters and the values are the search terms. Regex is supported.
  Example: `{"subject": "Hello", "from": "John Doe", "to": "myOtherMail@gmail.com", "text": re.compile("Hello World")}`

- `wait_for_match` (bool): If set to True, the function will wait for a new email to match the query and return it.

- `unread` (bool): If set to True, the function will search for emails that have already been read.

- `labels` (list): A list of labels to search for. Only works with Gmail.

- `delay` (int): The delay in seconds between each search if `wait_for_match` is set to True.

## Contributing

Contributions are welcome! Feel free to submit pull requests with bug fixes or new features. Check out the [contributing guidelines](./CONTRIBUTING.md) for more information.

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

## Contact Me

If you have any questions or suggestions, feel free to reach out to me:

- GitHub: [glizzykingdreko](https://github.com/glizzykingdreko)
- Medium: [glizzykingdreko](https://medium.com/@glizzykingdreko)
- Twitter: [glizzykingdreko](https://twitter.com/glizzykingdreko)
- Email: glizzykingdreko@protonmail.com
