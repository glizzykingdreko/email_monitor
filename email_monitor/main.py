import imaplib, os, re, email, pickle
from logging import getLogger, Logger, DEBUG, StreamHandler, Formatter
from typing import Union, Dict
from time import sleep
from base64 import b64decode

from .exceptions import InvalidCredentialsError, CredentialFileRequiredError, \
    EmailMonitorConnectionError, CredentialFileInvalidError

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Lazy imports for Google API (only when needed)
InstalledAppFlow = None
Request = None
build = None

def _load_google_api():
    """Lazy load Google API libraries."""
    global InstalledAppFlow, Request, build
    if InstalledAppFlow is None:
        from google_auth_oauthlib.flow import InstalledAppFlow as _InstalledAppFlow
        from google.auth.transport.requests import Request as _Request
        from googleapiclient.discovery import build as _build
        InstalledAppFlow = _InstalledAppFlow
        Request = _Request
        build = _build

class EmailMonitor:
    def __init__(
        self, 
        service: str = None, 
        user: str = None, 
        password: str = None, 
        credentials_file: str = None,
        logger: Logger = False
    ):
        """
        # EmailMonitor
        This class lets you monitor an IMAP mailbox for new emails.
        Quickly search for emails by subject, from, or text with regex support aswell and different search options.

        ### Supported services
        - Generic IMAP
        - Gmail (with Google API)

        ## Parameters
        - `service`: str
            The service to connect to. Currently only supports "gmail" and "protonmail".
        - `user`: str
            The username of the mailbox to connect to.
        - `password`: str
            The password of the mailbox to connect to.
        - `credentials_file`: str
            The path to the credentials file for the Google API. If this is provided, the service parameter is ignored.
        

        ## Raises
        - `EmailMonitorConnectionError`
            Raised when there's an error while connecting to the mailbox.
        - `InvalidCredentialsError`
            Raised when the credentials are invalid.
        - `CredentialFileRequiredError`
            Raised when the credentials file is required.
        - `CredentialFileInvalidError`
            Raised when the credentials file is invalid.

        ## Methods
        - `search_mail(query, wait_for_match=True, delay=3)`
            Search for emails in the mailbox.
        
        ### Parameters
        - `query`: dict
            A dictionary containing the search query. The keys are the search parameters and the values are the search terms. Regex is supported.
            Example: {"subject": "Hello", "from": "John Doe", "to": "myOtherMail@gmail.com", "text": re.compile("Hello World")}
        - `wait_for_match`: bool
            If set to True, the function will wait for a new email to match the query and return it.
        - `unread`: bool
            If set to True, the function will only search for unread emails.
        - `label`: list
            A list of labels to search for emails in.
        - `delay`: int
            The delay in seconds between each search attempt if wait_for_match is set to True.
        
        ### Returns
        - `Union[dict, None]`
            A dictionary containing the email data if a match was found, otherwise None.
        
        ## Example
        ```python
        from mail_reader import EmailMonitor
        import re

        monitor = EmailMonitor(credentials_file="credentials.json")
        email = monitor.search_mail(
            query={"subject": "Hello", "from": "John Doe", "text": re.compile("Hello World")},
            wait_for_match=True
        )
        print(email)
        ```
        """
        if not logger:
            self.logger = getLogger("EmailMonitor")
            self.logger.setLevel(DEBUG)
            self.logger.addHandler(StreamHandler())
            formatter = Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            self.logger.handlers[0].setFormatter(formatter)

        else:
            self.logger = logger
        
        self.gmail_auth = bool(credentials_file)
        self.logger.info(f"Initializing {self.__class__.__name__}...")
        if self.gmail_auth:
            _load_google_api()  # Load Google API libraries
            self.logger.info(f"Using Google API with credentials file {credentials_file}")
            self.user = user
            self.credentials_file = credentials_file
            self.credentials = self.get_credentials()
        else:
            self.logger.info(f"Using IMAP with service {service} and user {user}")
            self.host = self.get_host_by_service(service)
            self.user = user
            self.password = password
            self.connect()
    
    def get_host_by_service(self, service: str) -> str:
        """
        Get the host for a given service.

        Args:
            service (str): The service to get the host for.

        Returns:
            str: The host for the given service.
        """
        service_hosts = {
            "gmail": "imap.gmail.com",
            "protonmail": "imap.protonmail.com",
            # Add more services here
        }
        return service_hosts.get(service) or service # If the service is not in the dict, return the service name

    def get_credentials(self) -> object:
        """
        Get the credentials for the Google API.

        Returns:
            object: The credentials for the Google API.
        """
        creds = None
        try:
            if os.path.exists('token.pickle'):
                self.logger.info("Loading saved credentials...")
                with open('token.pickle', 'rb') as token:
                    creds = pickle.load(token)
        except Exception as e:
            self.logger.error(f"Error while loading saved credentials: {e}")
            pass

        try:
            if not creds or not creds.valid:
                self.logger.info("Getting credentials...")
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                else:
                    flow = InstalledAppFlow.from_client_secrets_file(self.credentials_file, SCOPES)
                    creds = flow.run_local_server(port=1113)
                with open('token.pickle', 'wb') as token:
                    pickle.dump(creds, token)
        except Exception as e:
            self.logger.error(f"Error while getting credentials: {e}")
            raise CredentialFileInvalidError("The credentials file is invalid.") from e
        return creds

    def connect(self):
        """
        Connect to the mailbox.
        
        Raises:
            EmailMonitorConnectionError: Raised when there's an error while connecting to the mailbox.
            CredentialFileRequiredError: Raised when the credentials file is required.
        """
        try: 
            if not self.gmail_auth:
                self.logger.info("Connecting to the mailbox...")
                self.mailbox = imaplib.IMAP4_SSL(self.host)
                self.mailbox.login(self.user, self.password)
        except imaplib.IMAP4.error as e:
            if 'https://support.google.com/accounts/answer/185833' in str(e):
                raise CredentialFileRequiredError("The credentials file is required for your Gmail account.") from e
            self.logger.error(f"Error while connecting to the mailbox: {e}")
            raise EmailMonitorConnectionError("There was an error while connecting to the mailbox.") from e
        except Exception as e:
            self.logger.error(f"Error while connecting to the mailbox: {e}")
            raise InvalidCredentialsError("The credentials file is invalid.") from e

    def disconnect(self):
        """
        Disconnect from the mailbox.
        """
        if not self.gmail_auth:
            self.logger.info("Disconnecting from the mailbox...")
            self.mailbox.logout()
    
    def _get_email_body(self, email_message) -> str:
        """
        Extract the body text from an email message, handling multipart emails
        and various encodings.
        
        Args:
            email_message: An email.message.Message object
            
        Returns:
            str: The decoded email body text
        """
        body = ""
        
        if email_message.is_multipart():
            for part in email_message.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                
                # Skip attachments
                if "attachment" in content_disposition:
                    continue
                    
                # Get text content (prefer plain text)
                if content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        try:
                            body = payload.decode(charset, errors='replace')
                        except (LookupError, UnicodeDecodeError):
                            body = payload.decode('utf-8', errors='replace')
                        break
                elif content_type == "text/html" and not body:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        try:
                            body = payload.decode(charset, errors='replace')
                        except (LookupError, UnicodeDecodeError):
                            body = payload.decode('utf-8', errors='replace')
        else:
            payload = email_message.get_payload(decode=True)
            if payload:
                charset = email_message.get_content_charset() or 'utf-8'
                try:
                    body = payload.decode(charset, errors='replace')
                except (LookupError, UnicodeDecodeError):
                    body = payload.decode('utf-8', errors='replace')
        
        return body
    
    def search_mail(
        self, 
        query: Dict[str, Union[str, re.Pattern]],
        wait_for_match: bool = False,
        unread: bool = True,
        mark_as_read: bool = True,
        labels: list = [],
        delay: int = 5
    ) -> Union[str, None]:
        """
        Search for emails in the mailbox.

        Args:
            `query`: dict
                A dictionary containing the search query. The keys are the search parameters and the values are the search terms. Regex is supported.
                Example: {"subject": "Hello", "from": "John Doe", "to": "myOtherMail@gmail.com", "text": re.compile("Hello World")}
            `wait_for_match`: bool
                If set to True, the function will wait for a new email to match the query and return it.
            `unread`: bool
                If set to True, the function will only search for unread emails.
            `mark_as_read`: bool
                If set to True (default), the matched email will be marked as read.
            `labels`: list
                A list of labels to search for. Only works with Gmail API.
            `delay`: int
                The delay in seconds between each search if `wait_for_match` is set to True.
        
        Returns:
            Union[str, None]: The email body if match is found, None otherwise.
        """
        self.logger.debug(f"Searching for emails with query {query} / {wait_for_match=} / {unread=} / {labels=} / {delay=}")
        while 1:
            try:
                self.logger.info("Searching for emails...")
                if self.gmail_auth:
                    # Gmail API
                    service = build('gmail', 'v1', credentials=self.credentials)
                    search_criteria = []

                    if unread:
                        search_criteria.append('is:unread')
                    # Note: Gmail API doesn't have a direct 'is:read' filter, we just don't filter by read status
                    for key, value in query.items():
                        if key.lower() in ["subject", "from", "to"]:
                            search_criteria.append(f'{key.lower()}:"{value}"')
                    
                    search_query = ' '.join(search_criteria)
                    response = service.users().messages().list(userId='me', q=search_query, maxResults=50).execute()
                    msg_ids = response.get('messages', [])

                    if msg_ids:
                        msg_id = msg_ids[0]
                        msg_data = service.users().messages().get(userId='me', id=msg_id['id']).execute()
                        '''
                        Example of msg_data:
                        {
                            'id': '...',
                            'threadId': '...',
                            'labelIds': [
                                'UNREAD',
                                'IMPORTANT',
                                'CATEGORY_PERSONAL',
                                'INBOX'
                            ],
                            'snippet': 'Aaaaaaaa Inviato con l&#39;email sicura di Proton Mail.',
                            'payload': {
                                'partId': '',
                                'mimeType': 'multipart/alternative',
                                'filename': '',
                                'headers': [
                                    {
                                        'name': 'Delivered-To',
                                        'value': 'glizzykingdreko@takion.io'
                                    },
                                    {
                                        'name': 'Received',
                                        'value': '...'
                                    },
                                    {
                                        'name': 'Date',
                                        'value': 'Thu, 20 Apr 2023 21:53:11 +0000'
                                    },
                                    {
                                        'name': 'DKIM-Signature',
                                        'value': 'v=1; a=rsa-sha256; c=relaxed/relaxed; d=protonmail.com; s=protonmail3; t=1682027595; x=1682286795; bh=Rpk17hJVamaN+Wt3IBQouj1kNe5khyiqVfgNzSES63E=; h=Date:To:From:Subject:Message-ID:Feedback-ID:From:To:Cc:Date:\t Subject:Reply-To:Feedback-ID:Message-ID:BIMI-Selector; b=ksVsB1/LL6vBUSawBvpOZoWQptWu7vAR23CuycY+Q6Ag/Xut1Dv3OKu70SYyixZUG\t ZwvkypumYNGvPBgMVu8LcUi7V634d4m1JEOMyo1Op5V83pOZrSjZKh+kAb9rj3dmgN\t Y8jMc5LzJPHWotbLQSOMSmy63y1TtKdWec6lFk/p0TZizHLRsZU57bTV8b3PBiBkI0\t /XNSHlHVQifv5LogxGACpM6M8qyWKK5Kjv47C4gWm6SNuJLs0LbvU8HctcmxjSV5Pz\t McARMVhUOkuZo9ijJ989RzRfxrxssIr3Spf/jtXDXFRrsciw1QGjLu4wqip3SwMSnN\t 4Dc7FVZ9tQLjg=='
                                    },
                                    {
                                        'name': 'To',
                                        'value': '"glizzykingdreko@takion.io" <glizzykingdreko@takion.io>'
                                    },
                                    {
                                        'name': 'From',
                                        'value': '"GLIZZY KING DREKO 😈" <glizzykingdreko@protonmail.com>'
                                    },
                                    {
                                        'name': 'Subject',
                                        'value': 'OTP for login'
                                    },
                                ],
                                'body': {
                                    'size': 0
                                },
                                'parts': [
                                    {
                                        'partId': '0',
                                        'mimeType': 'text/plain',
                                        'filename': '',
                                        'headers': [
                                            {
                                                'name': 'Content-Type',
                                                'value': 'text/plain; charset=utf-8'
                                            },
                                            {
                                                'name': 'Content-Transfer-Encoding',
                                                'value': 'base64'
                                            }
                                        ],
                                        'body': {
                                            'size': 74,
                                            'data': 'QWFhYWFhYWEKCkludmlhdG8gY29uIGwnZW1haWwgc2ljdXJhIGRpIFtQcm90b24gTWFpbF0oaHR0cHM6Ly9wcm90b24ubWUvKS4='
                                        }
                                    },
                                    {
                                        'partId': '1',
                                        'mimeType': 'text/html',
                                        'filename': '',
                                        'headers': [
                                            {
                                                'name': 'Content-Type',
                                                'value': 'text/html; charset=utf-8'
                                            },
                                            {
                                                'name': 'Content-Transfer-Encoding',
                                                'value': 'base64'
                                            }
                                        ],
                                        'body': {
                                            'size': 577,
                                            'data': 'PGRpdiBzdHlsZT0iZm9udC1mYW1pbHk6IEFyaWFsLCBzYW5zLXNlcmlmOyBmb250LXNpemU6IDE0cHg7Ij5BYWFhYWFhYTwvZGl2PjxkaXYgc3R5bGU9ImZvbnQtZmFtaWx5OiBBcmlhbCwgc2Fucy1zZXJpZjsgZm9udC1zaXplOiAxNHB4OyI-PGJyPjwvZGl2Pg0KPGRpdiBjbGFzcz0icHJvdG9ubWFpbF9zaWduYXR1cmVfYmxvY2siIHN0eWxlPSJmb250LWZhbWlseTogQXJpYWwsIHNhbnMtc2VyaWY7IGZvbnQtc2l6ZTogMTRweDsiPg0KICAgIDxkaXYgY2xhc3M9InByb3Rvbm1haWxfc2lnbmF0dXJlX2Jsb2NrLXVzZXIgcHJvdG9ubWFpbF9zaWduYXR1cmVfYmxvY2stZW1wdHkiPg0KICAgICAgICANCiAgICAgICAgICAgIDwvZGl2Pg0KICAgIA0KICAgICAgICAgICAgPGRpdiBjbGFzcz0icHJvdG9ubWFpbF9zaWduYXR1cmVfYmxvY2stcHJvdG9uIj4NCiAgICAgICAgSW52aWF0byBjb24gbCdlbWFpbCBzaWN1cmEgZGkgPGEgdGFyZ2V0PSJfYmxhbmsiIGhyZWY9Imh0dHBzOi8vcHJvdG9uLm1lLyIgcmVsPSJub29wZW5lciBub3JlZmVycmVyIj5Qcm90b24gTWFpbDwvYT4uDQogICAgPC9kaXY-DQo8L2Rpdj4NCg=='
                                        }
                                    }
                                ]
                            },
                            'sizeEstimate': 5313,
                            'historyId': '...',
                            'internalDate': '...'
                        }
                        '''
                        # Check if labels parameter is contained in the message['labelIds']
                        if set(labels).issubset(set(msg_data['labelIds'])):
                            if msg_data.get('raw'):
                                msg = email.message_from_string(msg_data['raw'])
                            else:
                                body = msg_data['payload']['parts'][0]['body']['data']
                                try: msg = b64decode(body.encode('utf-8')).decode('utf-8')
                                except: return body
                            if value := query.get('text'):
                                if isinstance(value, str):
                                    if value in msg:
                                        return msg
                                elif isinstance(value, re.Pattern):
                                    if value.search(msg):
                                        return msg
                            else:
                                return msg
                        else:
                            self.logger.debug(f"Message {msg_id} does not contain the labels {labels}")
                else:
                    # IMAP generic - fetch recent emails by message number (newest first)
                    _, data = self.mailbox.select("INBOX")
                    total_messages = int(data[0].decode())
                    
                    if total_messages == 0:
                        self.logger.debug("No messages in mailbox")
                        if not wait_for_match:
                            return None
                        continue
                    
                    # Process emails from newest to oldest, in batches
                    batch_size = 50
                    start_msg = max(1, total_messages - batch_size + 1)
                    
                    # Fetch batch of recent emails (newest first)
                    msg_range = f'{start_msg}:{total_messages}'
                    _, fetch_data = self.mailbox.fetch(msg_range, '(FLAGS RFC822)')
                    
                    # Process in reverse order (newest first)
                    items = []
                    for i in range(0, len(fetch_data), 2):
                        if fetch_data[i] is not None:
                            items.append(fetch_data[i])
                    items.reverse()
                    
                    for item in items:
                        if not item or len(item) < 2:
                            continue
                        
                        # Check flags for unread filter
                        flags_str = item[0].decode() if item[0] else ""
                        is_seen = "\\Seen" in flags_str
                        
                        # Extract message number for marking as read
                        msg_num_match = re.search(r'^(\d+)', flags_str)
                        msg_num = msg_num_match.group(1) if msg_num_match else None
                        
                        # Skip if we only want unread and this is read
                        if unread and is_seen:
                            continue
                        
                        raw_email = item[1]
                        
                        # Parse the email message properly
                        email_message = email.message_from_bytes(raw_email)
                        
                        # Extract body text
                        msg = self._get_email_body(email_message)

                        match = True
                        for key, value in query.items():
                            if key.lower() in ["subject", "from", "to"]:
                                header = email_message.get(key, "")
                                
                                if isinstance(value, str):
                                    if value not in header:
                                        match = False
                                        break
                                elif isinstance(value, re.Pattern):
                                    if not value.search(header):
                                        match = False
                                        break
                        if match:
                            # Mark as read if requested
                            if mark_as_read and msg_num:
                                try:
                                    self.mailbox.store(msg_num, '+FLAGS', '\\Seen')
                                except:
                                    pass
                            
                            if value := query.get('text'):
                                if isinstance(value, str):
                                    if value in msg:
                                        return msg
                                elif isinstance(value, re.Pattern):
                                    if value.search(msg):
                                        return msg
                            else:
                                return msg
            except Exception as e:
                self.logger.error(f"Error while searching for emails: {e}")
                self.logger.info("Trying to reconnect...")
                self.connect()
            
            # If not waiting for match, return None after first search
            if not wait_for_match:
                return None
            
            # Wait before next search attempt
            self.logger.info(f"No match found, waiting {delay} seconds before next search...")
            sleep(delay)
