# Changelog

All notable changes to the `email-monitor` project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned Features

- Expand IMAP support for non-Gmail OAuth providers.
- Improve email handling for various email services.

## [0.1.0] - 2023-04-21

### Added

- Initial release of `email-monitor`.
- Main `EmailMonitor` class with methods to authenticate with Gmail OAuth and connect to an IMAP server.
- `search_mail` function for searching emails based on specific parameters, such as subject, sender, recipient, and text.
- Support for waiting for a new email to match the search query.
- Option to search for emails that have already been read.
- Gmail-specific label search.
- Examples of usage in README.md.
- Detailed explanation of search_mail parameters in README.md.
- Contributing, License, and Contact sections in README.md.
- Installation instructions using pip in README.md.