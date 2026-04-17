"""External integrations: Jira, Slack, SIEM, SARIF, webhooks, GitHub Actions."""

from decepticon.integrations.jira import JiraClient, JiraFinding
from decepticon.integrations.sarif import findings_to_sarif
from decepticon.integrations.siem import to_cef, to_stix, to_syslog_rfc5424
from decepticon.integrations.slack import SlackFinding, SlackNotifier
from decepticon.integrations.webhook import WebhookDeliverer

__all__ = [
    "JiraClient",
    "JiraFinding",
    "SlackFinding",
    "SlackNotifier",
    "WebhookDeliverer",
    "findings_to_sarif",
    "to_cef",
    "to_stix",
    "to_syslog_rfc5424",
]
