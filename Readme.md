
# Burp push notifications

This Burp extension can be used to push notification to:

- Slack
- Mattermost
- Microsoft Teams
- Signal Private Messenger
- Email using SendGrid
- SMS using Twilio

This extension can be configured to send notification if a scan / intruder /sequencer / spider had finished or certain types of issues, depanding on severity / confidence are found.

## Configuration

When loading the extension a new button in Burp's menu bar called "Push" will appear. Upon clicking this button a new panel will pop out where the extension can be configured. After chnaging the values and clicking yes, the settings will be saved in a persistent way that survives reloads of the extension and of Burp Suit:

**request_timeout** - maximum time in seconds extension waits between requests to find if a tool finished, can get a value between 1 and 120

**verbose** - if false, notifications will have generic messages (eg. type 1 - scan finishes, type 2 - new issue reported). If true, in case of issues notification will report the name, severity, confidence, service, URL and type

**enable_spider**, **enable_scanner**, **enable_intruder**, **enable_sequencer** - if enable_finished enabled, extension will report when any of the tools enabled finishes

**enable_extender** - unused

**enable_finished** - extension will report when any of the tools enabled finishes

**enable_issue** - extension will report when a new issue with severity and confidence enabled is found

**enable_collaborator** - unused

**enable_mattermost** - extension will send notification to mattermost webhook: [setup mattermost incoming webhook documentation](https://docs.mattermost.com/developer/webhooks-incoming.html#simple-incoming-webhook). eg. matter_url: https://matter_/hooks/xxxxxxxxxxxxxxxxxxxxxxxxxx

**enable_slack** - extension will send notification to slack webhook: [setup slack incoming webhook documentation](https://api.slack.com/messaging/webhooks). eg. slack_url: https://hooks.slack.com_/services/xxxxxxx/xxxxxxx/xxxxxxxxxxxxxxx

**enable_teams** - extension will send notification to Microsoft Teams: [setup Teams incoming webhook documentation](https://docs.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/connectors-using#setting-up-a-custom-incoming-webhook). eg. teams_url: https://outlook.office.com_/webhook/UUID@UUID/IncomingWebhook/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/UUID

**enable_signal** - extension will send notification to signal. This is realised using [signal_cli](https://github.com/AsamK/signal-cli). If the host running Burp is master device it requires to [register the phone number](https://github.com/AsamK/signal-cli#usage). If the host running Burp is not master, it needs to be linked:
```
signal-cli link -n `hostname` > /tmp/signal.txt&
sleep 5
qrencode -t ANSI `cat /tmp/signal.txt`
```
Using the master device we add a new linked device scanning the QR code generated.  
**signal_path** is path to signal_cli eg. C:\\signal-cli-0.6.5\\bin\\signal-cli. A check if file exists is implemented, this value must be a valid path to a file.  
**signal_phone_from** is the username (phone number) registered or linked  
**signal_phone_to** is the DEVICE_ID (phone number) to whom the notifications will be sent, can be the same as **signal_phone_from** and the notifications will appear in "Note to Self". A check is implemented, the phone numbers should start with + followed by digits eg. +12345678901

**enable_twilio** - extension will send SMS notifications using Twilio.  
**twilio_url** - should not be changed  
**twilio_sid** and **twilio_token** can be obtained after registering and creating a new phone number  
**twilio_from** - is twilio generated phone number
**twilio_to** - is the destination phone number

**enable_sendgrid** - extension will send email notifications using SendGrid
**sendgrid_url** - should not be changed  
**sendgrid_key**  can be obtained after registering and creating a new SendGrid API key  
**sendgrid_from** - is the sender email address
**sendgrid_to** - is the destination email address


# Changelog

**1.00 2020-02-20**

- First public release

# Installation

 This extension requires jython. Add path to jython-standalone-2.7.0.jar in Extender > Options > Python Environment.
 Add burp-push-notifications.py in Extender > Extensions
