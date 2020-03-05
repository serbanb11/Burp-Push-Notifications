from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import IScannerListener
from burp import IExtensionStateListener
from burp import IHttpListener
from burp import IScannerCheck
from java.io import PrintWriter
from javax import swing
from javax.swing.event import MenuListener
from javax.swing.event import MenuEvent
from java.lang import Runnable
from java.text import NumberFormat
from collections import OrderedDict
from urlparse import urlparse
import java.awt as awt
import sys, time, threading, os, re, json, ast

    #
    # Variables from UI
    #

class GlobalSettings(Runnable):
    ConfigurableSettings = OrderedDict()
    ConfigurableSettings['request_timeout'] = 10

    ConfigurableSettings['verbose'] = False
   
    ConfigurableSettings['enable_spider'] = True
    ConfigurableSettings['enable_scanner'] = True
    ConfigurableSettings['enable_intruder'] = True
    ConfigurableSettings['enable_sequencer'] = True
    ConfigurableSettings['enable_extender'] = True

    ConfigurableSettings['enable_finished'] = True
    ConfigurableSettings['enable_issue'] = True
    ConfigurableSettings['enable_collaborator'] = True
    #ConfigurableSettings['enable_macro'] = True

    ConfigurableSettings['severity'] = OrderedDict([('High', True), ('Medium', False), ('Low', False), ('Information', False), ('False positive', False)])
    ConfigurableSettings['confidence'] = OrderedDict([('Certain', True), ('Firm', True), ('Tentative', False)])

    ConfigurableSettings['enable_mattermost'] = False
    ConfigurableSettings['matter_url'] = "" #"https://matter_url/hooks/xxxxxxxxxxxxxxxxxxxxxxxxxx"

    ConfigurableSettings['enable_slack'] = False
    ConfigurableSettings['slack_url'] = "" #"https://hooks.slack.com/services/xxxxxxx/xxxxxxx/xxxxxxxxxxxxxxx"

    ConfigurableSettings['enable_teams'] = False
    ConfigurableSettings['teams_url'] = "" #"https://outlook.office.com/webhook/UUID@UUID/IncomingWebhook/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/UUID"
  
    ConfigurableSettings['enable_signal'] = False
    ConfigurableSettings['signal_path'] = "" #"C:\\signal-cli-0.6.5\\bin\\signal-cli"
    ConfigurableSettings['signal_phone_from'] = "" #"+40123456789"
    ConfigurableSettings['signal_phone_to'] = "" #"+40123456789"

    ConfigurableSettings['enable_twilio'] = False
    ConfigurableSettings['twilio_url'] = 'https://api.twilio.com/2010-04-01/Accounts/'
    ConfigurableSettings['twilio_sid'] = "" #'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
    ConfigurableSettings['twilio_token'] = "" #'xxxxxxxxxxxxxxxxxxxxxxxxxxx'
    ConfigurableSettings['twilio_from'] = "" #'+12345678901'
    ConfigurableSettings['twilio_to'] = "" #"+40123456789"

    ConfigurableSettings['enable_sendgrid'] = False
    ConfigurableSettings['sendgrid_url'] = "https://api.sendgrid.com/v3/mail/send"
    ConfigurableSettings['sendgrid_key'] = "" #"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    ConfigurableSettings['sendgrid_from'] = "" #"example@gmail.com"
    ConfigurableSettings['sendgrid_to'] = "" #"example@gmail.com"

    # Load configuration
    def __init__(self, callbacks):
        self._callbacks = callbacks
        for key, value in self.ConfigurableSettings.items():
            saved = callbacks.loadExtensionSetting(key)
            if saved is None:
                continue
            if type(value) is bool:
                self.ConfigurableSettings[key] = json.loads(saved.lower())
            elif type(value) is int:
                self.ConfigurableSettings[key] = int(saved)
            elif type(value) is str:
                self.ConfigurableSettings[key] = str(saved)
            elif type(value) is OrderedDict:
                self.ConfigurableSettings[key] = OrderedDict(ast.literal_eval(saved))
            else:
                pass

    # Show configuration
    def run( self ):
        configured = {}
        panel = swing.JPanel()
        panel.setLayout(awt.GridLayout(0, 4))
        
        for key, value in self.ConfigurableSettings.items():
            panel.add(swing.JLabel("\n" + key + ": "))
            if type(value) is bool:
                box = swing.JCheckBox()
                box.setSelected(value)
                panel.add(box)
                configured[key] = box
            elif type(value) is int:
                box = swing.JFormattedTextField(NumberFormat.getIntegerInstance())
                box.setText(str(value))
                panel.add(box)
                configured[key] = box
            elif type(value) is str:
                box = swing.JTextField(value)
                box.setPreferredSize(awt.Dimension(300,10))
                panel.add(box)
                configured[key] = box
            elif type(value) is OrderedDict:
                panel.add(swing.JLabel("           "))
                configured[key] = {}
                for key1, value1 in value.items():
                    panel.add(swing.JLabel("\n     " + key1 + ": "))
                    box = swing.JCheckBox()
                    box.setSelected(value1)
                    panel.add(box)
                    configured[key][key1] = box
            else:
                pass

        # If click yes save configuration        
        result = swing.JOptionPane.showConfirmDialog(None, panel, "Push Notifications", swing.JOptionPane.OK_CANCEL_OPTION, swing.JOptionPane.PLAIN_MESSAGE)
        if result == swing.JOptionPane.OK_OPTION:
            for key, value in configured.items():
                if type(value) is swing.JCheckBox:
                    self.ConfigurableSettings[key] = value.isSelected()
                elif type(value) is swing.JFormattedTextField:
                    tempTimeOut = int(value.getText())
                    if tempTimeOut < 1 or tempTimeOut > 120:
                        continue
                    self.ConfigurableSettings[key] = tempTimeOut
                elif type(value) is swing.JTextField:
                    if key == "signal_path":
                        if os.path.isfile(str(value.getText())) == False:
                            continue
                    if key == "signal_phone_from" or key == "signal_phone_to":
                        if bool(re.match('^[+][0-9]+$', str(value.getText()))) == False:
                            continue
                    self.ConfigurableSettings[key] = str(value.getText())
                else:
                    for key1, value1 in value.items():
                        self.ConfigurableSettings[key][key1] = value1.isSelected()
                self._callbacks.saveExtensionSetting(key, str(self.ConfigurableSettings[key]))

# Add button to UI, push and remove if we unload the extension
class ConfigMenu(Runnable, MenuListener, IExtensionStateListener):

    menuButton = swing.JMenu("Push")

    def __init__(self, callbacks):
        self._globalSetting = GlobalSettings(callbacks)
        callbacks.registerExtensionStateListener(self)

    def run( self ):
        self.menuButton.addMenuListener(self)
        burpMenuBar = self.getBurpFrame().getJMenuBar()
        burpMenuBar.add(self.menuButton)
        
    def menuSelected(self, e):
        swing.SwingUtilities.invokeLater(self._globalSetting)

    def menuDeselected(self, e):
        pass

    def menuCanceled(self, e):
        pass

    def extensionUnloaded(self):
        try:
            jMenuBar = self.getBurpFrame().getJMenuBar()
            jMenuBar.remove(self.menuButton)
            jMenuBar.repaint()
        except:
            pass

    def getBurpFrame(self):
        for f in awt.Frame.getFrames():
            if f.isVisible() and f.getTitle().startswith("Burp Suite"):
                return f
        return None

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener, IScannerListener, IExtensionStateListener, IScannerCheck):
    name = "Burp push notifications"
    version = "1.00"

    push_finished = 1
    push_issue = 2
    push_collaborator = 3
    push_macro = 4

    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        # variable used in timer to see if we are still sending requests
        self._request_time = 0

        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # set our extension name
        callbacks.setExtensionName(self.name)
        
        # obtain our output stream
        self._stdout = PrintWriter(callbacks.getStdout(), True)

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # register ourselves as a Scanner listener
        callbacks.registerScannerListener(self)
        
        # register ourselves as an extension state listener
        callbacks.registerExtensionStateListener(self)

        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)

        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)

        # add menu option
        swing.SwingUtilities.invokeLater(ConfigMenu(callbacks))

    #
    # Push notification functions
    #

    # Push notification to Mattermost  
    def pushMatterNotification(self, type, issue):
        if type == self.push_finished:
            body = '{"text": "type 1"}' if GlobalSettings.ConfigurableSettings['verbose'] == False else '{"text": "scan finished"}'
        elif type == self.push_issue:
            body = '{"text": "type 2"}' if GlobalSettings.ConfigurableSettings['verbose'] == False else ('{"text": "New Issue\n' + 
                   ' - ' + issue.getIssueName() + '\n' +
                   ' - Severity: ' + issue.getSeverity() + '\n' +
                   ' - Confidence: ' + issue.getConfidence() + '\n' +
                   ' - Service: ' + issue.getHttpService().getProtocol() + '://' + issue.getHttpService().getHost() + ':' + str(issue.getHttpService().getPort()) + '\n' +
                   ' - Type: ' + str(issue.getIssueType()) + '\n' +
                   ' - Url: ' + str(issue.getUrl()) + '"}')
        elif type == self.push_collaborator:
            body = '{"text": "type 3"}' if GlobalSettings.ConfigurableSettings['verbose'] == False else '{"text": "new collaborator interaction"}'
        elif type == self.push_macro:
            body = '{"text": "type 4"}' if GlobalSettings.ConfigurableSettings['verbose'] == False else '{"text": "macro problems"}'
        else:
            return

        matter_url_parse = urlparse(GlobalSettings.ConfigurableSettings['matter_url'])
        headers = [ 'POST ' + matter_url_parse.path + ' HTTP/1.1', 'Host: ' + matter_url_parse.netloc, 'Content-type: application/json', ] 
        req = self._helpers.buildHttpMessage(headers, body)
        try:
            if matter_url_parse.scheme == "https":
                resp = self._callbacks.makeHttpRequest(matter_url_parse.netloc, 443, True, req)
            elif matter_url_parse.scheme == "http":
                resp = self._callbacks.makeHttpRequest(matter_url_parse.netloc, 80, False, req)
            else:
                return

            if (self._helpers.analyzeResponse(resp).getStatusCode() != 200):
                # write a message to the Burp alerts tab
                self._callbacks.issueAlert("Can't push notifications to Mattermost")
        except:
            # write a message to the Burp alerts tab
            self._callbacks.issueAlert("Can't push notifications to Mattermost")


    # Push notification to Slack
    def pushSlackNotification(self, type, issue):
        if type == self.push_finished:
            body = '{"text": "type 1"}' if GlobalSettings.ConfigurableSettings['verbose'] == False else '{"text": "scan finished"}'
        elif type == self.push_issue:
            body = '{"text": "type 2"}' if GlobalSettings.ConfigurableSettings['verbose'] == False else ('{"text": "New Issue\n' + 
                   ' - ' + issue.getIssueName() + '\n' +
                   ' - Severity: ' + issue.getSeverity() + '\n' +
                   ' - Confidence: ' + issue.getConfidence() + '\n' +
                   ' - Service: ' + issue.getHttpService().getProtocol() + '://' + issue.getHttpService().getHost() + ':' + str(issue.getHttpService().getPort()) + '\n' +
                   ' - Type: ' + str(issue.getIssueType()) + '\n' +
                   ' - Url: ' + str(issue.getUrl()) + '"}')
        elif type == self.push_collaborator:
            body = '{"text": "type 3"}' if GlobalSettings.ConfigurableSettings['verbose'] == False else '{"text": "new collaborator interaction"}'
        elif type == self.push_macro:
            body = '{"text": "type 4"}' if GlobalSettings.ConfigurableSettings['verbose'] == False else '{"text": "macro problems"}'
        else:
            return

        slack_url_parse = urlparse(GlobalSettings.ConfigurableSettings['slack_url'])
        headers = [ 'POST ' + slack_url_parse.path + ' HTTP/1.1', 'Host: ' + slack_url_parse.netloc, 'Content-type: application/json', ] 
        req = self._helpers.buildHttpMessage(headers, body)
        try:
            if slack_url_parse.scheme == "https":
                resp = self._callbacks.makeHttpRequest(slack_url_parse.netloc, 443, True, req)
            elif slack_url_parse.scheme == "http":
                resp = self._callbacks.makeHttpRequest(slack_url_parse.netloc, 80, False, req)
            else:
                return

            if (self._helpers.analyzeResponse(resp).getStatusCode() != 200):
                # write a message to the Burp alerts tab
                self._callbacks.issueAlert("Can't push notifications to Slack")
        except:
            # write a message to the Burp alerts tab
            self._callbacks.issueAlert("Can't push notifications to Slack")

    # Push notification to Twilio
    def pushTwilioNotification(self, type, issue):
        if type == self.push_finished:
            text = 'type 1' if GlobalSettings.ConfigurableSettings['verbose'] == False else 'scan finished'
        elif type == self.push_issue:
            text = 'type 2' if GlobalSettings.ConfigurableSettings['verbose'] == False else ('New Issue\n' + 
                   ' - ' + issue.getIssueName() + '\n' +
                   ' - Severity: ' + issue.getSeverity() + '\n' +
                   ' - Confidence: ' + issue.getConfidence())
        elif type == self.push_collaborator:
            text = 'type 3' if GlobalSettings.ConfigurableSettings['verbose'] == False else 'new collaborator interaction'
        elif type == self.push_macro:
            text = 'type 4' if GlobalSettings.ConfigurableSettings['verbose'] == False else 'macro problems'
        else:
            return
         
        body = "Body=" + self._helpers.urlEncode(text) + "&From=" + self._helpers.urlEncode(GlobalSettings.ConfigurableSettings['twilio_from']) + "&To=" + self._helpers.urlEncode(GlobalSettings.ConfigurableSettings['twilio_to'])

        twilio_url = GlobalSettings.ConfigurableSettings['twilio_url'] + GlobalSettings.ConfigurableSettings['twilio_sid'] + "/Messages.json"
        twilio_url_parse = urlparse(twilio_url)
        headers = [ 'POST ' + twilio_url_parse.path + ' HTTP/1.1', 'Host: ' + twilio_url_parse.netloc, 'Authorization: Basic ' + self._helpers.base64Encode(GlobalSettings.ConfigurableSettings['twilio_sid'] + ":" + GlobalSettings.ConfigurableSettings['twilio_token']), 'Content-Type: application/x-www-form-urlencoded', ]
        req = self._helpers.buildHttpMessage(headers, body)
        self._stdout.println("Twilio: " + req)
        try:
            resp = self._callbacks.makeHttpRequest(twilio_url_parse.netloc, 443, True, req)
            if (self._helpers.analyzeResponse(resp).getStatusCode() != 200):
                # write a message to the Burp alerts tab
                self._callbacks.issueAlert("Can't push notifications to Twilio")
        except:
            # write a message to the Burp alerts tab
            self._callbacks.issueAlert("Can't push notifications to Twilio")

    # Push notification to Teams
    def pushTeamsNotification(self, type, issue):
        if type == self.push_finished:
            body = '{"text": "type 1"}' if GlobalSettings.ConfigurableSettings['verbose'] == False else '{"text": "scan finished"}'
        elif type == self.push_issue:
            body = '{"text": "type 2"}' if GlobalSettings.ConfigurableSettings['verbose'] == False else ('{"text": "New Issue<br>' + 
                   ' - ' + issue.getIssueName() + '<br>' +
                   ' - Severity: ' + issue.getSeverity() + '<br>' +
                   ' - Confidence: ' + issue.getConfidence() + '<br>' +
                   ' - Service: ' + issue.getHttpService().getProtocol() + '://' + issue.getHttpService().getHost() + ':' + str(issue.getHttpService().getPort()) + '<br>' +
                   ' - Type: ' + str(issue.getIssueType()) + '<br>' +
                   ' - Url: ' + str(issue.getUrl()) + '"}')
        elif type == self.push_collaborator:
            body = '{"text": "type 3"}' if GlobalSettings.ConfigurableSettings['verbose'] == False else '{"text": "new collaborator interaction"}'
        elif type == self.push_macro:
            body = '{"text": "type 4"}' if GlobalSettings.ConfigurableSettings['verbose'] == False else '{"text": "macro problems"}'
        else:
            return

        teams_url_parse = urlparse(GlobalSettings.ConfigurableSettings['teams_url'])
        headers = [ 'POST ' + teams_url_parse.path + ' HTTP/1.1', 'Host: ' + teams_url_parse.netloc, 'Content-type: application/json', ] 
        req = self._helpers.buildHttpMessage(headers, body)
        try:
            if teams_url_parse.scheme == "https":
                resp = self._callbacks.makeHttpRequest(teams_url_parse.netloc, 443, True, req)
            elif teams_url_parse.scheme == "http":
                resp = self._callbacks.makeHttpRequest(teams_url_parse.netloc, 80, False, req)
            else:
                return

            if (self._helpers.analyzeResponse(resp).getStatusCode() != 200):
                # write a message to the Burp alerts tab
                self._callbacks.issueAlert("Can't push notifications to Teams")
        except:
            # write a message to the Burp alerts tab
            self._callbacks.issueAlert("Can't push notifications to Teams")

    # Push notification to Signal  
    def pushSignalNotification(self, type, issue):
        if type == self.push_finished:
            body = 'type 1' if GlobalSettings.ConfigurableSettings['verbose'] == False else 'scan finished'
        elif type == self.push_issue:
            body = 'type 2' if GlobalSettings.ConfigurableSettings['verbose'] == False else ('New Issue: ' + 
                   ' - ' + issue.getIssueName() + '&' +
                   ' - Severity: ' + issue.getSeverity() + '&' +
                   ' - Confidence: ' + issue.getConfidence() + '&' +
                   ' - Service: ' + issue.getHttpService().getProtocol() + '://' + issue.getHttpService().getHost() + ':' + str(issue.getHttpService().getPort()) + '&' +
                   ' - Type: ' + str(issue.getIssueType()) + '&' +
                   ' - Url: ' + str(issue.getUrl()))
        elif type == self.push_collaborator:
            body = 'type 3' if GlobalSettings.ConfigurableSettings['verbose'] == False else 'new collaborator interaction'
        elif type == self.push_macro:
            body = 'type 4' if GlobalSettings.ConfigurableSettings['verbose'] == False else 'macro problems'
        else:
            return

        self._stdout.println("signal: " + GlobalSettings.ConfigurableSettings['signal_path'] + ' -u ' + GlobalSettings.ConfigurableSettings['signal_phone_from'] + ' send -m "' + body + '" ' + GlobalSettings.ConfigurableSettings['signal_phone_to'])
        try:
            os.system(GlobalSettings.ConfigurableSettings['signal_path'] + ' -u ' + GlobalSettings.ConfigurableSettings['signal_phone_from'] + ' send -m "' + body + '" ' + GlobalSettings.ConfigurableSettings['signal_phone_to'])
        except:
            # write a message to the Burp alerts tab
            self._callbacks.issueAlert("Can't push notifications to Signal")


    # Push notification to Sendgrid
    def pushSendgridNotification(self, type, issue):
        if type == self.push_finished:
            text = 'type 1' if GlobalSettings.ConfigurableSettings['verbose'] == False else 'scan finished'
        elif type == self.push_issue:
            text = 'type 2' if GlobalSettings.ConfigurableSettings['verbose'] == False else ('New Issue<br />' + 
                   ' - ' + issue.getIssueName() + '<br>' +
                   ' - Severity: ' + issue.getSeverity() + '<br>' +
                   ' - Confidence: ' + issue.getConfidence() + '<br>' +
                   ' - Service: ' + issue.getHttpService().getProtocol() + '://' + issue.getHttpService().getHost() + ':' + str(issue.getHttpService().getPort()) + '<br>' +
                   ' - Type: ' + str(issue.getIssueType()) + '<br>' +
                   ' - Url: ' + str(issue.getUrl()))
        elif type == self.push_collaborator:
            text = 'type 3' if GlobalSettings.ConfigurableSettings['verbose'] == False else 'new collaborator interaction'
        elif type == self.push_macro:
            text = 'type 4' if GlobalSettings.ConfigurableSettings['verbose'] == False else 'macro problems'
        else:
            return

        body = '{"personalizations": [{"to": [{"email": "' + GlobalSettings.ConfigurableSettings['sendgrid_to'] + '"}]}],"from": {"email": "' + GlobalSettings.ConfigurableSettings['sendgrid_from'] + '"},"subject": "Burp notification","content": [{"type": "text/html", "value": "' + text + '"}]}'

        sendgrid_url_parse = urlparse(GlobalSettings.ConfigurableSettings['sendgrid_url'])
        headers = [ 'POST ' + sendgrid_url_parse.path + ' HTTP/1.1', 'Host: ' + sendgrid_url_parse.netloc, 'Content-type: application/json', 'Authorization: Bearer ' + GlobalSettings.ConfigurableSettings['sendgrid_key']] 
        req = self._helpers.buildHttpMessage(headers, body)
        self._stdout.println("Sendgrid: " + req)
        try:
            resp = self._callbacks.makeHttpRequest(sendgrid_url_parse.netloc, 443, True, req)

            if (self._helpers.analyzeResponse(resp).getStatusCode() != 200):
                # write a message to the Burp alerts tab
                self._callbacks.issueAlert("Can't push notifications to Sendgrid")
        except:
            # write a message to the Burp alerts tab
            self._callbacks.issueAlert("Can't push notifications to Sendgrid")

    #
    # Logic to identify start/finish of scans
    #

    # We check if there was any request in the last request_timeout seconds, if not push notification
    # Burp doesnt offer any way to check when a scan started or finished so this is a little workaround
    def checkRequestTimer(self):
        if (time.time() - self._request_time > GlobalSettings.ConfigurableSettings['request_timeout'] and self._request_time != 0):
            self._request_time = 0
            if GlobalSettings.ConfigurableSettings['enable_mattermost'] == True:
                self.pushMatterNotification(self.push_finished, None)
            if GlobalSettings.ConfigurableSettings['enable_slack'] == True:
                self.pushSlackNotification(self.push_finished, None)
            if GlobalSettings.ConfigurableSettings['enable_teams'] == True:
                self.pushTeamsNotification(self.push_finished, None)
            if GlobalSettings.ConfigurableSettings['enable_twilio'] == True:
                self.pushTwilioNotification(self.push_finished, None)
            if GlobalSettings.ConfigurableSettings['enable_signal'] == True:
                self.pushSignalNotification(self.push_finished, None)
            if GlobalSettings.ConfigurableSettings['enable_sendgrid'] == True:
                self.pushSendgridNotification(self.push_finished, None)
        else:
            self.request_timer = threading.Timer(GlobalSettings.ConfigurableSettings['request_timeout'], self.checkRequestTimer).start()


    # We use to find when a new scan begins
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        if GlobalSettings.ConfigurableSettings['enable_finished'] == False or GlobalSettings.ConfigurableSettings['enable_scanner'] == False:
            return

        # start timer only if it is not already started and we enabled this notification
        if (self._request_time == 0):
            self.checkRequestTimer()
            self._stdout.println("start time")
        
        # get current time
        self._request_time = time.time()


    # We start the timer when we have request from certain tools
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if GlobalSettings.ConfigurableSettings['enable_finished'] == False:
            return

        # only process requests
        if not messageIsRequest:
            return
        
        # only tools that run for some time
        if toolFlag != (self._callbacks.TOOL_SPIDER * GlobalSettings.ConfigurableSettings['enable_spider']) and \
           toolFlag != (self._callbacks.TOOL_INTRUDER * GlobalSettings.ConfigurableSettings['enable_intruder']) and \
           toolFlag != (self._callbacks.TOOL_SEQUENCER * GlobalSettings.ConfigurableSettings['enable_sequencer']) :
            return

        # start timer only if it is not already started and we enabled this notification
        if (self._request_time == 0):
            self.checkRequestTimer()
            self._stdout.println("start time")
        
        # get current time
        self._request_time = time.time()

    #
    # Identify new issues
    #

    # Push notifications for new issues
    def newScanIssue(self, issue):
        if GlobalSettings.ConfigurableSettings['enable_issue'] == True and GlobalSettings.ConfigurableSettings['severity'][issue.getSeverity()] == True and GlobalSettings.ConfigurableSettings['confidence'][issue.getConfidence()] == True:
            if GlobalSettings.ConfigurableSettings['enable_mattermost'] == True:
                self.pushMatterNotification(self.push_issue, issue)
            if GlobalSettings.ConfigurableSettings['enable_slack'] == True:
                self.pushSlackNotification(self.push_issue, issue)
            if GlobalSettings.ConfigurableSettings['enable_teams'] == True:
                self.pushTeamsNotification(self.push_issue, issue)
            if GlobalSettings.ConfigurableSettings['enable_twilio'] == True:
                self.pushTwilioNotification(self.push_issue, issue)
            if GlobalSettings.ConfigurableSettings['enable_signal'] == True:
                self.pushSignalNotification(self.push_issue, issue)
            if GlobalSettings.ConfigurableSettings['enable_sendgrid'] == True:
                self.pushSendgridNotification(self.push_issue, issue)


    #
    # implement IExtensionStateListener
    #
    def extensionUnloaded(self):
        try:
            self.request_timer.cancel()
        except:
            pass
        self._stdout.println("Extension was unloaded")