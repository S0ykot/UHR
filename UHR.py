from burp import IBurpExtender, IHttpListener, IMessageEditorTabFactory, IMessageEditorTab
from javax.swing import JTextArea, JScrollPane
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit
from java.io import PrintWriter
import hashlib

class BurpExtender(IBurpExtender, IHttpListener, IMessageEditorTabFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Unnecessary Header Remove")
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        self.cleaned_requests = {}
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.registerHttpListener(self)
        self.stdout.println("[+] Header Cleaner Plugin Loaded Successfully!")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """ Cleans the HTTP request by removing unnecessary headers """
        if messageIsRequest:
            request = messageInfo.getRequest()
            request_info = self._helpers.analyzeRequest(request)
            headers = request_info.getHeaders()
            body = request[request_info.getBodyOffset():]
            # Headers to remove
            uninteresting_headers = {
                "Accept",
                "Accept-Language",
                "Accept-Encoding",
                "Upgrade-Insecure-Requests",
                "Sec-Fetch-Dest",
                "Sec-Fetch-Mode",
                "Sec-Fetch-Site",
                "Sec-Fetch-User",
                "Priority"
            }
            filtered_headers = [header for header in headers if not any(header.lower().startswith(h.lower()) for h in uninteresting_headers)]
            cleaned_request = "\n".join(filtered_headers) + "\n\n" + self._helpers.bytesToString(body)
            # Store cleaned request in dictionary with hash of request as key
            request_hash = hashlib.md5(request).hexdigest()
            self.cleaned_requests[request_hash] = cleaned_request

    def createNewInstance(self, controller, editable):
        return CleanedRequestTab(self._helpers, controller, self.cleaned_requests)


class CleanedRequestTab(IMessageEditorTab):

    def __init__(self, helpers, controller, cleaned_requests):
        self._helpers = helpers
        self._controller = controller
        self.cleaned_requests = cleaned_requests  # Dictionary of cleaned requests
        self.text_area = JTextArea()
        self.text_area.setEditable(False)
        self.scroll_pane = JScrollPane(self.text_area)

    def getTabCaption(self):
        return "Cleaned Request"

    def getUiComponent(self):
        return self.scroll_pane

    def isEnabled(self, content, isRequest):
        return isRequest

    def setMessage(self, content, isRequest):
        if isRequest:
            request_hash = hashlib.md5(content).hexdigest()
            cleaned_request = self.cleaned_requests.get(request_hash, "No cleaned request available.")
            self.text_area.setText(cleaned_request)

    def getMessage(self):
        return None

    def isModified(self):
        return False

    def getSelectedData(self):
        return self.text_area.getSelectedText()
