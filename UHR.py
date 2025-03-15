from burp import IBurpExtender, IHttpListener, IMessageEditorTabFactory, IMessageEditorTab
from javax.swing import JTextArea
import re

class BurpExtender(IBurpExtender, IHttpListener, IMessageEditorTabFactory):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Header Cleaner")
        
        # Register HTTP listener
        callbacks.registerHttpListener(self)
        
        # Register tab factory
        callbacks.registerMessageEditorTabFactory(self)
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            request_info = self._helpers.analyzeRequest(messageInfo)
            headers = list(request_info.getHeaders())
            body = messageInfo.getRequest()[request_info.getBodyOffset():]
            
            headers_to_remove = set([
                "accept", "accept-encoding", "accept-language", "if-modified-since", "if-none-match", "priority",
                "sec-ch-ua", "sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-full-version", "sec-ch-ua-mobile", "sec-ch-ua-model", 
                "sec-ch-ua-platform", "sec-ch-ua-platform-version", "sec-ch-ua-wow64", "sec-fetch-dest", "sec-fetch-mode", 
                "sec-fetch-site", "sec-fetch-user", "upgrade-insecure-requests", "x-requested-with"
            ])
            
            cleaned_headers = [headers[0]]  # Keep request line (e.g., GET / HTTP/1.1)
            for header in headers[1:]:
                header_name = header.split(":")[0].strip().lower()
                if header_name not in headers_to_remove:
                    cleaned_headers.append(header)
            
            new_request = self._helpers.buildHttpMessage(cleaned_headers, body)
            messageInfo.setRequest(new_request)
    
    def createNewInstance(self, controller, editable):
        return CleanedHeadersTab(self._callbacks, self._helpers, controller, editable)

class CleanedHeadersTab(IMessageEditorTab):
    def __init__(self, callbacks, helpers, controller, editable):
        self._helpers = helpers
        self._controller = controller
        self._editable = editable
        self._txtArea = JTextArea()
        self._txtArea.setEditable(False)
    
    def getTabCaption(self):
        return "Cleaned Headers"
    
    def getUiComponent(self):
        return self._txtArea
    
    def isEnabled(self, content, isRequest):
        return isRequest
    
    def setMessage(self, content, isRequest):
        if isRequest:
            request_info = self._helpers.analyzeRequest(content)
            headers = list(request_info.getHeaders())
            
            headers_to_remove = set([
                "accept", "accept-encoding", "accept-language", "if-modified-since", "if-none-match", "priority",
                "sec-ch-ua", "sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-full-version", "sec-ch-ua-mobile", "sec-ch-ua-model", 
                "sec-ch-ua-platform", "sec-ch-ua-platform-version", "sec-ch-ua-wow64", "sec-fetch-dest", "sec-fetch-mode", 
                "sec-fetch-site", "sec-fetch-user", "upgrade-insecure-requests", "x-requested-with"
            ])
            
            cleaned_headers = [headers[0]]  # Keep request line (e.g., GET / HTTP/1.1)
            for header in headers[1:]:
                header_name = header.split(":")[0].strip().lower()
                if header_name not in headers_to_remove:
                    cleaned_headers.append(header)
            
            self._txtArea.setText("\n".join(cleaned_headers))
        else:
            self._txtArea.setText("")
    
    def getMessage(self):
        return None
    
    def isModified(self):
        return False
    
    def getSelectedData(self):
        return None
