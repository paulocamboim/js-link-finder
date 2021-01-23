#
#  BurpLinkFinder - Find links within JS files.
#
#  Copyright (c) 2019 Frans Hendrik Botes
#  Credit to https://github.com/GerbenJavado/LinkFinder for the idea and regex
#
from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab
from java.io import PrintWriter
from java.net import URL
from java.util import ArrayList, List
from java.util.regex import Matcher, Pattern
import binascii
import base64
import re
from javax import swing
from java.awt import Font, Color
from threading import Thread
from array import array
from java.awt import EventQueue
from java.lang import Runnable
from thread import start_new_thread
from javax.swing import JFileChooser
from urlparse import urlparse

# Using the Runnable class for thread-safety with Swing
class Run(Runnable):
    def __init__(self, runner):
        self.runner = runner

    def run(self):
        self.runner()

# Needed params
class BurpExtender(IBurpExtender, IScannerCheck, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BurpJSLinkFinder")

        callbacks.issueAlert("BurpJSLinkFinder Passive Scanner enabled")

        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.registerScannerCheck(self)
        self.initUI()
        self.callbacks.addSuiteTab(self)
        
        print ("Burp JS LinkFinder loaded.")
        print ("Copyright (c) 2019 Frans Hendrik Botes")
        self.outputTxtArea.setText("Burp JS LinkFinder loaded." + "\n" + "Copyright (c) 2019 Frans Hendrik Botes" + "\n")

        self.dynamicExclusionList = None

    def initUI(self):
        self.tab = swing.JPanel()

        # UI for Output
        self.outputLabel = swing.JLabel("LinkFinder Log:")
        self.outputLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        self.outputLabel.setForeground(Color(255,102,52))
        self.logPane = swing.JScrollPane()
        self.outputTxtArea = swing.JTextArea()
        self.outputTxtArea.setFont(Font("Consolas", Font.PLAIN, 12))
        self.outputTxtArea.setLineWrap(True)
        self.logPane.setViewportView(self.outputTxtArea)
        self.clearBtn = swing.JButton("Clear Log", actionPerformed=self.clearLog)
        self.exportBtn = swing.JButton("Export Log", actionPerformed=self.exportLog)
        self.parentFrm = swing.JFileChooser()

        self.exclusionLabel = swing.JLabel("Exclusion list (separated by by comma):")
        self.exclusionInput = swing.JTextField() # TODO: Save configuration


        # Layout
        layout = swing.GroupLayout(self.tab)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        self.tab.setLayout(layout)
      
        layout.setHorizontalGroup(
            layout.createParallelGroup()
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup()
                    .addComponent(self.exclusionLabel)
                    .addComponent(self.exclusionInput)
                    .addComponent(self.outputLabel)
                    .addComponent(self.logPane)
                    .addComponent(self.clearBtn)
                    .addComponent(self.exportBtn)
                )
            )
        )
        
        layout.setVerticalGroup(
            layout.createParallelGroup()
            .addGroup(layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                    .addComponent(self.exclusionLabel)
                    .addComponent(self.exclusionInput)
                    .addComponent(self.outputLabel)
                    .addComponent(self.logPane)
                    .addComponent(self.clearBtn)
                    .addComponent(self.exportBtn)
                )
            )
        )

    def getTabCaption(self):
        return "BurpJSLinkFinder"

    def getUiComponent(self):
        return self.tab

    def clearLog(self, event):
          self.outputTxtArea.setText("Burp JS LinkFinder loaded." + "\n" + "Copyright (c) 2019 Frans Hendrik Botes" + "\n" )

    def exportLog(self, event):
        chooseFile = JFileChooser()
        ret = chooseFile.showDialog(self.logPane, "Choose file")
        filename = chooseFile.getSelectedFile().getCanonicalPath()
        print("\n" + "Export to : " + filename)
        open(filename, 'w', 0).write(self.outputTxtArea.text)

    
    def make_request(self, base_request_url, link_found):
        '''
        Make a new request using Burp and analyze the response. 
        If returns 200: add to sitemap
        url: string
        '''
        # Parse base_request_url
        parsed_base_url = urlparse(base_request_url)
        base_http_protocol = parsed_base_url.scheme
        base_address_and_port = parsed_base_url.netloc.split(':')
        base_host = base_address_and_port[0]

        if len(base_address_and_port) > 1 and base_address_and_port[1]:
            base_port = int(base_address_and_port[1])
        else:
            base_port = 80 if (base_http_protocol == 'http') else 443

        # Try to make a valid URL from Origin + path found 
        if link_found.startswith('http://') or link_found.startswith('https://'):
            target_url = link_found
        elif link_found.startswith('//'):
            target_url = 'https:' + link_found
        elif link_found.startswith('/'):
            target_url = 'https://' + base_host  + link_found
        else:
            target_url = 'https://' + base_host + '/' + link_found

        # Parse target_url
        parsed_url = urlparse(target_url)
        http_protocol = parsed_url.scheme
        address_and_port = parsed_url.netloc.split(':')
        host = address_and_port[0]

        if len(address_and_port) > 1 and address_and_port[1]:     
            port = int(address_and_port[1])
        else:
            port = 80 if (http_protocol == 'http') else 443

        # Make request to the URL
        my_new_request_headers = [
            'GET ' + parsed_url.path + '?' + parsed_url.query + ' HTTP/1.1',
            'host: ' + host
        ]
        my_new_request_body = ''
        my_new_request = self.helpers.buildHttpMessage(
            my_new_request_headers,
            self.helpers.stringToBytes(my_new_request_body)
        )

        # Send request
        my_http_service = self.helpers.buildHttpService(host, port, http_protocol)
        my_new_http_request_response = self.callbacks.makeHttpRequest(
            my_http_service,
            my_new_request
        )

        # Analyze the response
        analyzed_response = self.helpers.analyzeResponse(my_new_http_request_response.getResponse())
        status_code = analyzed_response.getStatusCode()

        print('-----------> ' + target_url + ' -- ' + str(status_code))

        # Logic for adding to sitemap is here
        if status_code in [200]:
            self.callbacks.addToSiteMap(my_new_http_request_response)

    def doPassiveScan(self, ihrr):
        '''
        The Scanner invokes this method for each base request / response that is passively scanned.
        Note: Extensions should only analyze the HTTP messages provided during passive scanning, and should not make any new HTTP requests of their own.
        '''
        
        try:
            urlReq = ihrr.getUrl()
            testString = str(urlReq)
            linkA = linkAnalyse(ihrr,self.helpers)
            # check if JS file
            if ".js" in str(urlReq):
                # Exclude casual JS files
                self.dynamicExclusionList = str(self.exclusionInput.getText().strip()).split(',') if str(self.exclusionInput.getText().strip()) else None

                if self.dynamicExclusionList and any(x in testString for x in self.dynamicExclusionList):
                    print("\n" + "[-] URL excluded " + str(urlReq))
                else:
                    self.outputTxtArea.append("\n" + "[+] Valid URL found: " + str(urlReq))
                    issueText = linkA.analyseURL()
                    for counter, issueText in enumerate(issueText):
                            #print("TEST Value returned SUCCESS")
                            self.outputTxtArea.append("\n" + "\t" + str(counter)+' - ' +issueText['link'])   
                            self.make_request(testString, issueText['link'])
                    issues = ArrayList()
                    issues.add(SRI(ihrr, self.helpers))
                    return issues
        except UnicodeEncodeError:
            print ("Error in URL decode.")
        return None


    def consolidateDuplicateIssues(self, isb, isa):
        return -1

    def extensionUnloaded(self):
        print "Burp JS LinkFinder unloaded"
        return

class linkAnalyse():
    
    def __init__(self, reqres, helpers):
        self.helpers = helpers
        self.reqres = reqres
        

    regex_str = """
    
      (?:"|')                               # Start newline delimiter
    
      (
        ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
        [^"'/]{1,}\.                        # Match a domainname (any character + dot)
        [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
    
        |
    
        ((?:/|\.\./|\./)                    # Start with /,../,./
        [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
        [^"'><,;|()]{1,})                   # Rest of the characters can't be
    
        |
    
        ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
        [a-zA-Z0-9_\-/]{1,}                 # Resource name
        \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
        (?:[\?|/][^"|']{0,}|))              # ? mark with parameters
    
        |
    
        ([a-zA-Z0-9_\-]{1,}                 # filename
        \.(?:php|asp|aspx|jsp|json|
             action|html|js|txt|xml)             # . + extension
        (?:\?[^"|']{0,}|))                  # ? mark with parameters
    
      )
    
      (?:"|')                               # End newline delimiter
    
    """     

    def	parser_file(self, content, regex_str, mode=1, more_regex=None, no_dup=1):
        #print ("TEST parselfile #2")
        regex = re.compile(regex_str, re.VERBOSE)
        items = [{"link": m.group(1)} for m in re.finditer(regex, content)]
        if no_dup:
            # Remove duplication
            all_links = set()
            no_dup_items = []
            for item in items:
                if item["link"] not in all_links:
                    all_links.add(item["link"])
                    no_dup_items.append(item)
            items = no_dup_items
    
        # Match Regex
        filtered_items = []
        for item in items:
            # Remove other capture groups from regex results
            if more_regex:
                if re.search(more_regex, item["link"]):
                    #print ("TEST parselfile #3")
                    filtered_items.append(item)
            else:
                filtered_items.append(item)
        return filtered_items

    # Potential for use in the future...
    def threadAnalysis(self):
        thread = Thread(target=self.analyseURL(), args=(session,))
        thread.daemon = True
        thread.start()

    def analyseURL(self):
        
        endpoints = ""
        #print("TEST AnalyseURL #1")
        mime_type=self.helpers.analyzeResponse(self.reqres.getResponse()).getStatedMimeType()
        if mime_type.lower() == 'script':
                url = self.reqres.getUrl()
                encoded_resp=binascii.b2a_base64(self.reqres.getResponse())
                decoded_resp=base64.b64decode(encoded_resp)
                endpoints=self.parser_file(decoded_resp, self.regex_str)
                #print("TEST AnalyseURL #2")
                return endpoints
        return endpoints


class SRI(IScanIssue,ITab):
    def __init__(self, reqres, helpers):
        self.helpers = helpers
        self.reqres = reqres

    def getHost(self):
        return self.reqres.getHost()

    def getPort(self):
        return self.reqres.getPort()

    def getProtocol(self):
        return self.reqres.getProtocol()

    def getUrl(self):
        return self.reqres.getUrl()

    def getIssueName(self):
        return "Linkfinder Analysed JS files"

    def getIssueType(self):
        return 0x08000000  # See http:#portswigger.net/burp/help/scanner_issuetypes.html

    def getSeverity(self):
        return "Information"  # "High", "Medium", "Low", "Information" or "False positive"

    def getConfidence(self):
        return "Certain"  # "Certain", "Firm" or "Tentative"

    def getIssueBackground(self):
        return str("JS files holds links to other parts of web applications. Refer to TAB for results.")

    def getRemediationBackground(self):
        return "This is an <b>informational</b> finding only.<br>"

    def getIssueDetail(self):
        return str("Burp Scanner has analysed the following JS file for links: <b>"
                      "%s</b><br><br>" % (self.reqres.getUrl().toString()))

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        #print ("................raising issue................")
        rra = [self.reqres]
        return rra
        
    def getHttpService(self):
        return self.reqres.getHttpService()
        
        
if __name__ in ('__main__', 'main'):
    EventQueue.invokeLater(Run(BurpExtender))
