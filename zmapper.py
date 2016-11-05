#!/usr/bin/env python
""" do 3 way-handshake over a given net, on given port(s) and return a compressed csv by email"""
try:
  import sys
except ImportError:
  errMsg = "\nfailed lib, try pip install sys\n"
  sys.stderr.write(errMsg)
  sys.exit(1)
try:
  import os
except ImportError:
  errMsg = "\nfailed lib, try pip install os\n"
  sys.stderr.write(errMsg)
  sys.exit(1)
try:
  import datetime
except ImportError:
  errMsg = "\nfailed lib, try pip install datetime\n"
  sys.stderr.write(errMsg)
  sys.exit(1)
try:
  import tempfile
except ImportError:
  errMsg = "\nfailed lib, try pip install tempfile\n"
  sys.stderr.write(errMsg)
  sys.exit(1)
try:
  from netaddr import IPNetwork
except ImportError:
  errMsg = "\nfailed lib, try pip install netaddr\n"
  sys.stderr.write(errMsg)
  sys.exit(1)
try:
  import uuid
except ImportError:
  errMsg = "\nfailed lib, try pip install uuid\n"
  sys.stderr.write(errMsg)
  sys.exit(1)
try:
  import fnmatch
except ImportError:
  errMsg = "\nfailed lib, try pip install fnmatch\n"
  sys.stderr.write(errMsg)
  sys.exit(1)
try:
  import csv
except ImportError:
  errMsg = "\nfailed lib, try pip install csv\n"
  sys.stderr.write(errMsg)
  sys.exit(1)
try:
  import smtplib
except ImportError:
  errMsg = "\nfailed lib, try pip install smtplib\n"
  sys.stderr.write(errMsg)
  sys.exit(1)
try:
  from email.MIMEMultipart import MIMEMultipart
  from email.MIMEBase import MIMEBase
  from email.MIMEText import MIMEText
  from email import Encoders
  from os.path import basename
except ImportError:
  errMsg = "\nfailed lib, try pip install email\n"
  sys.stderr.write(errMsg)
  sys.exit(1)
try:
  import shutil
except ImportError:
  errMsg = "\nfailed lib, try pip install shututil\n"
  sys.stderr.write(errMsg)
  sys.exit(1)
try:
  import argparse
except ImportError:
  errMsg = "\nfailed lib, try pip install argparse\n"
  sys.stderr.write(errMsg)
  sys.exit(1)
try:
  from distutils.spawn import find_executable
except ImportError:
  errMsg = "\nfailed lib, try pip install disutils\n"
  sys.stderr.write(errMsg)
  sys.exit(1)

try:
  import zipfile
except ImportError:
  errMsg = "\nfailed lib, try pip install zipfile\n"
  sys.stderr.write(errMsg)
  sys.exit(1)


#  some constants
zmapIface = "eth1"
zmapSourcePortRange = "1024-65535"
zmapSourceAddress = "189.145.6.4"
zmapMacOfRouter = "c0:67:af:6c:71:80"
zmapMaxFailures = "10000000"
zmapStaticArguments = "--disable-syslog --quiet -v0"
zmapOutFields = "--output-fields=saddr,sport"
zmapProbeNumber = "-P1"
mailFrom = "zmapper@somedomain.tld"
smtpServer = "localhost"
smtpUser = ""
smtpPass = ""


def checkForZmap():
  """ this function do something """
  hashToReturn = {}
  zmapFlag = False
  zmapBin = "/dev/null"
  try:
    hashToReturn['zmapBin'] = find_executable('zmap')
    if hashToReturn['zmapBin'] != None:
      hashToReturn['zmapFlag'] = True
  except OSError:
    hashToReturn['zmapFlag'] = zmapFlag
    hashToReturn['zmapBin'] = zmapBin
  return hashToReturn


def getArgs():
  """ this function do something """
  hashToReturn = {}
  if len(sys.argv) == 1:
    errMsg = "\nbad args\n\n" + "exec " + sys.argv[0] + " -h to get help\n\n"
    sys.stderr.write(errMsg)
    sys.exit(3333)
  try:
    parser = argparse.ArgumentParser(description="3 way handshake scanner and reporter", version='0.0.0a')
    parser.add_argument("-d", "--destinations", help="email destination(s) for the report separated by \",\"",
                        type=str, required=True, default="root@somedomain.tld")
    parser.add_argument("-ns", "--net2Scan", help="net 2 scan , in cidr format ",
                        type=IPNetwork, required=True, default='127.0.0.0/8')
    parser.add_argument("-ne", "--net2Exclude", help="subnet 2 exclude in scan,  in cidr format ",
                        type=IPNetwork, required=False, default='127.0.0.0/24')
    parser.add_argument("-sp", "--startPort", help="port to start scan ",
                        type=int, required=False, default='1')
    parser.add_argument("-ep", "--endPort", help="port to end scan ",
                        type=int, required=False, default='65535')
    args = parser.parse_args()
    allEmails = args.destinations
    hashToReturn = {}
    hashToReturn['net2Exclude'] = args.net2Exclude
    hashToReturn['net2Scan'] = args.net2Scan
    hashToReturn['destinations'] = str(allEmails).split(",", 1)
    hashToReturn['startPort'] = args.startPort
    hashToReturn['endPort'] = args.endPort
  except StandardError as err:
    errMsg = "\nsomething was with arg capture"
    sys.stderr.write(errMsg)
    sys.stderr.write("\n" + str(err) + "\n")
    sys.exit(9)
  return hashToReturn


def showHelp():
  """ this function do something """
  pass


def asRoot():
  """ this function do something """
  try:
    if not os.geteuid() == 0:
      errMsg = "\nOnly root can run this script\n"
      sys.stderr(errMsg)
      sys.exit(2)
  except StandardError as err:
    errMsg = "\nrunning as non root user\n"
    sys.stderr.write(errMsg)
    sys.stderr.write("\n" + str(err) + "\n")
    sys.exit(2)


def generateTmpDir():
  """ this function do something """
  tmpdirname = None
  try:
    tmpdirname = tempfile.mkdtemp()
  except EnvironmentError:
    tmpdirname = "/tmp"
  finally:
    return tmpdirname


def generateExcludeFile(netToExclude='127.0.0.1/8', someDir="/tmp"):
  """ this function do something """
  tmpFile = tempfile.mkstemp(suffix=".exclude-zmap", dir=someDir, prefix=str(uuid.uuid4()))
  with open(tmpFile[1], 'w') as fh:
    fh.write(netToExclude)
    fh.write("\n")
    fh.close()
  return tmpFile[1]


def composeZmapScanCommand(zmapBin="/usr/bin/zmap", net2scan="1.1.1.0/16", port=0, blacklist="/dev/null", someDir="/tmp/"):
  """ this function do something """
  zmapCmd = zmapBin + " " + zmapStaticArguments
  zmapCmd = zmapCmd + " " + zmapProbeNumber
  zmapCmd = zmapCmd + " " + "-i" + " " + zmapIface
  zmapCmd = zmapCmd + " " + "-s" + " " + zmapSourcePortRange
  zmapCmd = zmapCmd + " " + "-S" + " " + zmapSourceAddress
  zmapCmd = zmapCmd + " " + "--max-sendto-failures" + "=" + zmapMaxFailures
  zmapCmd = zmapCmd + " " + "--gateway-mac" + "=" + zmapMacOfRouter
  zmapCmd = zmapCmd + " " + "--blacklist-file" + "=" + blacklist
  zmapCmd = zmapCmd + " " + zmapOutFields
  zmapCmd = zmapCmd + " " + "-p" + " " + str(port)
  zmapCmd = zmapCmd + " " + net2scan
  zmapCmd = zmapCmd + " " + "-o" + " " + someDir + "/" + str(port) + ".zmap"
  return zmapCmd


def cleanUp(someDir="/tmp"):
  """ this function do something """
  if someDir == "/tmp":  # improve this with a positive regexp
    cmd = "find" + " " + someDir + " -mindepth 1" + " " + r"-exec rm -rf {} \;"  # this shit is so ugly
    os.system(cmd)
  else:
    shutil.rmtree(someDir, ignore_errors=False, onerror=None)


def getListOfZmapeds(someDir="/tmp"):
  """ this function do something """
  listOfFilesWithData = ()
  for root, dirs, files in os.walk(someDir):
    for fileName in fnmatch.filter(files, '*.zmap'):
      fileWithPath = root + "/" + fileName
      listOfFilesWithData = listOfFilesWithData + (fileWithPath, )
  return listOfFilesWithData


def doTheZmapStuff(cmd="/bin/false"):
  """ this function do something """
  os.system(cmd)


def sortDataPerIp(netToSortPerIp='1.1.1.0/16', zmapDestPortRange=range(0, 0, 1), someFiles="/dev/null", someDir="/tmp"):
  """ this function do something """
  rows = []
  for addr in IPNetwork(netToSortPerIp):
    row = []
    portline = {}
    portsEvaluation = []
    for port in zmapDestPortRange:
      isIpInFile = "close"
      expectedFileName = someDir + "/" + str(port) + ".zmap"
      ipPortTuple = str(addr) + "," + str(port)
      for f in someFiles:
        if expectedFileName == f:
          with open(f, 'r') as lines:
            for line in lines:
              if ipPortTuple in line:
                isIpInFile = "open"
      portsEvaluation.append(isIpInFile)
      portline[str(addr)] = portsEvaluation
    key = str(addr)
    data = portline[key]
    row.append(key)
    #  print str(key) + " -> " + str(data)
    for ans in data:
      row.append(ans)
    rows.append(row)
  return rows


def csvWriter(rows=None, portRange=range(0, 0, 1), someDir="/tmp"):
  """ this function do something """
  try:
    tmpFile = tempfile.mkstemp(suffix=".csv", dir=someDir, prefix=str(uuid.uuid4()))
    ofile = open(tmpFile[1], "a+", buffering=True)
    writer = csv.writer(ofile, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL, lineterminator='\n', skipinitialspace=True)
    headings = ["IP"]
    for port in portRange:
      headings.append(port)
    writer.writerow(headings)
    for row in rows:
      writer.writerow(row)
  except EnvironmentError:
    ofile = "/dev/null"
  finally:
    ofile.close
    return ofile


def composeMail(mode="text"):
  """ this function do something """
  if mode == "text":
    msg = """Hola!\
    \n\nAdjunto Resultados del escaneo usando zmap:\n\n
--<br>
Atte/Kindly
Zmapper

Fono/Phone: +50 33333333
Email: zmapper@somedomain.tld
"""
  elif mode == "html":
    msg = """\
<html>
<head></head>
<body>
Hola!<br><br>
<p>Adjunto resultados del escaneo usando zmap.</p>
<br><br>
<p>
--<br>
Atte/Kindly<br><br>
Zmapper<br>
Fono/Phone: +50 33333333<br>
Email: zmapper@somedomain.tld<br>
Web: http://www.somepage.tld<br>
</p><br>
</body><br>
</html><br>
"""
  return msg


def sendFileByMail(someFile="/dev/null", server="localhost", authUser="someUser",
                   authPass="somePass", mailFrom="zmapper@somedomain.tld", mailTo="zmapper@somedomain.tld"):
  """ this function do something """
  try:
    msg = MIMEMultipart('alternative')
    subject = "Zmap Results"
    msg['Subject'] = subject
    msg['From'] = mailFrom
    if isinstance(mailTo, (tuple, list)):
      for d in mailTo:
        msg['To'] = d
    elif isinstance(mailTo, str):
      msg['To'] = mailTo
    text = composeMail("text")
    html = composeMail("html")
    part1 = MIMEText(text, 'plain')
    part2 = MIMEBase('application', "zip")
    part3 = MIMEText(html, 'html')
    someCompressedFile = compressFile(someFile)
    part2.set_payload(open(someCompressedFile, "rb").read())
    Encoders.encode_base64(part3)
    part2.add_header('Content-Disposition', 'attachment; filename=\"' + basename(someCompressedFile) + '\"')
    msg.attach(part1)
    msg.attach(part2)
    msg.attach(part3)
    server = smtplib.SMTP(server)
    # server.set_debuglevel(1)
    server.sendmail(mailFrom, mailTo, msg.as_string())
  except StandardError as e:
    errMsg = "\nsome error on mail stuff\n" + "\n\n" + str(e) + "\n\n"
    sys.stderr.write(errMsg)
    sys.exit(5)
  finally:
    pass


def compressFile(someFile="/dev/null"):
  """ this function do something """
  someFileToCompress = str(someFile).replace(".csv", ".zip")
  someCompressedFile = zipfile.ZipFile(someFileToCompress, mode='w')
  try:
    someCompressedFile.write(someFile, compress_type=zipfile.ZIP_DEFLATED)
  finally:
    someCompressedFile.close()
  return someFileToCompress


def main():
  """ this function do something """
  try:
    generalStartTime = datetime.datetime.today()
    asRoot()
    zmapCheckResults = checkForZmap()
    if zmapCheckResults['zmapBin'] == None:
      errMsg = "\nzmap not found!!\n"
      sys.stderr.write(errMsg)
      sys.exit(3333)
    zmapBin = zmapCheckResults['zmapBin']
    args = getArgs()
    try:
      receivers = args['destinations']
      scnNet = args['net2Scan']
      excNet = args['net2Exclude']
      startPort = args['startPort']
      endPort = args['endPort']
      if not endPort >= startPort:
        errMsg = "\nstarting port MUST BE lower or equal that ending port\n"
        sys.stderr.write(errMsg)
        sys.exit(3334)
      zmapDestPortRange = range(startPort, endPort + 1, 1)
    except StandardError:
      receivers = ""
      scnNet = ""
      excNet = ""
      startPort = 0
      endPort = 0
      zmapDestPortRange = range(startPort, endPort + 1, 1)
      errMsg = "\nsomething was wrong, getting args!!\n"
      sys.stderr.write(errMsg)
      sys.exit(6767)
    someDir = generateTmpDir()
    excludeFile = generateExcludeFile(str(excNet), someDir)
    for port in zmapDestPortRange:
      portStartTime = datetime.datetime.today()
      doTheZmapStuff(composeZmapScanCommand(zmapBin, str(scnNet), port, excludeFile, someDir))
      portEndTime = datetime.datetime.today()
      print "zmap over port " + str(port) + " exec time : " + str(portEndTime - portStartTime)
    generalEndTime = datetime.datetime.today()
    print "total scan time : " + str(generalEndTime - generalStartTime)
    sortStartTime = datetime.datetime.today()
    filesToSort = getListOfZmapeds(someDir)
    rowsToWrite = sortDataPerIp(scnNet, zmapDestPortRange, filesToSort, someDir)
    outputFile = csvWriter(rowsToWrite, zmapDestPortRange, someDir)
    sendFileByMail(outputFile.name, smtpServer, smtpUser, smtpPass, mailFrom, receivers)
    sortEndTime = datetime.datetime.today()
    print "total sort time : " + str(sortEndTime - sortStartTime)
    cleanUp(someDir)
    print "total time : " + str((datetime.datetime.today()) - generalStartTime)
  except StandardError as err:
    errMsg = "\nsomething was wrong, run in circles!!\n"
    sys.stderr.write(errMsg)
    sys.stderr.write("\n" + str(err) + "\n")
    sys.exit(6868)


if __name__ == "__main__":
  try:
    main()
  except StandardError as err:
    # handle more properly the exceptions on each function
    errMsg = "\nsomething was wrong, run in circles!!\n"
    sys.stderr.write(errMsg)
    sys.stderr.write("\n" + str(err) + "\n")
    sys.exit(6969)
  finally:
    print "bye, have a nice day"
