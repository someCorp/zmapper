# zmapper
# a wrapper around to zmap to scan a range of ports
# and send a compressed csv via email with the results

/some/place/zmapper.py --destinations someWhoCares@somedomain.tld --net2Scan somePublicNet/CIDRMask -sp N -ep N+1

(where N its a number)

in cron usages , you should use :

crontab -l
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
@monthly       /some/place/zmapper.py --destinations someWhoCares@somedomain.tld --net2Scan somePublicNet/CIDRMask -sp N -ep N+1

after a while, depending on how big is/was the net 2 scan and the how big is/was the port range to scan , you'd get a compressed csv file, with contents similar to the following

"IP","1","2","3","4","5","6","7","8","9","10"
"somePublicIp","close","close","close","close","close","close","close","close","close","close"
"somePublicIp","close","open","close","close","close","close","close","close","open","close"
"somePublicIp","close","close","close","close","open","close","close","close","close","close"


i suggest start with small nets and small ranges and start to incresing the scope, and do not forget zmap's scanning best practices

(extracted from https://zmap.io/documentation.html)



We offer these suggestions for researchers conducting Internet-wide scans as guidelines for good Internet citizenship.

    Coordinate closely with local network administrators to reduce risks and handle inquiries
    Verify that scans will not overwhelm the local network or upstream provider
    Signal the benign nature of the scans in web pages and DNS entries of the source addresses
    Clearly explain the purpose and scope of the scans in all communications
    Provide a simple means of opting out and honor requests promptly
    Conduct scans no larger or more frequent than is necessary for research objectives
    Spread scan traffic over time or source addresses when feasible

It should go without saying that scan researchers should refrain from exploiting vulnerabilities or accessing protected resources, and should comply with any special legal requirements in their jurisdictions.
