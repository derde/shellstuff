#! /usr/bin/python

import sys,smtplib
import os
import socket
import optparse
import time
import base64
import signal

def getmx(domain):
    mx=[]
    f = os.popen("host -t mx "+domain,'r')
    for line in f:
        bits=line.split()
        if len(bits)<7: continue
        if bits[3]=='handled': mx.append(bits[6])
    return mx

def gencontent(n):
    s='abcdefghijklmnopqrstuvwxyz01234\n';
    return s*(n/len(s))+s[ : n % len(s)]

if __name__=="__main__":
    hostname = socket.gethostbyaddr(socket.gethostbyname(socket.gethostname()))[0]
    usage="Usage: %prog [options] account ... \n"
    parser=optparse.OptionParser(usage)
    parser.add_option("-P","--port",dest="port", action="store",type=int, default=25, help="TCP port")
    parser.add_option("-s","--ssl",dest="ssl", action="store_true", default=None)
    parser.add_option("-f","--from",dest="mailfrom", action="store", default=None)
    parser.add_option("-u","--user",dest="user", action="store", default=None, help="User")
    parser.add_option("-p","--password",dest="password", action="store", default=None, help="Password")
    parser.add_option("-t","--to",dest="to", action="append", default=[], help="Extra recipients")
    parser.add_option("-d","--data",dest="data", action="store", type='int', default=0);
    parser.add_option("-G","--gtube",dest="gtube", action="store_true", default=None, help="Send a spam test");
    parser.add_option("-E","--eicar",dest="eicar", action="store_true", default=None, help="Send a virus test");
    parser.add_option("-H","--helo",dest="helo", action="store", default=hostname);
    parser.add_option("-S","--sleep",dest="sleep", action="store",type='int', default=0, help="Sleep time between operations");
    parser.add_option("--timeout",dest="timeout",action='store', type='int', default=0, help="Overall timeout (alarm)");
    (options,args) = parser.parse_args()

    if options.timeout:
        signal.alarm(options.timeout)

    mailfrom = "mailer-daemon@" + hostname
    if options.mailfrom: mailfrom=options.mailfrom
    rcptto = args[0]
    user,domain = rcptto.split("@",1)

    rcpts=[rcptto]
    rcpts.extend(options.to);
    #rcpts.append ( user+"-bogus@"+domain)
    #rcpts.append ( "relaytest@"+hostname)
    if len(args)>1: mxlist=args[1:]
    else: mxlist=getmx(domain)

    split=False
    for mx in mxlist:
        try:
            if split: print ""
            print 'telnet '+mx,options.port
            server = smtplib.SMTP(mx,port=options.port,local_hostname=options.helo)
            server.id=os.getpid()
            server.set_debuglevel(1)
            if options.sleep: time.sleep(options.sleep)
            server.ehlo()
            if options.ssl:
                if options.sleep: time.sleep(options.sleep)
                server.starttls()
                if options.sleep: time.sleep(options.sleep)
                server.ehlo()
            if options.password:
                if options.user:
                    user=options.user
                else:
                    user=options.mailfrom
                #server.login(user,options.password)
                try:
                    # attempt a 'standard' login
                    if options.sleep: time.sleep(options.sleep)
                    server.login( user , options.password )
                except smtplib.SMTPAuthenticationError, e:
                    # if login fails, try again using a manual plain login method
                    if options.sleep: time.sleep(options.sleep)
                    server.docmd("AUTH LOGIN", base64.b64encode( user ))
                    if options.sleep: time.sleep(options.sleep)
                    server.docmd(base64.b64encode( options.password ), "")
            if options.data or options.gtube or options.eicar:
                content=''
                if options.eicar:
                    content+='X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n'
                if options.data:
                    content+=gencontent(options.data)
                    testtype='Test'
                if options.gtube:
                    content+='XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
                    testtype='GTUBE spam'
                data= (
                    "From: %(mailfrom)s\n"
                    "To: %(mailto)s\n"
                    "Date: %(date)s\n"
                    "Subject: %(testtype)s from %(mailfrom)s to %(mailto)s via %(mx)s\n"
                    "\n"
                    "Hello\n%(content)s"
                ) % {
                    'date': time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime()),
                    'mailfrom': mailfrom,
                    'mailto': ', '.join(rcpts),
                    'mx': mx,
                    'content': content,
                    'testtype': testtype,
                }
                if options.sleep: time.sleep(options.sleep)
                server.sendmail(mailfrom,rcpts,data)
            else:
                if options.sleep: time.sleep(options.sleep)
                server.mail(mailfrom)
                for rcptto in rcpts:
                    if options.sleep: time.sleep(options.sleep)
                    server.rcpt(rcptto)
            # server.rset()
            if options.sleep: time.sleep(options.sleep)
            server.quit()
            split=True
        except:
            # http://docs.python.org/library/traceback.html
            import traceback
            exc_type, exc_value, exc_traceback = sys.exc_info()
            #print "*** print_tb:"
            #traceback.print_tb(exc_traceback, limit=1, file=sys.stderr)
            print "*** print_exception:"
            traceback.print_exception(exc_type, exc_value, exc_traceback, limit=2, file=sys.stdout)
