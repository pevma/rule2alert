from subprocess import Popen, PIPE
import re

class SnortAlert:
    def __init__(self, gid, sid, rev, msg):
        #Trust only the sid...
        self.sid = sid
        self.gid = gid
        self.rev = rev
        self.msg = msg

    def __str__(self):
        return "[**] [%s:%s:%s] %s [**]" % (self.gid, self.sid, self.rev, self.msg)

class TestSuricata:
    
    def __init__(self, pcap, loaded_sids, pass_the_options):
	
        self.ruleFile = pass_the_options.rule_file
        self.alerts = []
        self.alert_sids = []
        self.failSids = []
        self.goodSids = []
        self.pcap = pcap
        self.loaded_sids = loaded_sids
	
	if not pass_the_options.suri_log:
	  self.logfile = "/var/log/suricata/fast.log"
	  self.logfile_run_option = ""
	else:
	  self.logdir = pass_the_options.suri_log
	  self.logfile = pass_the_options.suri_log+"fast.log"
	  self.logfile_run_option = "-l " + self.logdir
	    
	if not pass_the_options.suri_conf:
	  self.suri_conf = "/etc/suricata/suricata.yaml"
	else:
	  self.suri_conf = pass_the_options.suri_conf
	  
	if not pass_the_options.suri_binary:
	  self.suri_binary = "suricata"
	else:
	  self.suri_binary = pass_the_options.suri_binary
	
	
	self.cmd    = "%s -c %s %s -S %s -r %s" % (self.suri_binary, self.suri_conf, self.logfile_run_option, self.ruleFile, self.pcap)
	

    def run(self):
        p = Popen(self.cmd, shell=True, stdout=PIPE, stderr=PIPE)
	#p.wait()
	p.communicate()

	f = open(self.logfile, 'r')
	alerts = f.read().splitlines()
	f.close()

        sig_reg = re.compile(r'\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s*(?P<msg>.*)\s*\[\*\*\]')

        for alert in alerts:
            m = sig_reg.search(alert)
            if m:
                try:
                    s = SnortAlert(m.group("gid"),m.group("sid"),m.group("rev"),m.group("msg"))
                    self.alerts.append(s)
                    if not s.sid in self.alert_sids:
                        self.alert_sids.append(s.sid)
                        #print s.sid, alert
                except:
                    print "Error parsing alert: %s" % alert

        if len(self.alerts) == len(self.loaded_sids):
            print "Successfully alerted on all loaded rules"
            self.goodSids = self.loaded_sids
            self.badSids = []
        #elif len(self.alerts) < len(self.loaded_sids):
	else:
            f = open("output/fail_suricata.log",'w')
            f2 = open("output/success_suricata.log",'w')
            missed = 0
            success = 0
            for sid in self.loaded_sids:
                if not sid in self.alert_sids:
                    missed += 1
                    self.failSids.append(sid)
                    f.write(sid + "\n")
                if sid in self.alert_sids:
                    success += 1
                    self.goodSids.append(sid)
                    f2.write(sid + "\n")
                    
            print "\n" ,"Alerted on %d rules" % success
            print "Failed to alert on %d rules" % missed, "\n"
                    
            f.close()
            f2.close()

        return self.failSids, self.goodSids
            
    def readSnortAlerts(self):
        #12/21-16:14:50.971883  [**] [1:20000000:1] Snort alert [**] [Priority: 0] {TCP} 192.168.0.1:9001 -> 1.1.1.1:80
        #                            [gid:sid:rev]
        p = re.compile(r'\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s*(?P<msg>.*)\s*\[\*\*\]')
        f = open(self.logfile, "r")
        for line in f.read().splitlines():
            m = p.search(line)
            if m:
                try:
                    self.alerts.append(SnortAlert(m.group("gid"),m.group("sid"),m.group("rev"),m.group("msg")))
                except:
                    print "Error parsing alert from " + str(line)

        if len(self.alerts) > 0:
            self.clearLog()

    def printAlerts(self):
        for alert in self.alerts:
            print alert
