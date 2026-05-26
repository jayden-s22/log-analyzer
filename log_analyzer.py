import re #regular expressions (regex)
import sys #system interface
import json #JSON handling
import time
from datetime import datetime
from collections import defaultdict, Counter #data structures
from pathlib import Path #filepaths

BRUTE_FORCE_THRESHOLD = 5
AUTH_LOG = '/var/log/auth.log'
APACHE_LOG = '/var/log/apache2/access.log'
REPORT_OUTPUT = 'report.html'

SSH_FAILED = re.compile(r'(\d{4}-\d{2}-\d{2}T[\d:\.]+[+-][\d:]+)\s+\S+\s+sshd.*Failed password for (\S+) from ([\d.]+)')
#ex failed ssh log format:  Mar     10  12:34:56  sshd[x]: Failed password for    from 192.168.1.1
#                                               ^servername                   ^user

SSH_ACCEPTED = re.compile(r'(\d{4}-\d{2}-\d{2}T[\d:\.]+[+-][\d:]+)\s+\S+\s+sshd.*Accepted password for (\S+) from ([\d.]+)')

APACHE_ACCESS = re.compile(r'([\d.]+).*\[(.+?)\].*"(\w+)\s+(/\S*).*"\s+(\d{3})')
#ex apache log format:   192.168.1.1 [10/Mar/...] "GET  /index.html "   200
#                                                                  ^HTTP/x  ^response size

def parse_auth_log(filepath):
    failed = defaultdict(list) #data structure that holds failed login attempts
    accepted = [] #list for succesful logins
    try:
        with open(filepath, 'r') as f: #open 'filepath' in read mode, auto close when finished using 'with'
            for line in f: #iterates line-by-line through 'filepath'
                m= SSH_FAILED.search(line) #returns true if pattern is found in line, otherwise None
                if m is not None:
                    timestamp, user, ip = m.group(1), m.group(2), m.group(3) #retrieves captured text and stores in timestamp, user, and ip
                    failed[ip].append({'time':timestamp, 'user': user}) #creates new dictionaries in 'failed' by ip for each failed login
                    continue
                m = SSH_ACCEPTED.search(line)
                if m is not None:
                    accepted.append({'time': m.group(1), 'user': m.group(2), 'ip': m.group(3)})#creates new dictionaries in 'accepted' for each successful login
    except FileNotFoundError: #if (open) cannot find file at given path, prints warning
        print(f'Warning: {filepath} not found')
    return failed, accepted #returns the 'failed' and 'accepted' data structs

def detect_brute_force(failed_attempts):
    threats = [] #accumulate threat dictionaries
    for ip, attempts in failed_attempts.items():
        if len(attempts) >= BRUTE_FORCE_THRESHOLD: #tells if number of failed attempts from an ip exceeds 'BRUTE_FORCE_THRESHOLD'
            threats.append({#appends new dictionary to 'threats'
                            'ip':ip, 
                            'count': len(attempts), 
                            'severity': 'HIGH' if len(attempts) > 20 else 'MEDIUM', 
                            'attempts': attempts[:5]})  
    return sorted(threats, key=lambda x: x['count'], reverse=True) #returns sorted list of threats by count in descending order

def parse_apache_log(filepath):
    status_counts = Counter() #creates empty dictionary for how many times each HTTPS status code appears
    ip_counts = Counter() #counts requests per IP
    suspicious_paths = [] #accumulate suspicious_paths dictionaries

    SUSPICIOUS = ['/admin', '/wp-admin', '/phpmyadmin', '/env', 'etc/passwd', 'shell'] #detection paths for common attack vectors

    try:
        with open(filepath, 'r') as f:
            for line in f:
                m = APACHE_ACCESS.search(line) #searches for pattern in line, returns match object if found, otherwise None
                if m:
                    ip, ts, method, path, status = m.groups() #returns all groups as a single tuple, which is unpacked into ip, ts, method, path, and status
                    status_counts[status] +=1 #increments count of status code in 'status_counts' Counter
                    ip_counts[ip] += 1 #increments count of requests from ip in 'ip_counts' Counter
                    if any(s in path for s in SUSPICIOUS): #'if any suspicious path strings in request's path, flag'
                        suspicious_paths.append({'ip': ip, 'path': path, 'status': status}) #appends new dictionary with ip, path, and status of request
    except FileNotFoundError:
        print(f'{filepath} not found')
    return {
        'status_counts': dict(status_counts), #returns dictionary of status_counts Counter
        'top_ips': ip_counts.most_common(10), #returns list of 10 most common IPs and their counts from 'ip_counts' Counter
        'suspicious_paths': suspicious_paths #returns list of dictionaries for requests flagged as suspicious
    }

def generate_html_report(ssh_threats, ssh_accepted, web_stats):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    total_threats = len(ssh_threats)
    
    html = f'''<!DOCTYPE html>
<html><head><meta charset='UTF-8'>
<title>Log Analysis Report</title>
<style>
  body {{ font-family: Arial, sans-serif; background: #0f0f1a; color: #e0e0e0; padding: 30px; }}
  h1 {{ color: #4fc3f7; }} h2 {{ color: #80deea; border-bottom: 1px solid #333; padding-bottom: 6px; }}
  .threat {{ background: #1a1a2e; border-left: 4px solid #ef5350; padding: 12px; margin: 8px 0; border-radius: 4px; }}
  .high {{ border-left-color: #ef5350; }} .medium {{ border-left-color: #ff9800; }}
  .safe {{ color: #66bb6a; }} .danger {{ color: #ef5350; }}
  table {{ border-collapse: collapse; width: 100%; }} td,th {{ padding: 8px 12px; text-align: left; }}
  th {{ background: #1a3a4a; }} tr:nth-child(even) {{ background: #1a1a2e; }}
  .badge {{ padding: 3px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; }}
  .HIGH {{ background: #ef5350; }} .MEDIUM {{ background: #ff9800; color: #000; }}
</style></head><body>
<h1>Security Log Analysis Report</h1>
<p>Generated: {now} | Threats Found: <span class='{"danger" if total_threats else "safe"}'>{total_threats}</span></p>
<hr>
<h2>SSH Brute Force Threats</h2>
'''
#creates HTML report with inline CSS styling, 
#includes sections for SSH brute force threats, successful logins, and web server activity
#uses conditional formatting to highlight threats and safe status

    
    if not ssh_threats: #condition for empty 'ssh_threats' list, if no threats detected
        html += '<p class="safe">No brute force attacks detected.</p>' 
    else:
        for t in ssh_threats:
            html += f'''<div class="threat {t['severity']}">
  <strong>IP: {t['ip']}</strong> — <span class="badge {t['severity']}">{t['severity']}</span>
  &nbsp; {t['count']} failed attempts<br>
  <small>Sample attempts: {', '.join(a['user'] for a in t['attempts'][:3])}</small>
</div>'''
#concatenates HTML for each detected SSH brute force threat, 
#showing IP, severity, # of failed attempts, and usernames attempted
    
    html += '<h2>Successful SSH Logins</h2>'
    if not ssh_accepted:
        html += '<p>No successful logins found.</p>'
    else:
        html += '<table><tr><th>Time</th><th>User</th><th>IP</th></tr>'
        for a in ssh_accepted[-10:]:#last 10 successful logins
            html += f'<tr><td>{a["time"]}</td><td>{a["user"]}</td><td>{a["ip"]}</td></tr>'
        html += '</table>'
    
    html += '<h2>Web Server Activity</h2>'
    html += '<table><tr><th>HTTP Status</th><th>Count</th></tr>'
    for status, count in sorted(web_stats['status_counts'].items()): #sorts status codes in ascending order
        html += f'<tr><td>{status}</td><td>{count}</td></tr>'
    html += '</table>'
    
    if web_stats['suspicious_paths']:
        html += '<h2>Suspicious Web Requests</h2><table><tr><th>IP</th><th>Path</th><th>Status</th></tr>'
        for r in web_stats['suspicious_paths'][:20]: #shows first 20 suspicious requests
            html += f'<tr><td>{r["ip"]}</td><td>{r["path"]}</td><td>{r["status"]}</td></tr>'
        html += '</table>'
    
    html += '</body></html>' #closes HTML document
    return html

def detect_port_scans(apache_log_path):
    from collections import defaultdict
    ip_requests = defaultdict(int) #counts requests per IP address, defaulting to 0 for new IPs
    scanner_signatures = ['Nikto', 'nmap', 'masscan', 'zgrab', 'python-requests', 'curl/7'] #common user agent signatures for port scanning tools

    scanners_detected = [] #list for confirmed signatures of port scanning activity

    SCAN_THRESHOLD = 50 #thrshold of requests to flag as possible port scan

    try:
          with open(apache_log_path, 'r') as f:
            for line in f:
                m = re.match(r'([\d.]+)', line) #matches IP address at start of line
                if m:
                    ip_requests[m.group(1)] += 1 #increments request count for matched IP address, making a full list of how many requests each IP has made
                for sig in scanner_signatures: #iterates over every signature string
                    if sig.lower() in line.lower(): #looks for agent signature in line
                        ip_match = re.match(r'([\d.]+)', line) #if signature is found, tries to match IP address at start of line to identify source of scan
                        if ip_match:
                            scanners_detected.append({'ip': ip_match.group(1), 'tool': sig}) #if match is found, appends to 'scanners_detected' dictionary with IP and tool name
    except FileNotFoundError:
        pass
    high_volume = [{'ip': ip, 'count': count, 'type': 'HIGH_VOLUME_SCAN'} 
                    for ip,count in ip_requests.items() if count >= SCAN_THRESHOLD] #creates list of dictionaries for IPs that have made more than 'SCAN_THRESHOLD' requests, flagged as 'HIGH_VOLUME_SCAN'

    return high_volume + scanners_detected

def watch_live(log_path, threshold=5):
    print(f' Watching {log_path} for attacks (Ctrl+C to stop)')
    ip_counts = {}

    with open(log_path, 'r') as f:
        f.seek(0,2) #jumps to end of file to only read new lines as they are added
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            m = SSH_FAILED.search(line) #checks every new line for failed SSH login pattern
            if m:
                ip = m.group(3) #extracts IP address from matched line
                ip_counts[ip] = ip_counts.get(ip, 0) + 1 #increments count of failed attempts for that IP, defaulting to 0 if IP is new
                count = ip_counts[ip] #stores current count of failed attempts for that IP
                print(f'Failed login from {ip} (attempt #{count})') #prints message for each failed login attempt, showing IP and current count
                if count == threshold:
                    print(f' ALERT: {ip} has hit {threshold} failures - BRUTE FORCE DETECTED') #when count reaches threshold, prints alert message indicating brute force attack detected from that IP


def main():

    
    print('Log Analyzer Starting...')
    print(f' Analyzing: {AUTH_LOG}')
    failed_ssh, accepted_ssh = parse_auth_log(AUTH_LOG) #parses auth log and returns data for failed and accepted SSH logins

    print(' Detecting brute force attacks...')
    threats = detect_brute_force(failed_ssh) #analyzes failed SSH logins to identify brute force attacks, returns list of detected threats

    print(f' Analyzing: {APACHE_LOG}')
    web_stats = parse_apache_log(APACHE_LOG) #parses Apache log to gather statistics on status codes, IPs, and suspicious requests
    
    print(f' Generating HTML report...')
    report = generate_html_report(threats, accepted_ssh, web_stats) #renders HTML report based on detected SSH threats, successful logins, and web server activity

    with open(REPORT_OUTPUT, 'w') as f:
        f.write(report)

    print(f' Report saved to {REPORT_OUTPUT}') #saves generated report to file
    print(f' SSH threats detected: {len(threats)}') #prints number of detected SSH brute force threats
    print(f' Succesful logins: {len(accepted_ssh)}') #prints number of successful SSH logins
    print(f' Suspicious web requests: {len(web_stats["suspicious_paths"])}') #prints number of web requests flagged as suspicious

if __name__ == '__main__':
    if '--watch' in sys.argv:
        watch_live(AUTH_LOG)
    else:
        main()