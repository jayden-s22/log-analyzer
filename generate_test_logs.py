import random
from datetime import datetime, timedelta

attacker_ips = ['185.220.101.5', '45.33.32.156', '198.51.100.1', '10.0.0.1']
usernames = ['root', 'admin', 'test', 'ubuntu', 'postgres', 'oracle']
start = datetime.now() - timedelta(hours=2)

lines = []
for i in range(150):
    ip = random.choice(attacker_ips)
    user = random.choice(usernames)
    t = (start + timedelta(seconds=i*45)).strftime('%b %d %H:%M:%S')
    lines.append(f'{t} server sshd[1234]: Failed password for {user} from {ip} port {30000+i} ssh2')

lines.append(f'{start.strftime("%b %d %H:%M:%S")} server sshd[9891]: Accepted password for john from 192.168.1.50 port 442 ssh2')
lines.append(f'{start.strftime("%b %d %H:%M:%S")} server sshd[9892]: Accepted password for alice from 192.168.1.51 port 443 ssh2')

with open('/tmp/test_auth.log', 'w') as f:
    f.write('\n'.join(lines))
print('Test log written to /tmp/test_auth.log')