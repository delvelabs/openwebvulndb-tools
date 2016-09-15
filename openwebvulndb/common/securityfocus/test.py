import re
import pycurl
from io import BytesIO
'''
buffer = BytesIO()
url = 'http://www.securityfocus.com/bid/92841/info'
c = pycurl.Curl()
c.setopt(c.URL, url)
c.setopt(c.WRITEDATA, buffer)
c.perform()
c.close()

body = buffer.getvalue()

file = open('vuln' + '.html', 'wb')
file.write(body)
file.close()
'''
file = open('vuln' + '.html', 'r')
str_file = file.read()

title = re.search('"title">.*?<', str_file)
str_title = title.group()
str_title = re.sub('"title">', '', str_title)
str_title = re.sub('<', '', str_title)

bugtraqid = re.search('Bugtraq ID\D*\d*', str_file, re.S)
str_bugtraqid = bugtraqid.group()
str_bugtraqid = re.sub('\D*', '', str_bugtraqid)
print(str_bugtraqid)

file.close()
