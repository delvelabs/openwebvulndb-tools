from lxml import etree
import re

parser = etree.HTMLParser()
tree = etree.parse("wordpress_vuln_with_cve.html", parser)
title = tree.xpath('//span[@class="title"]/text()') #return le text dans tous les elements span avec l'attribut class="title"
title = title[0]
print(title)
bugtraqid = tree.xpath('//span[text() = "Bugtraq ID:"]/../../td[2]/text()')
bugtraqid = re.sub("\D", "", bugtraqid[0])  # removes the white spaces around the bugtraq ID in the <td>
print(bugtraqid)
