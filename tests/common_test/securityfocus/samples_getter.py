import pycurl
from io import BytesIO

"""simple program to download a html page from an url."""

def get_sample(url, dest_file_name):
    buffer = BytesIO()
    print(url)
    c = pycurl.Curl()
    c.setopt(c.URL, url)
    c.setopt(c.WRITEDATA, buffer)
    c.perform()
    c.close()

    body = buffer.getvalue()

    file = open(dest_file_name, 'wb')
    file.write(body)
    file.close()

def __main__():
    url = input("enter url:")
    dest_file_name = input("enter destination file name (with extension):")
    get_sample(url, dest_file_name)

__main__()
