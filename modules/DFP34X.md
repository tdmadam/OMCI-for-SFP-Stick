#### Prerequisite:

Wireshark with the <b>omci.lua</b> and <b>BinDecHex.lua</b> plug-ins installed.


#### Procedure:
For the DFP-34X-2C2 OMCI logs capturing, configure the following option

```
# flash set OMCI_LOGFILE 1
# reboot
```
The logs will be available at /tmp/omcilog. 

##### To convert the omcilog to hex format readable by Wireshark
   
```
cat omcilog | sed -e 's/^/000000 /' > omci.hex
```

##### To open the file omci.hex in Wireshark
```
File -> Import from Hex Dump
Encapsulation Type -> Ethernet
set Ethernet -> Ethertype (hex): 88b5
Import
```


   
##### To have the omcilog converted to the pcap format, the following script should be used with the original omcilog file   
```cat omcilog | sed '{s/^/20 52 45 43 56 00 20 53 45 4e 44 00 88 b5 /g;s/^/000000 /}' > omci.pcp
text2pcap omci.pcp omci.pcap
```
After capturing don't forget to disable OMCI_LOGFILE 0
   
