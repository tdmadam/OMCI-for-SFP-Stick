For the DFP-34X-2C2 OMCI logs capturing, configure the following option

```
# flash set OMCI_LOGFILE 1
# reboot
```
The logs will be available at /tmp/omcilog. To convert them to pcap, the following script should be used
   
```
cat omcilog | sed '{s/^/20 52 45 43 56 00 20 53 45 4e 44 00 88 b5 /g;s/^/000000 /}' > omci.pcp
text2pcap omci.pcp omci.pcap
```
After capturing don't forget to disable OMCI_LOGFILE 0
   
