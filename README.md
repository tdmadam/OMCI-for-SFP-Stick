# OMCI decoding for SFP Stick

While running my GPON SFP stick, I noticed that viewing the omci log is very time consuming. The log has many messages, and each of them contains a lot of information that needs to be decoded. I decided to make my work easier and dump the logs into Wireshark to analyze the flow of OMCI messages.

OMCI is G.988 ITU Recommendation for the management and control of ONUs. The latest public version of this document is available on the ITU website:

https://www.itu.int/rec/T-REC-G.988/en

The page 475 of the 11/17 version of the document lists all Managed Entity(ME) identifiers. This information will be useful later when viewing messages in the Wireshark.

Work on omci-wireshark-dissector which is the most popular software used for OMCI decoding started about 10 years ago. The original repository is still on google code.
https://code.google.com/archive/p/omci-wireshark-dissector/

Fortunately for us, omci-dissector plugins are now part of the Wireshark plugin repository. The latest version available is 14-3-13-r11.
https://wiki.wireshark.org/Contrib#Protocol_Dissectors


## Wireshark plugins installation

1. After wireshark is installed go to: *Help, About Wireshark, Folders* and locate your plugins folder. My global is /usr/lib64/wireshark/plugins
or personal \/home/user/.local/lib/wireshark/plugins
2. Copy the **omci.lua** and **BinDecHex.lua** files to one of the plugin folders.
3. Use provided example omci-example.pcap to test your installation.

## Extracting OMCI logs from V2801F SFP Stick - RTL9601CI   

#### Enable OMCI debug logs
```
# flash set OMCI_DBGLVL 2    1-Driver 2-High 3-Normal 4-Low
# flash set OMCI_LOGFILE_MASK 2
# reboot
```
Notes:   
DBGLVL - 1 is the lowest, produces no hex dump. 4 is the highest, realtime.   
Also present is the variable OMCI_LOGFILE 0. Changing this variable to 1 does not create any logs in the /tmp folder.   
On the V2801F, the logs are only visible on the UART console.
   
   
#### Example of the console output saved to omci.log   

*It is recommended to save logs and perform file operations on Linux. It may be necessary to use dos2unix to convert line breaks if using Windows.*

<details>
  <summary>Click to see OMCI log!</summary>
its 5 =omci_send_to_nic() Fail=
===
Transaction ID <0x0000> : Prio <0>, tcId <0>
Message Type <0x10> : DB <0x00>, AR <0x00>, AK <0x00>, MT <16> <Alarm>
Device ID <0x0A>
Message ID <0x000B0401>  : Class <11>, Instance <1025>

0x0000:   00 00 10 0A 00 0B 04 01   
0x0000:   80 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
0x0010:   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 01   
0x0000:   00 00 00 28 65 1A D0 4F   

=====================recv==============================================
Transaction ID <0x0000> : Prio <0>, tcId <0>
Message Type <0x10> : DB <0x00>, AR <0x00>, AK <0x00>, MT <16> <Alarm>
Device ID <0x0A>
Message ID <0x000B0401>  : Class <11>, Instance <1025>

0x0000:   00 00 10 0A 00 0B 04 01   
0x0000:   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
0x0010:   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 02   
0x0000:   00 00 00 28 17 26 76 71   

RTK.0> command:
</details>
   
   
#### Filter OMCI from omci.log

  ```
  sed -n '/0x0000:\|0x0010:/p' omci.log | awk -F"0x00.0:   " '{print$2}' | sed -r 's/\s+//g' | awk '{ ORS = (NR%4 ? "" : RS) } 1' > omci.raw
  ```
  Two OMCI messages after conversion:
  ```
  0000100A000B0401800000000000000000000000000000000000000000000000000000000000000100000028651AD04F
  0000100A000B040100000000000000000000000000000000000000000000000000000000000000020000002817267671
  ```   
  
## Convert raw OMCI to a format that Wireshark understands   
  ```
  cat omci.raw | sed -e 's/.\{2\}/& /g' | sed -e 's/^/000000 /' > omci.hex
  ```
  In order for Wireshark to display these packets, each byte must be separated by a space, and there must be a start offset<000000> in front of it.
   
  The same OMCI messages after conversion:   
  ```
  000000 00 00 10 0A 00 0B 04 01 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 28 65 1A D0 4F 
  000000 00 00 10 0A 00 0B 04 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00 28 17 26 76 71
  ```  
  
  ## Display omci.hex in the Wireshark
   
 To open the omci.hex file in Wireshark select:   
   
  File -> Import from Hex Dump   
  Encapsulation Type -> Ethernet   
  set Ethernet -> Ethertype (hex): 88b5   
  Import   
 
   ## Convert raw OMCI to pcap file   
   
   pcap file needs three additional elements
   
   ```
    Destination Address  + Source Address + Ethertype
    20:52:45:43:56:00   20:53:45:4e:44:00      88 b5
   ```

```
cat omci.raw | sed 's/^/2052454356002053454e440088b5/g' | sed -e 's/.\{2\}/& /g' | sed -e 's/^/000000 /' > omci.pcp
```

The text2pcap program is part of the Wireshark installation, it loads an ASCII hexadecimal dump and writes the data to a pcap file.
   
```  
text2pcap omci.pcp omci.pcap
```

   
Then just double click on the pcap file.
   

   ![omci](https://user-images.githubusercontent.com/52431348/163656575-4ce8717f-d7e7-40d1-89f3-710939222718.png)

   
   
   
