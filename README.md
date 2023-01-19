# OMCI decoding for SFP Stick

While running my GPON SFP stick, I noticed that viewing the omci log is very time consuming. The log has many messages, and each of them contains a lot of information that needs to be decoded. I decided to make my work easier and dump the logs into Wireshark to analyze the flow of OMCI messages.

OMCI is G.988 ITU Recommendation for the management and control of ONUs. The latest public version of this document is available on the ITU website:

https://www.itu.int/rec/T-REC-G.988/en

The page 475 of the 11/17 version of the document lists all Managed Entity(ME) identifiers. This information will be useful later when viewing messages in the Wireshark.

Work on omci-wireshark-dissector which is the most popular software used for OMCI decoding started about 10 years ago. The original repository is still on google code.
https://code.google.com/archive/p/omci-wireshark-dissector/

Fortunately for us, omci-dissector plugins are now part of the Wireshark plugin repository. The latest available version from 2014 is 14-3-13-r11.
https://wiki.wireshark.org/Contrib#Protocol_Dissectors

I recommend using <b>omci.lua</b> from my repository, as I have started updating this file with the missing MEs. 

Detailed instructions for <b>RTL9601CI V2801F, RTL9601D DFP-34X-2C2 or BCM68380 Broadcom</b> devices can be found at the bottom of the page.



# General overview that applies to most devices.

## Wireshark plugins installation

1. After wireshark is installed go to: *Help, About Wireshark, Folders* and locate your plugins folder. My global is /usr/lib64/wireshark/plugins
or personal \/home/user/.local/lib/wireshark/plugins
2. Copy the **omci.lua** and **BinDecHex.lua** files to one of the plugin folders.
3. Use provided omci-example.pcap from wiki.wireshark.org to test your installation.

 


## Sample OMCI log   

```
00 00 10 0A 00 0B 04 01 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 28 65 1A D0 4F 
00 00 10 0A 00 0B 04 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00 28 17 26 76 71
```
## Convert OMCI log to a hex dump format that Wireshark understands

In order for Wireshark to display these packets as a hex dump, each byte must be separated by a space and have a start offset<000000> before it.
```
cat omcilog | sed -e 's/^/000000 /' > omci.hex
```
  The same OMCI messages after conversion:   
  ```
  000000 00 00 10 0A 00 0B 04 01 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 28 65 1A D0 4F 
  000000 00 00 10 0A 00 0B 04 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00 28 17 26 76 71
  ```  


<!-- Convert OMCI log to a format that Wireshark understands  

```
  cat omci.raw | sed '{s/.\{2\}/& /g;s/^/000000 /}' > omci.hex
  ```
  In order for Wireshark to display these packets, each byte must be separated by a space, and there must be a start offset<000000> in front of it.
   
  The same OMCI messages after conversion:   
  ```
  000000 00 00 10 0A 00 0B 04 01 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 28 65 1A D0 4F 
  000000 00 00 10 0A 00 0B 04 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00 28 17 26 76 71
  ```  
  -->
  
  
  ## Display OMCI hex dump in the Wireshark
   
 To open the omci.hex file in Wireshark select:   
   
  File -> Import from Hex Dump   
  Encapsulation Type -> Ethernet   
  set Ethernet -> Ethertype (hex): 88b5   
  Import   
  
</br>

 ## Convert OMCI log to a pcap file 
 

   
 pcap file needs three additional elements. Start with the original omcilog file.
   
   ```
    Destination Address  + Source Address + Ethertype
    20:52:45:43:56:00   20:53:45:4e:44:00      88 b5   
   ```   
```   
cat omcilog | sed '{s/^/20 52 45 43 56 00 20 53 45 4e 44 00 88 b5 /g;s/^/000000 /}' > omci.pcp   
text2pcap omci.pcp omci.pcap
```   

The text2pcap program is part of the Wireshark installation, it loads an ASCII hexadecimal dump and writes the data to a pcap file.
</br>

Then just double click on the pcap file.
   

   ![omci](https://user-images.githubusercontent.com/52431348/163656575-4ce8717f-d7e7-40d1-89f3-710939222718.png)



## More detailed methods for specific devices.
   
### [Extracting OMCI logs from V2801F SFP Stick - RTL9601CI](https://github.com/tdmadam/OMCI-for-SFP-Stick/blob/main/modules/V2801F.md) 

### [Extracting OMCI logs from DFP-34X-2C2 Stick - RTL9601D](https://github.com/tdmadam/OMCI-for-SFP-Stick/blob/main/modules/DFP34X.md)  

### [Extracting OMCI logs from Broadcom units - BCM68380IFSBG](https://github.com/tdmadam/OMCI-for-SFP-Stick/blob/main/modules/BCM68380.md)

### [Extracting OMCI logs from Lantiq G-010S-A and G-010G-A units](https://github.com/tdmadam/OMCI-for-SFP-Stick/blob/main/modules/G010SA.md) 
   

