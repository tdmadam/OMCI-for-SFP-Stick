--[[ 
   Wireshark dissector for ITU-T G984.4 and G988 OMCI frames.
   Copyright (C) 2012 Technicolor 
   Authors:
   Dirk Van Aken (dirk.vanaken@technicolor.com),
   Olivier Hardouin (olivier.hardouin@technicolor.com)

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; version 2
   of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 
   Description:
   Wireshark dissector for ONT Management and Control Interface (OMCI) protocol (ITU-T G984.4, ITU-T G988)
   This protocol is used on Gigabit Passive Optical Network (GPON) between Optical Line Termition (OLT, the network side) and Optical Network Termination (ONT, the end user side) units.
   This is management protocol used to configure services (like Ethernet, QoS, Video overlay, Tx/Rx control) on the ONT.
   The dissector applies on UDP or Ethernet packet that contains a copy of OMCI data going between ONT and OLT as explained in appendix III of ITU-T G988
  
   Links that were used to create this dissector:
   General presentation about WS dissector in Lua: http://sharkfest.wireshark.org/sharkfest.09/DT06_Bjorlykke_Lua%20Scripting%20in%20Wireshark.pdf
   Standard Wireshark dissector: http://www.wireshark.org/docs/wsug_html_chunked/wslua_dissector_example.html
   Lua Support in Wireshark: http://www.wireshark.org/docs/wsug_html_chunked/wsluarm.html
   Nice Wireshark dissector example: http://thomasfischer.biz/?p=175
   Another nice Wireshark dissector example: http://code.google.com/p/eathena/source/browse/devel/FlavioJS/athena.lua?r=9341
  
   The dissector binary to hexadecimal conversion, module available at http://www.dialectronics.com/Lua/code/BinDecHex.shtml
  
   Note from the author:
   *) Not all ME classes described in the OMCI standards are supported in this dissector (any support to complete the list is very welcome)
   *) This implementation is the first LUA SW written by the author. It (certainly) could be more efficient (any comment is welcome) 

--]]

require "BinDecHex"

-- Create a new dissector
omciproto = Proto ("omci", "OMCI Protocol")

-- init function
function omciproto.init()
end

local msgtype_meta = {
  __index = function(t, k)   
    if k < 4 or k > 28 then
      return "Reserved"
    end
  end
}

local msgtype = {
	[4]="Create",
	[5]="Create Complete Connection",
	[6]="Delete",
	[7]="Delete Complete Connection",
	[8]="Set",
	[9]="Get",
	[10]="Get Complete Connection",
	[11]="Get All Alarms",
	[12]="Get All Alarms Next",
	[13]="MIB Upload",
	[14]="MIB Upload Next",
	[15]="MIB Reset",
	[16]="Alarm",
	[17]="Attribute Value Change",
	[18]="Test",
	[19]="Start Software Download",
	[20]="Download Section",
	[21]="End Software Download",
	[22]="Activate Software",
	[23]="Commit Software",
	[24]="Synchronize Time",
	[25]="Reboot",
	[26]="Get Next",
	[27]="Test Result",
	[28]="Get Current Data"
}
setmetatable(msgtype, msgtype_meta)

local msg_result_meta = {
  __index = function(t, k)   
    if k == 7 or k == 8 or k > 9 then
      return "Unknown"
    end
  end
}

local msg_result= {
	[0] = "Command processed successfully",
	[1] = "Command processing error",
	[2] = "Command not supported",
	[3] = "Command parameter error",
	[4] = "Unknown managed entity",
	[5] = "Unknown managed entity instance",
	[6] = "Device busy",
	[9] = "Attribute failed or unknown"
}
setmetatable(msg_result, msg_result_meta)

local test_message_name = {}
local test_message_name_meta = {
	__index = function(t, k)
		if k >= 0 and k <= 6 then
			return "Reserved for future use"
		elseif k == 7 then
			return "Self test"
		elseif k > 7 and k <=255 then 
			return "Vendor specific" 
		else
			return "***ERROR: Not a Test ID*** (" .. k .. ")"
		end
	end
}
setmetatable(test_message_name, test_message_name_meta)

local mt2 = {
  __index = function(t2, k)   
	local returntable = {}
	if k >= 172 and k <= 239 then
		returntable.me_class_name= "Reserved for future B-PON managed entities"
	elseif k >= 240 and k <= 255 then
		returntable.me_class_name= "Reserved for vendor-specific managed entities"
   	elseif k >= 343 and k <= 65279 then 
		returntable.me_class_name= "Reserved for future standardization" 
	elseif k >= 65280 and k <= 65535 then 
		returntable.me_class_name= "Reserved for vendor-specific use"
	else
		returntable.me_class_name= "***TBD*** (" .. k .. ")"
    end
	return returntable
  end
}

local omci_def = {
[2] = { me_class_name = "ONT Data",
	{ attname="MIB Data Sync", length=1, setbycreate=false }},

[5] = { me_class_name = "Cardholder",
	{ attname="Actual Plug-in Unit Type", length=1, setbycreate=false },
	{ attname="Expected Plug-in Unit Type", length=1, setbycreate=false },
	{ attname="Expected Port Count", length=1, setbycreate=false },
	{ attname="Expected Equipment Id", length=20, setbycreate=false },
	{ attname="Actual Equipment Id", length=20, setbycreate=false },
	{ attname="Protection Profile Pointer", length=1, setbycreate=false },
	{ attname="Invoke Protection Switch", length=1, setbycreate=false }},

[6] = { me_class_name = "Circuit Pack",
	{ attname="Type", length=1, setbycreate=true },
	{ attname="Number of ports", length=1, setbycreate=false },
	{ attname="Serial Number", length=8, setbycreate=false },
	{ attname="Version", length=14, setbycreate=false },
	{ attname="Vendor Id", length=4, setbycreate=false },
	{ attname="Administrative State", length=1, setbycreate=true },
	{ attname="Operational State", length=1, setbycreate=false },
	{ attname="Bridged or IP Ind", length=1, setbycreate=false },
	{ attname="Equipment Id", length=20, setbycreate=false },
	{ attname="Card Configuration", length=1, setbycreate=true },
	{ attname="Total T-CONT Buffer Number", length=1, setbycreate=false },
	{ attname="Total Priority Queue Number", length=1, setbycreate=false },
	{ attname="Total Traffic Scheduler Number", length=1, setbycreate=false },
	{ attname="Power Shed Override", length=4, setbycreate=false }},

[7] = { me_class_name = "Software Image",
	{ attname="Version", length=14, setbycreate=false },
	{ attname="Is committed", length=1, setbycreate=false },
	{ attname="Is active", length=1, setbycreate=false },
	{ attname="Is valid", length=1, setbycreate=false }},

[11] = { me_class_name = "PPTP Ethernet UNI",
	{attname="Expected Type",			length=1, setbycreate=false},
	{attname="Sensed Type",				length=1, setbycreate=false},
	{attname="Auto Detection Configuration",	length=1, setbycreate=false},
	{attname="Ethernet Loopback Configuration",	length=1, setbycreate=false},
	{attname="Administrative State",		length=1, setbycreate=false},
	{attname="Operational State",			length=1, setbycreate=false},
	{attname="Configuration Ind",			length=1, setbycreate=false},
	{attname="Max Frame Size",			length=2, setbycreate=false},
	{attname="DTE or DCE",				length=1, setbycreate=false},
	{attname="Pause Time",				length=2, setbycreate=false},
	{attname="Bridged or IP Ind",			length=1, setbycreate=false},
	{attname="ARC",					length=1, setbycreate=false},
	{attname="ARC Interval",			length=1, setbycreate=false},
	{attname="PPPoE Filter",			length=1, setbycreate=false},
	{attname="Power Control",			length=1, setbycreate=false}},

[24] = { me_class_name = "Ethernet PM History Data",
	{ attname="Interval End Time", length=1, setbycreate=false },
	{ attname="Threshold Data 1/2 Id", length=2, setbycreate=true },
	{ attname="FCS errors Drop events", length=4, setbycreate=false },
	{ attname="Excessive Collision Counter", length=4, setbycreate=false },
	{ attname="Late Collision Counter", length=4, setbycreate=false },
	{ attname="Frames too long", length=4, setbycreate=false },
	{ attname="Buffer overflows on Receive", length=4, setbycreate=false },
	{ attname="Buffer overflows on Transmit", length=4, setbycreate=false },	
	{ attname="Single Collision Frame Counter", length=4, setbycreate=false },	
	{ attname="Multiple Collisions Frame Counter", length=4, setbycreate=false },
	{ attname="SQE counter", length=4, setbycreate=false },
	{ attname="Deferred Transmission Counter", length=4, setbycreate=false },
	{ attname="Internal MAC Transmit Error Counter", length=4, setbycreate=false },
	{ attname="Carrier Sense Error Counter", length=4, setbycreate=false },
	{ attname="Alignment Error Counter", length=4, setbycreate=false },
	{ attname="Internal MAC Receive Error Counter", length=4, setbycreate=false}},

[44] = { me_class_name = "Vendor Specific",
	{ attname="Sub-Entity", length=1, setbycreate=true },
	subentity_attr = {}},
		
[45] = { me_class_name = "MAC Bridge Service Profile",
	{ attname="Spanning tree ind", length=1, setbycreate=true },
	{ attname="Learning ind", length=1, setbycreate=true },
	{ attname="Port bridging ind", length=1, setbycreate=true },
	{ attname="Priority", length=2, setbycreate=true },
	{ attname="Max age", length=2, setbycreate=true },
	{ attname="Hello time", length=2, setbycreate=true },
	{ attname="Forward delay", length=2, setbycreate=true },
	{ attname="Unknown MAC address discard", length=1, setbycreate=true },
	{ attname="MAC learning depth", length=1, setbycreate=true }},

[47] = { me_class_name = "MAC bridge port configuration data",
	{ attname="Bridge id pointer", length=2, setbycreate=true },
	{ attname="Port num", length=1, setbycreate=true },
	{ attname="TP type", length=1, setbycreate=true },
	{ attname="TP pointer", length=2, setbycreate=true },
	{ attname="Port priority", length=2, setbycreate=true },
	{ attname="Port path cost", length=2, setbycreate=true },
	{ attname="Port spanning tree ind", length=1, setbycreate=true },
	{ attname="Encapsulation method", length=1, setbycreate=true },
	{ attname="LAN FCS ind", length=1, setbycreate=true },
	{ attname="Port MAC address", length=6, setbycreate=false },
	{ attname="Outbound TD pointer", length=2, setbycreate=false },
	{ attname="Inbound TD pointer", length=2, setbycreate=false }},

[48] = { me_class_name = "MAC bridge port designation data",
	{ attname="Designated bridge root cost port", length=24, setbycreate=false },
	{ attname="Port state", length=1, setbycreate=false }},

[49] = { me_class_name = "MAC bridge port filter table data",
	{ attname="MAC filter table", length=8, setbycreate=false }},

[51] = { me_class_name = "MAC Bridge PM History Data",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Threshold data 1/2 id", length=2, setbycreate=true },
	{ attname="Bridge learning entry discard count", length=4, setbycreate=false }},

[52] = { me_class_name = "MAC Bridge Port PM History Data",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Threshold data 1/2 id", length=2, setbycreate=true },
	{ attname="Forwarded frame counter", length=4, setbycreate=false },	
	{ attname="Delay exceeded discard counter", length=4, setbycreate=false },	
	{ attname="MTU exceeded discard counter", length=4, setbycreate=false },	
	{ attname="Received frame counter", length=4, setbycreate=false },	
	{ attname="Received and discarded counter", length=4, setbycreate=false }},

[79] = { me_class_name = "MAC bridge port filter preassign table",
	{ attname="IPv4 multicast filtering", length=1, setbycreate=false },
	{ attname="IPv6 multicast filtering", length=1, setbycreate=false },
	{ attname="IPv4 broadcast filtering", length=1, setbycreate=false },
	{ attname="RARP filtering", length=1, setbycreate=false },
	{ attname="IPX filtering", length=1, setbycreate=false },
	{ attname="NetBEUI filtering", length=1, setbycreate=false },
	{ attname="AppleTalk filtering", length=1, setbycreate=false },
	{ attname="Bridge management information filtering", length=1, setbycreate=false },
	{ attname="ARP filtering", length=1, setbycreate=false }},

[82] = { me_class_name = "PPTP Video UNI",
	{attname="Administrative State", length=1, setbycreate=false},
	{attname="Operational State", length=1, setbycreate=false},
	{attname="ARC",	length=1, setbycreate=false},
	{attname="ARC Interval", length=1, setbycreate=false},
	{attname="Power Control", length=1, setbycreate=false}},
	
[84] = { me_class_name = "VLAN tagging filter data",
	{attname="VLAN filter list", length=24, setbycreate=true},
	{attname="Forward operation", length=1, setbycreate=true},
	{attname="Number of entries",	length=1, setbycreate=true}},

[89] = { me_class_name = "Ethernet PM History Data 2",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Threshold data 1/2 id", length=2, setbycreate=true },
	{ attname="PPPoE filtered frame counter", length=4, setbycreate=false }},
	
[90] = { me_class_name = "PPTP Video ANI",
	{attname="Administrative State", length=1, setbycreate=false},
	{attname="Operational State", length=1, setbycreate=false},
	{attname="ARC",	length=1, setbycreate=false},
	{attname="ARC Interval", length=1, setbycreate=false},
	{attname="Frequency Range Low", length=1, setbycreate=false},
	{attname="Frequency Range High", length=1, setbycreate=false},
	{attname="Signal Capability", length=1, setbycreate=false},
	{attname="Optical Signal Level", length=1, setbycreate=false},
	{attname="Pilot Signal Level", length=1, setbycreate=false},
	{attname="Signal Level min", length=1,	setbycreate=false},
	{attname="Signal Level max", length=1,	setbycreate=false},
	{attname="Pilot Frequency", length=4,	setbycreate=false},
	{attname="AGC Mode", length=1,	setbycreate=false},
	{attname="AGC Setting", length=1,	setbycreate=false},	
	{attname="Video Lower Optical Threshold", length=1, setbycreate=false},
	{attname="Video Upper Optical Threshold", length=1, setbycreate=false}},
 
 [130] = { me_class_name = "802.1P Mapper Service Profile",
	{attname="TP Pointer",					length=2,  setbycreate=true},
	{attname="Interwork TP pointer for P-bit priority 0",	length=2,  setbycreate=true},
	{attname="Interwork TP pointer for P-bit priority 1",	length=2,  setbycreate=true},
	{attname="Interwork TP pointer for P-bit priority 2",	length=2,  setbycreate=true},
	{attname="Interwork TP pointer for P-bit priority 3",	length=2,  setbycreate=true},
	{attname="Interwork TP pointer for P-bit priority 4",	length=2,  setbycreate=true},
	{attname="Interwork TP pointer for P-bit priority 5",	length=2,  setbycreate=true},
	{attname="Interwork TP pointer for P-bit priority 6",	length=2,  setbycreate=true},
	{attname="Interwork TP pointer for P-bit priority 7",	length=2,  setbycreate=true},
	{attname="Unmarked frame option:",		length=1,  setbycreate=true},
	{attname="DSCP to P-bit mapping",		length=24, setbycreate=false},
	{attname="Default P-bit marking",		length=1,  setbycreate=true},
	{attname="TP Type:",					length=1,  setbycreate=true}},

[131] = { me_class_name = "OLT-G",
	{attname="OLT vendor id",					length=4,  setbycreate=false},
	{attname="Equipment id",	length=20,  setbycreate=false},
	{attname="OLT version",	length=14,  setbycreate=false}},
				
[133] = { me_class_name = "ONT Power Shedding",
	{ attname="Restore power timer reset interval", length=2, setbycreate=false },
	{ attname="Data class shedding interval", length=2, setbycreate=false },
	{ attname="Voice class shedding interval", length=2, setbycreate=false },
	{ attname="Video overlay class shedding interval", length=2, setbycreate=false },
	{ attname="Video return class shedding interval", length=2, setbycreate=false },
	{ attname="DSL class shedding interval", length=2, setbycreate=false },
	{ attname="ATM class shedding interval", length=2, setbycreate=false },
	{ attname="CES class shedding interval", length=2, setbycreate=false },
	{ attname="Frame class shedding interval", length=2, setbycreate=false },
	{ attname="SONET class shedding interval", length=2, setbycreate=false },
	{ attname="Shedding status", length=2, setbycreate=false }},

[158] = { me_class_name = "ONT remote debug",
	{ attname="Command format", length=1, setbycreate=false },
	{ attname="Command", length=25, setbycreate=false },
	{ attname="Reply table", length=4, setbycreate=false }},

[159] = { me_class_name = "Equipment protection profile",
	{ attname="Protect slot 1,protect slot 2", length=2, setbycreate=true },
	{ attname="working slot 1,working slot 2,working slot 3,working slot 4,working slot 5,working slot 6,working slot 7,working slot 8", length=8, setbycreate=true },
	{ attname="Protect status 1,protect status 2", length=2, setbycreate=false },
	{ attname="Revertive ind", length=1, setbycreate=true },
	{ attname="Wait to restore time", length=1, setbycreate=true }},

[160] = { me_class_name = "Equipment extension package",
	{ attname="Environmental sense", length=2, setbycreate=false },
	{ attname="Contact closure output", length=2, setbycreate=false }},

[171] = { me_class_name = "Extended VLAN tagging operation configuration data",
	{ attname="Association type", length=1, setbycreate=true },
	{ attname="Received frame VLAN tagging operation table max size", length=2, setbycreate=false },
	{ attname="Input TPID", length=2, setbycreate=false },
	{ attname="Output TPID", length=2, setbycreate=false },	
	{ attname="Downstream mode", length=1, setbycreate=false },
	{ attname="Received frame VLAN tagging operation table", length=16, setbycreate=false },
	{ attname="Associated ME pointer", length=2, setbycreate=true },
	{ attname="DSCP to P-bit mapping", length=24, setbycreate=false }},
	
[256] = { me_class_name = "ONT-G",
	{ attname="Vendor Id", length=4, setbycreate=false },
	{ attname="Version", length=14, setbycreate=false },
	{ attname="Serial Nr", length=8, setbycreate=false },
	{ attname="Traffic management option", length=1, setbycreate=false },
	{ attname="VP/VC cross connection function option", length=1, setbycreate=false },
	{ attname="Battery backup", length=1, setbycreate=false },
	{ attname="Administrative State", length=1, setbycreate=false },
	{ attname="Operational State", length=1, setbycreate=false }},

[257] = { me_class_name = "ONT2-G",
	{ attname="Equipment id", length=20, setbycreate=false },
	{ attname="OMCC version", length=1, setbycreate=false },
	{ attname="Vendor product code", length=2, setbycreate=false },
	{ attname="Security capability", length=1, setbycreate=false },
	{ attname="Security mode", length=1, setbycreate=false },
	{ attname="Total priority queue number", length=2, setbycreate=false },
	{ attname="Total traffic scheduler number", length=1, setbycreate=false },
	{ attname="Mode", length=1, setbycreate=false },
	{ attname="Total GEM port-ID number", length=2, setbycreate=false },
	{ attname="SysUp Time", length=4, setbycreate=false }},

[262] = { me_class_name = "T-CONT",
	{ attname="Alloc-id", length=2, setbycreate=false },
	{ attname="Mode indicator", length=1, setbycreate=false },
	{ attname="Policy", length=1, setbycreate=false }},

[263] = { me_class_name = "ANI-G",
	{ attname="SR indication", length=1, setbycreate=false },
	{ attname="Total T-CONT number", length=2, setbycreate=false },
	{ attname="GEM block length", length=2, setbycreate=false },
	{ attname="Piggyback DBA reporting", length=1, setbycreate=false },
	{ attname="Whole ONT DBA reporting", length=1, setbycreate=false },
	{ attname="SF threshold", length=1, setbycreate=false },
	{ attname="SD threshold", length=1, setbycreate=false },
	{ attname="ARC", length=1, setbycreate=false },
	{ attname="ARC interval", length=1, setbycreate=false },
	{ attname="Optical signal level", length=2, setbycreate=false },
	{ attname="Lower optical threshold", length=1, setbycreate=false },
	{ attname="Upper optical threshold", length=1, setbycreate=false },
	{ attname="ONT response time", length=2, setbycreate=false },
	{ attname="Transmit optical level", length=2, setbycreate=false },
	{ attname="Lower transmit power threshold", length=1, setbycreate=false },
	{ attname="Upper transmit power threshold", length=1, setbycreate=false }},

[264] = { me_class_name = "UNI-G",
	{ attname="Config option status", length=2, setbycreate=false },
	{ attname="Administrative state", length=1, setbycreate=false }},
	
[266] = { me_class_name = "GEM interworking Termination Point",
	{ attname="GEM port network CTP connectivity pointer", length=2, setbycreate=true },
	{ attname="Interworking option", length=1, setbycreate=true },
	{ attname="Service profile pointer", length=2, setbycreate=true },
	{ attname="Interworking termination point pointer", length=2, setbycreate=true },
	{ attname="PPTP counter", length=1, setbycreate=false },
	{ attname="Operational state", length=1, setbycreate=false },
	{ attname="GAL profile pointer", length=2, setbycreate=true },
	{ attname="GAL loopback configuration", length=1, setbycreate=false }},

[267] = { me_class_name = "GEM Port PM History Data",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Threshold data 1/2 id", length=2, setbycreate=true },
	{ attname="Lost packets", length=4, setbycreate=false },
	{ attname="Misinserted packets", length=4, setbycreate=false },
	{ attname="Received packets", length=5, setbycreate=false },
	{ attname="Received blocks", length=5, setbycreate=false },
	{ attname="Transmitted blocks", length=5, setbycreate=false },
	{ attname="Impaired blocks", length=4, setbycreate=false }},

[268] = { me_class_name = "GEM Port Network CTP",
	{ attname="Port id value", length=2, setbycreate=true },
	{ attname="T-CONT pointer", length=2, setbycreate=true },
	{ attname="Direction", length=1, setbycreate=true },
	{ attname="Traffic management pointer for upstream", length=2, setbycreate=true },
	{ attname="Traffic descriptor profile pointer", length=2, setbycreate=true },
	{ attname="UNI counter", length=1, setbycreate=false },
	{ attname="Priority queue pointer for downstream", length=2, setbycreate=true },
	{ attname="Encryption state", length=1, setbycreate=false }},

[271] = { me_class_name = "GAL TDM profile",
	{ attname="GEM frame loss integration period", length=2, setbycreate=true }},

[272] = { me_class_name = "GAL Ethernet profile",
	{ attname="Maximum GEM payload size", length=2, setbycreate=true }},

[273] = { me_class_name = "Threshold Data 1",
	{attname="Threshold value 1",	length=4,  setbycreate=true},
	{attname="Threshold value 2",	length=4,  setbycreate=true},
	{attname="Threshold value 3",	length=4,  setbycreate=true},
	{attname="Threshold value 4",	length=4,  setbycreate=true},
	{attname="Threshold value 5",	length=4,  setbycreate=true},
	{attname="Threshold value 6",	length=4,  setbycreate=true},
	{attname="Threshold value 7",	length=4,  setbycreate=true}},

[274] = { me_class_name = "Threshold Data 2",
	{attname="Threshold value 8",	length=4,  setbycreate=true},
	{attname="Threshold value 9",	length=4,  setbycreate=true},
	{attname="Threshold value 10",	length=4,  setbycreate=true},
	{attname="Threshold value 11",	length=4,  setbycreate=true},
	{attname="Threshold value 12",	length=4,  setbycreate=true},
	{attname="Threshold value 13",	length=4,  setbycreate=true},
	{attname="Threshold value 14",	length=4,  setbycreate=true}},

[275] = { me_class_name = "GAL TDM PM History Data",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Threshold data 1/2 id", length=2, setbycreate=true },
	{ attname="GEM frame loss", length=4, setbycreate=false },
	{ attname="Buffer underflows", length=4, setbycreate=false },
	{ attname="Buffer overflows", length=4, setbycreate=false }},

[276] = { me_class_name = "GAL Ethernet PM History Data",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Threshold data 1/2 id", length=2, setbycreate=true },
	{ attname="Discarded frames", length=4, setbycreate=false }},

[277] = { me_class_name = "Priority queue-G",
	{attname="Queue Configuration Option",		length=1,  setbycreate=false},
	{attname="Maximum Queue Size",			length=2,  setbycreate=false},
	{attname="Allocated Queue Size",		length=2,  setbycreate=false},
	{attname="Discard-block Counter Reset Interval",length=2,  setbycreate=false},
	{attname="Threshold Value For Discarded Blocks Due To Buffer Overflow",	length=2,  setbycreate=false},
	{attname="Related Port",			length=4,  setbycreate=false},
	{attname="Traffic Scheduler-G Pointer",		length=2,  setbycreate=false},
	{attname="Weight",				length=1,  setbycreate=false},
	{attname="Back Pressure Operation",		length=2,  setbycreate=false},
	{attname="Back Pressure Time",			length=4,  setbycreate=false},
	{attname="Back Pressure Occur Queue Threshold",	length=2,  setbycreate=false},
	{attname="Back Pressure Clear Queue Threshold",	length=2,  setbycreate=false}},

[278] = { me_class_name = "Traffic Scheduler-G",
	{ attname="TCONT pointer", length=2, setbycreate=false },
	{ attname="traffic shed pointer", length=2, setbycreate=false },
	{ attname="policy", length=1, setbycreate=false },
	{ attname="priority/weight", length=1, setbycreate=false }},
	
[279] = { me_class_name = "Protection data",
	{ attname="Working ANI-G pointer", length=2, setbycreate=false },
	{ attname="Protection ANI-G pointer", length=2, setbycreate=false },
	{ attname="Protection type", length=2, setbycreate=false },
	{ attname="Revertive ind", length=1, setbycreate=false },
	{ attname="Wait to restore time", length=1, setbycreate=false },
	{ attname="Switching guard time", length=2, setbycreate=false }},

[281] = { me_class_name = "Multicast GEM interworking termination point",
	{ attname="GEM port network CTP connectivity pointer", length=2, setbycreate=true },
	{ attname="Interworking option", length=1, setbycreate=true },
	{ attname="Service profile pointer", length=2, setbycreate=true },
	{ attname="Interworking termination point pointer", length=2, setbycreate=true },
	{ attname="PPTP counter", length=1, setbycreate=false },
	{ attname="Operational state", length=1, setbycreate=false },
	{ attname="GAL profile pointer", length=2, setbycreate=true },
	{ attname="GAL loopback configuration", length=1, setbycreate=true },
	{ attname="Multicast address table", length=12, setbycreate=false }},

[287] = { me_class_name = "OMCI",
	{ attname="ME Type Table", length=2, setbycreate=false },
	{ attname="Message Type Table", length=2, setbycreate=false }},


[290] = { me_class_name = "Dot1X Port Extension Package",
	{ attname="Dot1x Enable", length=1, setbycreate=false },
	{ attname="Action Register", length=1, setbycreate=false },
	{ attname="Authenticator PAE State", length=1, setbycreate=false },
	{ attname="Backend Authentication State", length=1, setbycreate=false },
	{ attname="Admin Controlled Directions", length=1, setbycreate=false },
	{ attname="Operational Controlled Directions", length=1, setbycreate=false },
	{ attname="Authenticator Controlled Port Status", length=1, setbycreate=false },
	{ attname="Quiet Period", length=2, setbycreate=false },
	{ attname="Server Timeout Period", length=2, setbycreate=false },
	{ attname="Reauthentication Period", length=2, setbycreate=false },
	{ attname="Reauthentication Enabled", length=1, setbycreate=false },
	{ attname="Key transmission Enabled", length=1, setbycreate=false }},

[296] = { me_class_name = "Ethernet PM History Data 3",
	{ attname="Interval End Time", length=1, setbycreate=false },
	{ attname="Threshold Data 1/2 Id", length=2, setbycreate=true },
	{ attname="Drop events", length=4, setbycreate=false },
	{ attname="Octets", length=4, setbycreate=false },
	{ attname="Packets", length=4, setbycreate=false },
	{ attname="Broadcast Packets", length=4, setbycreate=false },
	{ attname="Multicast Packets", length=4, setbycreate=false },
	{ attname="Undersize Packets", length=4, setbycreate=false },	
	{ attname="Fragments", length=4, setbycreate=false },	
	{ attname="Jabbers", length=4, setbycreate=false },	
	{ attname="Packets 64 Octets", length=4, setbycreate=false },
	{ attname="Packets 65 to 127 Octets", length=4, setbycreate=false },
	{ attname="Packets 128 to 255 Octets", length=4, setbycreate=false },
	{ attname="Packets 256 to 511 Octets", length=4, setbycreate=false },
	{ attname="Packets 512 to 1023 Octets", length=4, setbycreate=false },
	{ attname="Packets 1024 to 1518 Octets", length=4, setbycreate=false }},
	
[297] = { me_class_name = "Port mapping package-G",
	{ attname="Max ports", length=1, setbycreate=false },
	{ attname="Port list 1", length=16, setbycreate=false },
	{ attname="Port list 2", length=16, setbycreate=false },
	{ attname="Port list 3", length=16, setbycreate=false },
	{ attname="Port list 4", length=16, setbycreate=false },
	{ attname="Port list 5", length=16, setbycreate=false },
	{ attname="Port list 6", length=16, setbycreate=false },
	{ attname="Port list 7", length=16, setbycreate=false },
	{ attname="Port list 8", length=16, setbycreate=false }},

[309] = { me_class_name = "Multicast operations profile",
	{ attname="IGMP version", length=1, setbycreate=true },
	{ attname="IGMP function", length=1, setbycreate=true },
	{ attname="Immediate leave", length=1, setbycreate=true },
	{ attname="Upstream IGMP TCI", length=2, setbycreate=true },
	{ attname="Upstream IGMP tag control", length=1, setbycreate=true },
	{ attname="Upstream IGMP rate", length=4, setbycreate=true },
	{ attname="Dynamic access control list table", length=24, setbycreate=false },
	{ attname="Static access control list table", length=24, setbycreate=false },	
	{ attname="Lost groups list table", length=10, setbycreate=false },		
	{ attname="Robustness", length=1, setbycreate=true },	
	{ attname="Querier IP address", length=4, setbycreate=true },		
	{ attname="Query interval", length=4, setbycreate=true },		
	{ attname="Query max response time", length=4, setbycreate=true },		
	{ attname="Last member query interval", length=4, setbycreate=false }},

[310] = { me_class_name = "Multicast subscriber config info",
	{ attname="ME type", length=1, setbycreate=true },
	{ attname="Multicast operations profile pointer", length=2, setbycreate=true },
	{ attname="Max simultaneous groups", length=2, setbycreate=true },
	{ attname="Max multicast bandwidth", length=4, setbycreate=true },
	{ attname="Bandwidth enforcement", length=1, setbycreate=true }},	
	
[311] = { me_class_name = "Multicast Subscriber Monitor",
	{ attname="ME type", length=1, setbycreate=true },
	{ attname="Current multicast bandwidth", length=4, setbycreate=false },
	{ attname="Max Join messages counter", length=4, setbycreate=false },
	{ attname="Bandwidth exceeded counter:", length=4, setbycreate=false },
	{ attname="Active group list table", length=24, setbycreate=false }},	

	[312] = { me_class_name = "FEC PM History Data",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Threshold data 1/2 id", length=2, setbycreate=true },
	{ attname="Corrected bytes", length=4, setbycreate=false },
	{ attname="Corrected code words", length=4, setbycreate=false },
	{ attname="Uncorrectable code words", length=4, setbycreate=false },
	{ attname="Total code words", length=4, setbycreate=false },
	{ attname="FEC seconds", length=2, setbycreate=false }},

[321] = { me_class_name = "Ethernet Frame PM History Data DS",
	{ attname="Interval End Time", length=1, setbycreate=false },
	{ attname="Threshold Data 1/2 Id", length=2, setbycreate=true },
	{ attname="Drop events", length=4, setbycreate=false },
	{ attname="Octets", length=4, setbycreate=false },
	{ attname="Packets", length=4, setbycreate=false },
	{ attname="Broadcast Packets", length=4, setbycreate=false },
	{ attname="Multicast Packets", length=4, setbycreate=false },
	{ attname="CRC Errored Packets", length=4, setbycreate=false },	
	{ attname="Undersize Packets", length=4, setbycreate=false },	
	{ attname="Oversize Packets", length=4, setbycreate=false },
	{ attname="Packets 64 Octets", length=4, setbycreate=false },
	{ attname="Packets 65 to 127 Octets", length=4, setbycreate=false },
	{ attname="Packets 128 to 255 Octets", length=4, setbycreate=false },
	{ attname="Packets 256 to 511 Octets", length=4, setbycreate=false },
	{ attname="Packets 512 to 1023 Octets", length=4, setbycreate=false },
	{ attname="Packets 1024 to 1518 Octets", length=4, setbycreate=false }},

[322] = { me_class_name = "Ethernet Frame PM History Data US",
	{ attname="Interval End Time", length=1, setbycreate=false },
	{ attname="Threshold Data 1/2 Id", length=2, setbycreate=true },
	{ attname="Drop events", length=4, setbycreate=false },
	{ attname="Octets", length=4, setbycreate=false },
	{ attname="Packets", length=4, setbycreate=false },
	{ attname="Broadcast Packets", length=4, setbycreate=false },
	{ attname="Multicast Packets", length=4, setbycreate=false },
	{ attname="CRC Errored Packets", length=4, setbycreate=false },	
	{ attname="Undersize Packets", length=4, setbycreate=false },	
	{ attname="Oversize Packets", length=4, setbycreate=false },
	{ attname="Packets 64 Octets", length=4, setbycreate=false },
	{ attname="Packets 65 to 127 Octets", length=4, setbycreate=false },
	{ attname="Packets 128 to 255 Octets", length=4, setbycreate=false },
	{ attname="Packets 256 to 511 Octets", length=4, setbycreate=false },
	{ attname="Packets 512 to 1023 Octets", length=4, setbycreate=false },
	{ attname="Packets 1024 to 1518 Octets", length=4, setbycreate=false }},
}

setmetatable(omci_def, mt2)

-- GUI field definition
local f = omciproto.fields
f.tci = ProtoField.uint16("omciproto.tci", "Transaction Correlation ID")
f.msg_type_db = ProtoField.uint8("omciproto.msg_type_db", "Destination Bit", base.HEX, nil, 0x80)
f.msg_type_ar = ProtoField.uint8("omciproto.msg_type_ar", "Acknowledge Request", base.HEX, nil, 0x40)
f.msg_type_ak = ProtoField.uint8("omciproto.msg_type_ak", "Acknowledgement", base.HEX, nil, 0x20)
f.msg_type_mt = ProtoField.uint8("omciproto.msg_type_mt", "Message Type", base.DEC, msgtype, 0x1F)
f.dev_id = ProtoField.uint8("omciproto.dev_id", "Device Identifier", base.HEX)
f.me_id = ProtoField.uint16("omciproto.me_id", "Managed Entity Instance", base.HEX)
f.me_class = ProtoField.uint16("omciproto.me_class", "Managed Entity Class", base.DEC) 
f.me_class_str = ProtoField.string("omciproto.me_class_str", "Managed Entity Class") 
f.attribute_mask = ProtoField.uint16("omciproto.attribtute_mask", "Attribute Mask", base.HEX, nil, 0xFFFF)
f.attribute = ProtoField.bytes("omciproto.attribute", "Attribute")
f.content = ProtoField.bytes("omciproto.content", "Message Content")
f.trailer = ProtoField.bytes("omciproto.trailer", "Trailer")
f.cpcsuu_cpi = ProtoField.uint16("omciproto.cpcsuu_cpi", "CPCS-UU and CPI", base.HEX)
f.cpcssdu_length = ProtoField.uint16("omciproto.cpcssdu_length", "CPCS-SDU Length", base.HEX)
f.crc32 = ProtoField.uint32("omciproto.crc32", "CRC32", base.HEX)

-- The dissector function
function omciproto.dissector (buffer, pinfo, tree)
	if buffer:len() == 0 then return end -- validate packet length is adequate, otherwise quit

	-- Show name of the protocol, create Tree item for displaying info
	pinfo.cols.protocol = omciproto.name
	local subtree = tree:add(omciproto, buffer())

	-- Start analysing data
	local offset = 0
	
	-- OMCI Transaction Correlation Identifier
	local tci = buffer(offset, 2)
	subtree:add(f.tci, tci)
	offset = offset +  2
	
	-- OMCI Message Type
	local msg_type = buffer(offset, 1)
	local msg_type_mt = msgtype[msg_type:bitfield(3,5)]
	local msg_type_ar = msg_type:bitfield(1,1)
	local msg_type_ak = msg_type:bitfield(2,1)
	local msgtype_subtree = subtree:add(msg_type, "Message Type = " .. msg_type_mt)
	msgtype_subtree:add(f.msg_type_db, msg_type)
	msgtype_subtree:add(f.msg_type_ar, msg_type)
	msgtype_subtree:add(f.msg_type_ak, msg_type)
	msgtype_subtree:add(f.msg_type_mt, msg_type)
	offset = offset +  1
	
	-- OMCI Device ID
	local dev_id = buffer(offset, 1)
	subtree:add(f.dev_id, dev_id)
	offset = offset +  1
	
	-- OMCI Message Entity Class & Instance
	local me_class = buffer(offset, 2)
	local me_instance = buffer(offset + 2, 2)
	local me_class_name = omci_def[me_class:uint()].me_class_name
	
	local devid_subtree = subtree:add(buffer(offset, 4), "Message Identifier, ME Class = " .. me_class_name .. ", Instance = " .. me_instance:uint())
--	devid_subtree:add(f.me_class, me_class)
	devid_subtree:add(f.me_class_str, me_class_name .. " (" .. me_class .. ")")
	devid_subtree:add(f.me_id, me_instance)
	offset = offset +  4
	
	-- OMCI Attributes and/or message result	
	local content = buffer(offset, 32)
	if( (msg_type_mt == "Get" or msg_type_mt == "Get Current Data") and msg_type_ar == 1 and msg_type_ak == 0) then
		local attribute_mask = content(0, 2)
		local attributemask_subtree = subtree:add(attribute_mask, "Attribute Mask (0x" .. attribute_mask .. ")" )
		attributemask_subtree:add(attribute_mask, tostring(BinDecHex.Hex2Bin(tostring(attribute_mask))))
		local content_subtree = subtree:add(content, "Attribute List")
		attributes = omci_def[me_class:uint()]
		for i = 1,#attributes do
			local attr = attributes[i]
			if attribute_mask:bitfield(i-1,1) == 1 then
				content_subtree:add(string.format("%2.2d", i) .. ": " .. attr.attname)
			end
		end
	end

	if( (msg_type_mt == "Get" or msg_type_mt == "Get Current Data") and msg_type_ar == 0 and msg_type_ak == 1) then
		subtree:add(content(0,1), "Result: " .. msg_result[content(0,1):uint()] .. " (" .. content(0,1) .. ")")
		local attribute_mask = content(1, 2)
		local attributemask_subtree = subtree:add(attribute_mask, "Attribute Mask (0x" .. attribute_mask .. ")" )
		attributemask_subtree:add(attribute_mask, tostring(BinDecHex.Hex2Bin(tostring(attribute_mask))))
		local content_subtree = subtree:add(content, "Attribute List")
		local attributes = {}
		local attribute_offset = 0
		attributes = omci_def[me_class:uint()]
		attribute_offset=3
		for i = 1,#attributes do
			local attr = attributes[i]
			if attribute_mask:bitfield(i-1,1) == 1 then
				local attr_bytes = content(attribute_offset, attr.length)
				content_subtree:add(attr_bytes, string.format("%2.2d", i) .. ": " .. attr.attname .. " (" .. attr_bytes .. ")")
				attribute_offset = attribute_offset + attr.length
			end
		end
	end

	if( msg_type_mt == "Set" and msg_type_ar == 1 and msg_type_ak == 0) then
		local attribute_mask = content(0, 2)
		local attributemask_subtree = subtree:add(attribute_mask, "Attribute Mask (0x" .. attribute_mask .. ")" )
		attributemask_subtree:add(attribute_mask, tostring(BinDecHex.Hex2Bin(tostring(attribute_mask))))
		local content_subtree = subtree:add(content, "Attribute List")
		local attributes = {}
		local attribute_offset = 0
		attributes = omci_def[me_class:uint()]
		attribute_offset=2
		for i = 1,#attributes do
			local attr = attributes[i]
			if attribute_mask:bitfield(i-1,1) == 1 then
				local attr_bytes = content(attribute_offset, attr.length)
				content_subtree:add(attr_bytes, string.format("%2.2d", i) .. ": " .. attr.attname .. " (" .. attr_bytes .. ")")
				attribute_offset = attribute_offset + attr.length
			end
		end
	end

	if((msg_type_mt == "Set" or 
		msg_type_mt == "Create" or
		msg_type_mt == "MIB Reset" or 
		msg_type_mt == "Test" ) and msg_type_ar == 0 and msg_type_ak == 1) then
		subtree:add(content(0,1), "Result: " .. msg_result[content(0,1):uint()] .. " (" .. content(0,1) .. ")")
	end

	if( msg_type_mt == "Create" and msg_type_ar == 1 and msg_type_ak == 0) then
		local content_subtree = subtree:add(content, "Attribute List")
		local attributes = {}
		local attribute_offset = 0
		attributes = omci_def[me_class:uint()]
		attribute_offset=0
		for i = 1,#attributes do
			local attr = attributes[i]
			if attr.setbycreate then
				local attr_bytes = content(attribute_offset, attr.length)
				content_subtree:add(attr_bytes, string.format("%2.2d", i) .. ": " .. attr.attname .. " (" .. attr_bytes .. ")")
				attribute_offset = attribute_offset + attr.length
			end
		end
	end

	if(msg_type_mt == "MIB Upload" and msg_type_ar == 0 and msg_type_ak == 1) then
		subtree:add(content(0,2), "Number of subsequent commands: " .. content(0,2):uint() .. " (" .. content(0,2) .. ")")
	end

	if(msg_type_mt == "MIB Upload Next" and msg_type_ar == 1 and msg_type_ak == 0) then
		subtree:add(content(0,2), "Command number: " .. content(0,2):uint() .. " (" .. content(0,2) .. ")")
	end

	if(msg_type_mt == "MIB Upload Next" and msg_type_ar == 0 and msg_type_ak == 1) then
		local upload_substree = subtree:add(content, "ME Class Upload Content")
		local upload_me_class = content(0,2)
		upload_substree:add( upload_me_class, "Managed Entity Class: " .. omci_def[upload_me_class:uint()].me_class_name .. " (" .. upload_me_class:uint() .. ")")
		upload_substree:add(content(2,2), "Managed Entity Instance: " .. content(2,2):uint() .. " (0x" .. content(2,2) .. ")")
		local attribute_mask = content(4, 2)
		local attributemask_subtree = upload_substree:add(attribute_mask, "Attribute Mask (0x" .. attribute_mask .. ")" )
		attributemask_subtree:add(attribute_mask, tostring(BinDecHex.Hex2Bin(tostring(attribute_mask))))
		local content_subtree = upload_substree:add(content, "Attribute List")
		local attributes = {}
		local attribute_offset
		attributes = omci_def[upload_me_class:uint()]
		attribute_offset=6
		for i = 1,#attributes do
			local attr = attributes[i]
			if attribute_mask:bitfield(i-1,1) == 1 then
				local attr_bytes = content(attribute_offset, attr.length)
				content_subtree:add(attr_bytes, string.format("%2.2d", i) .. ": " .. attr.attname .. " (" .. attr_bytes .. ")")
				attribute_offset = attribute_offset + attr.length
			end			
		end
		me_class_name = me_class_name .. " (" .. omci_def[upload_me_class:uint()].me_class_name .. ")"
	end

	if(msg_type_mt == "Test" and msg_type_ar == 1 and msg_type_ak == 0) then
		if( dev_id:uint() == 0x0b) then -- ITU-T G988 XGPON 
			if( me_class:uint() == 263 ) then -- ANI-G
				subtree:add(content(0,2), "Size of message content field: " .. content(0,2))  
				subtree:add(content(2,1), "Test to perform: " .. test_message_name[content(2,1):uint()] .. " (" .. content(2,1) .. ")")
			end
		elseif( dev_id:uint() == 0x0a) then -- ITU-T G984.4 GPON 
			if( me_class:uint() == 263 ) then -- ANI-G
				subtree:add(content(0,1), "Test to perform: " .. test_message_name[content(0,1):uint()] .. " (" .. content(0,1) .. ")")
			end
		end
	end

	if(msg_type_mt == "Test Result" and msg_type_ar == 0 and msg_type_ak == 0 ) then	
		local content_subtree = subtree:add(content, "Test report")
		if( me_class_name == "ANI-G" ) then
			if( content(0,1):uint() == 1 ) then
				content_subtree:add(content(0,3), "Test " .. string.format("%2.2d: ", content(0,1):uint()) .. "Power feed voltage = " .. content(1,2):int() * 20 .. " mV (0x" .. content(1,2) .. ")")
			else
				content_subtree:add_expert_info( PI_MALFORMED, PI_ERROR, "Unexpected 0x" .. content(0,1) .. " test at this location " )
			end
			if( content(3,1):uint() == 3 ) then
				if( content(4,2):int() ~= 0 ) then
					content_subtree:add(content(3,3), "Test " .. string.format("%2.2d: ", content(3,1):uint()) .. "Received optical power = " .. content(4,2):int() * 0.002 - 30 .. " dBm (0x" .. content(4,2) .. ")")		
				else
					content_subtree:add(content(3,3), "Test " .. string.format("%2.2d: ", content(3,1):uint()) .. "Received optical power: Not supported")
				end
			else
				content_subtree:add_expert_info( PI_MALFORMED, PI_ERROR, "Unexpected 0x" .. content(3,1) .. " test at this location " )
			end		
			if( content(6,1):uint() == 5 ) then
				if( content(7,2):int() ~= 0 ) then
					content_subtree:add(content(6,3), "Test " .. string.format("%2.2d: ", content(6,1):uint()) .. "Transmitted optical power = " .. content(7,2):int() * 0.002 - 30 .. " dBm (0x" .. content(7,2) .. ")")		
				else
					content_subtree:add(content(6,3), "Test " .. string.format("%2.2d: ", content(6,1):uint()) .. "Transmitted optical power: Not supported" )
				end
			else
				content_subtree:add_expert_info( PI_MALFORMED, PI_ERROR, "Unexpected 0x" .. content(6,1) .. " test at this location " )
			end		
			if( content(9,1):uint() == 9 ) then
				content_subtree:add(content(9,3), "Test " .. string.format("%2.2d: ", content(9,1):uint()) .. "Laser bias current = " .. content(10,2):int() * 2 .. " uA (0x" .. content(10,2) .. ")")		
			else
				content_subtree:add_expert_info( PI_MALFORMED, PI_ERROR, "Unexpected 0x" .. content(9,1) .. " test at this location " )
			end		
			if( content(12,1):uint() == 12 ) then
				content_subtree:add(content(12,3), "Test " .. string.format("%2.2d: ", content(12,1):uint()) .. "Temperature = " .. content(13,2):int() / 256.0 .. " deg C (0x" .. content(13,2) .. ")")		
			else
				content_subtree:add_expert_info( PI_MALFORMED, PI_ERROR, "Unexpected 0x" .. content(13,1) .. " test at this location " )
			end		
		else
			subtree:add(content, "Test Result for ME Class " .. me_class_name .. " is not implemented!")
		end
	end

	if(msg_type_mt == "Alarm" and msg_type_ar == 0 and msg_type_ak == 0 ) then	
		local alarm_subtree = subtree:add(content(0,27), "Alarms")
		local alarm_set = false
		for i = 0, 27 do --loop through all alarms
			for j = 0, 7 do
				if(content(i,1):bitfield(j,1) == 1) then
					alarm_subtree:add(content(i,1), "Alarm number " .. i*8+j .. " is set")
					alarm_set = true
				end
			end
		end
		if( alarm_set == false) then
			alarm_subtree:add("All alarms cleared")
		end
		alarm_subtree:add(content(28,3), "Padding")
		alarm_subtree:add(content(31,1), "Sequence number: 0x" .. content(31,1) )		
	end
	
	offset = offset + 32
		
	-- OMCI Trailer (if any)
	if( buffer:len() > 46) then
		local trailer = buffer(offset, 8)
		local trailer_subtree = subtree:add(trailer, "Trailer")
		trailer_subtree:add(f.cpcsuu_cpi, trailer(0,2))
		trailer_subtree:add(f.cpcssdu_length, trailer(2,2))
		trailer_subtree:add(f.crc32, trailer(4,4))
	end

	if( msg_type_ar == 0 ) then
		msg_type_mt = "ONU< " .. msg_type_mt
	else 
		msg_type_mt = "OLT> " .. msg_type_mt
	end

	while msg_type_mt:len() < 25 do  -- Padding to align ME classes
		msg_type_mt = msg_type_mt .. " "
	end
    pinfo.cols.info:set(msg_type_mt .. " - " .. me_class_name)
	subtree:append_text (", " .. msg_type_mt .. " - " .. me_class_name )	-- at the top of the OMCI tree
end

-- Register the dissector
local ether_table = DissectorTable.get( "ethertype" )
ether_table:add(0x88B5, omciproto) 
