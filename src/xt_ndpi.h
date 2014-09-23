/* 
 * xt_ndpi.h
 * Copyright (C) 2010-2012 G. Elian Gidoni <geg@gnu.org>
 *               2012 Ed Wildgoose <lists@wildgooses.com>
 * 
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the PACE technology by ipoque GmbH
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef _LINUX_NETFILTER_XT_NDPI_H
#define _LINUX_NETFILTER_XT_NDPI_H 1

#include <linux/netfilter.h>
#include "ndpi_main.h"

struct xt_ndpi_mtinfo {
        NDPI_PROTOCOL_BITMASK flags;
};
#ifndef NDPI_PROTOCOL_LONG_STRING
#define NDPI_PROTOCOL_LONG_STRING "Unknown","FTP-Data","POP","SMTP","IMAP","DNS","IPP","HTTP","MDNS","NTP","NETBIOS",\
"NFS","SSDP","BGP","SNMP","XDMCP","SMB","SYSLOG","DHCP","PostgreSQL","MySQL",\
"TDS","DirectDownloadLink","I23V5","AppleJuice","DirectConnect","Socrates","WinMX","VMware","PANDO","Filetopia",\
"iMESH","Kontiki","OpenFT","Kazaa","Gnutella","eDonkey","Bittorrent","OFF","AVI","Flash",\
"OGG","MPEG","QuickTime","RealMedia","Windowsmedia","MMS","XBOX","QQ","MOVE","RTSP",\
"IMAPS","Icecast","PPLive","PPStream","Zattoo","SHOUTCast","SopCast","TVAnts","TVUplayer","VeohTV",\
"QQLive","Thunder","Soulseek","GaduGadu","IRC","Popo","Unencrypted_Jabber","MSN","Oscar","Yahoo",\
"Battlefield","Quake","VRRP","Steam","Halflife2","World_of_Warcraft","Telnet","STUN","IPSEC","GRE",\
"ICMP","IGMP","EGP","SCTP","OSPF","IP_in_IP","RTP","RDP","VNC","PCAnywhere",\
"SSL","SSH","USENET","MGCP","IAX","TFTP","AFP","StealthNet","Aimini","SIP",\
"Truphone","ICMPv6","DHCPv6","Armagetron","CrossFire","Dofus","Fiesta","Florensia","Guildwars","HTTP_Application_Activesync",\
"Kerberos","LDAP","MapleStory","msSQL","PPTP","WARCRAFT3","World_of_Kung_Fu","MEEBO","FaceBook","Twitter",\
"DropBox","Gmail","Google_Maps","YouTube","Skype","Google","DCE_RPC","NetFlow_IPFIX","sFlow","HTTP_Connect_SSL_over_HTTP",\
"HTTP_Proxy","Citrix","Netflix","LastFM","Grooveshark","SkyFile_Prepaid","SkyFile_Rudics","SkyFile_Postpaid","CitrixOnline","Apple_iMessage_FaceTime",\
"Webex","WhatsApp","Apple_iCloud","Viber","Apple_iTunes","Radius","Windows_Update","TeamViewer","Tuenti","Lotus_Notes",\
"SAP","GTP","uPnP","LLMNR","Remote_Scan","Spotify","WebM","H323","OpenVPN","NOE","CiscoVPN","TeamSpeak","Tor","Skinny","RTCP","RSYNC","Oracle","Corba","Ubuntu_ONE","WHOIS_DAS"
#endif

#ifndef NDPI_PROTOCOL_SHORT_STRING
#define NDPI_PROTOCOL_SHORT_STRING "ukn","ftp_data","pop","smtp","imap","dns","ipp","http","mdns","ntp","netbios",\
"nfs","ssdp","bgp","snmp","xdmcp","smb","syslog","dhcp","postgres","mysql",\
"tds","ddl","i23v5","applejuice","directconnect","socrates","winmx","vmware","pando","filetopia",\
"iMESH","kontiki","openft","fasttrack","gnutella","edonkey","bittorrent","off","avi","flash",\
"ogg","mpeg","quicktime","realmedia","windowsmedia","mms","xbox","qq","move","rtsp",\
"imaps","icecast","pplive","ppstream","zattoo","shoutcast","sopcast","tvants","tvuplayer","veohtv",\
"qqlive","thunder","soulseek","gadugadu","irc","popo","jabber","msn","oscar","yahoo",\
"battlefield","quake","vrrp","steam","hl2","worldofwarcraft","telnet","stun","ipsec","gre",\
"icmp","igmp","egp","sctp","ospf","ipip","rtp","rdp","vnc","pcanywhere",\
"ssl","ssh","usenet","mgcp","iax","tftp","afp","stealthnet","aimini","sip",\
"truphone","icmpv6","dhcpv6","armagetron","crossfire","dofus","fiesta","florensia","guildwars","httpactivesync",\
"kerberos","ldap","maplestory","mssql","pptp","warcraft3","wokf","meebo","facebook","twitter",\
"dropbox","gmail","gmaps","youtube","skype","google","dcerpc","netflow","sflow","httpconnect",\
"httpproxy","citrix","netflix","lastfm","grooveshark","skyfileprepaid","skyfilerudics","skyfilepostpaid","citrixonline","apple",\
"webex","wgatsapp","appleicloud","viber","appleitunes","radius","windowsupdate","teamviewer","tuenti","lotusnotes",\
"sap","gtp","upnp","llmnr","remotescan","spotify","webm","h323","openvpn","noe","ciscovpn","teamspeak","tor","skinny","rtcp","rsync","oracle","corba","ubuntuone","whoisdas"
#endif

#ifndef NDPI_LAST_NFPROTO
#define NDPI_LAST_NFPROTO NDPI_LAST_IMPLEMENTED_PROTOCOL-13
#endif

#endif /* _LINUX_NETFILTER_XT_NDPI_H */
