/*
* This file is part of Capby.
* 
* Capby is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* Capby is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU Lesser General Public License for more details.
* 
* You should have received a copy of the GNU Lesser General Public License
* along with Capby.  If not, see <http://www.gnu.org/licenses/>.
* 
* Copyright (c) 2009, Di Cioccio Lucas
*/

#ifndef CAPBY_HEADERS
        #define CAPBY_HEADERS
#endif

#ifdef CAPBY_SOURCE
        #define __capby_global__
#else
        #define __capby_global__ extern
#endif

#ifndef CAPBY_VERSION
        #define CAPBY_VERSION "0.5.3"
#endif

#ifndef CAPBY_DEFAULT_BUFLEN
        #define CAPBY_DEFAULT_BUFLEN 3000
#endif

#ifdef WIN32
#ifndef CAPBY_DEFAULT_TIMEOUT
	#define CAPBY_DEFAULT_TIMEOUT 0
#endif

#ifndef HAVE_TYPE_STRUCT_TIMESPEC
#define HAVE_TYPE_STRUCT_TIMESPEC 1
struct timespec{
	long tv_sec;
	long tv_nsec;
};
#endif
#endif /* WIN32 */

#include <pcap.h>
#include <ruby.h>

/* define datatypes */
struct capby_datalink_triolet {
        int idx;
        const char *name;
        VALUE sym;
};

struct capby_capture {
        pcap_t * ctx;
        int      type;
        VALUE    dev;
};
#define CAPBY_LIVE_CAPTURE (1 << 0)
#define CAPBY_FILE_CAPTURE (1 << 1)

struct capby_packet {
        VALUE data;
        VALUE tst;
};

struct __capby_version_record {
        const char* cst;
        const char* val;
};


/* Shared data */
__capby_global__ VALUE capby_mCapby;
__capby_global__ VALUE capby_mConstants;
__capby_global__ VALUE capby_mConstantsDLT;
__capby_global__ VALUE capby_eError;
__capby_global__ VALUE capby_cDevice;
__capby_global__ VALUE capby_cCapture;
__capby_global__ VALUE capby_cLiveCapture;
__capby_global__ VALUE capby_cFileCapture;
__capby_global__ VALUE capby_cPacket;

__capby_global__ 
struct capby_datalink_triolet capby_datalink_mapping[] = {
        /* Please tell me if there are missing ones, or if some need an #ifdef before */
#ifdef DLT_NULL
        {DLT_NULL,"null",Qnil},
#else
#error We should have the DLT_NULL macro
#endif

#ifdef DLT_EN10MB
        {DLT_EN10MB,"en10mb",Qnil},
#endif
#ifdef DLT_EN3MB
        {DLT_EN3MB,"en3mb",Qnil},
#endif
#ifdef DLT_AX25
        {DLT_AX25,"ax25",Qnil},
#endif
#ifdef DLT_PRONET
        {DLT_PRONET,"pronet",Qnil},
#endif
#ifdef DLT_CHAOS
        {DLT_CHAOS,"chaos",Qnil},
#endif
#ifdef DLT_IEEE802
        {DLT_IEEE802,"ieee802",Qnil},
#endif
#ifdef DLT_ARCNET
        {DLT_ARCNET,"arcnet",Qnil},
#endif
#ifdef DLT_SLIP
        {DLT_SLIP,"slip",Qnil},
#endif
#ifdef DLT_PPP
        {DLT_PPP,"ppp",Qnil},
#endif
#ifdef DLT_FDDI
        {DLT_FDDI,"fddi",Qnil},
#endif
#ifdef DLT_ATM_RFC1483
        {DLT_ATM_RFC1483,"atm_rfc1483",Qnil},
#endif
#ifdef DLT_RAW
        {DLT_RAW,"raw",Qnil},
#endif
#ifdef DLT_PPP_BSDOS
        {DLT_PPP_BSDOS,"ppp_bsdos",Qnil},
#endif
#ifdef DLT_SLIP_BSDOS
        {DLT_SLIP_BSDOS,"slip_bsdos",Qnil},
#endif
#ifdef DLT_ATM_CLIP
        {DLT_ATM_CLIP,"atm_clip",Qnil},
#endif
#ifdef DLT_REDBACK_SMARTEDGE
        {DLT_REDBACK_SMARTEDGE,"redback_smartedge",Qnil},
#endif
#ifdef DLT_PPP_SERIAL
        {DLT_PPP_SERIAL,"ppp_serial",Qnil},
#endif
#ifdef DLT_PPP_ETHER
        {DLT_PPP_ETHER,"ppp_ether",Qnil},
#endif
#ifdef DLT_SYMANTEC_FIREWALL
        {DLT_SYMANTEC_FIREWALL,"symantec_firewall",Qnil},
#endif
#ifdef DLT_C_HDLC
        {DLT_C_HDLC,"c_hdlc",Qnil},
#endif
#ifdef DLT_CHDLC
        {DLT_CHDLC,"chdlc",Qnil},
#endif
#ifdef DLT_IEEE802_11
        {DLT_IEEE802_11,"ieee802_11",Qnil},
#endif
#ifdef DLT_FRELAY
        {DLT_FRELAY,"frelay",Qnil},
#endif
#ifdef DLT_LOOP
        {DLT_LOOP,"loop",Qnil},
#endif
#ifdef DLT_ENC
        {DLT_ENC,"enc",Qnil},
#endif
#ifdef DLT_LINUX_SLL
        {DLT_LINUX_SLL,"linux_sll",Qnil},
#endif
#ifdef DLT_LTALK
        {DLT_LTALK,"ltalk",Qnil},
#endif
#ifdef DLT_ECONET
        {DLT_ECONET,"econet",Qnil},
#endif
#ifdef DLT_IPFILTER
        {DLT_IPFILTER,"ipfilter",Qnil},
#endif
#ifdef DLT_OLD_PFLOG
        {DLT_OLD_PFLOG,"old_pflog",Qnil},
#endif
#ifdef DLT_PFSYNC
        {DLT_PFSYNC,"pfsync",Qnil},
#endif
#ifdef DLT_PFLOG
        {DLT_PFLOG,"pflog",Qnil},
#endif
#ifdef DLT_CISCO_IOS
        {DLT_CISCO_IOS,"cisco_ios",Qnil},
#endif
#ifdef DLT_PRISM_HEADER
        {DLT_PRISM_HEADER,"prism_header",Qnil},
#endif
#ifdef DLT_AIRONET_HEADER
        {DLT_AIRONET_HEADER,"aironet_header",Qnil},
#endif
#ifdef DLT_HHDLC
        {DLT_HHDLC,"hhdlc",Qnil},
#endif
#ifdef DLT_IP_OVER_FC
        {DLT_IP_OVER_FC,"ip_over_fc",Qnil},
#endif
#ifdef DLT_SUNATM
        {DLT_SUNATM,"sunatm",Qnil},
#endif
#ifdef DLT_RIO
        {DLT_RIO,"rio",Qnil},
#endif
#ifdef DLT_PCI_EXP
        {DLT_PCI_EXP,"pci_exp",Qnil},
#endif
#ifdef DLT_AURORA
        {DLT_AURORA,"aurora",Qnil},
#endif
#ifdef DLT_IEEE802_11_RADIO
        {DLT_IEEE802_11_RADIO,"ieee802_11_radio",Qnil},
#endif
#ifdef DLT_TZSP
        {DLT_TZSP,"tzsp",Qnil},
#endif
#ifdef DLT_ARCNET_LINUX
        {DLT_ARCNET_LINUX,"arcnet_linux",Qnil},
#endif
#ifdef DLT_JUNIPER_MLPPP
        {DLT_JUNIPER_MLPPP,"juniper_mlppp",Qnil},
#endif
#ifdef DLT_JUNIPER_MLFR
        {DLT_JUNIPER_MLFR,"juniper_mlfr",Qnil},
#endif
#ifdef DLT_JUNIPER_ES
        {DLT_JUNIPER_ES,"juniper_es",Qnil},
#endif
#ifdef DLT_JUNIPER_GGSN
        {DLT_JUNIPER_GGSN,"juniper_ggsn",Qnil},
#endif
#ifdef DLT_JUNIPER_MFR
        {DLT_JUNIPER_MFR,"juniper_mfr",Qnil},
#endif
#ifdef DLT_JUNIPER_ATM2
        {DLT_JUNIPER_ATM2,"juniper_atm2",Qnil},
#endif
#ifdef DLT_JUNIPER_SERVICES
        {DLT_JUNIPER_SERVICES,"juniper_services",Qnil},
#endif
#ifdef DLT_JUNIPER_ATM1
        {DLT_JUNIPER_ATM1,"juniper_atm1",Qnil},
#endif
#ifdef DLT_APPLE_IP_OVER_IEEE1394
        {DLT_APPLE_IP_OVER_IEEE1394,"apple_ip_over_ieee1394",Qnil},
#endif
#ifdef DLT_MTP2_WITH_PHDR
        {DLT_MTP2_WITH_PHDR,"mtp2_with_phdr",Qnil},
#endif
#ifdef DLT_MTP2
        {DLT_MTP2,"mtp2",Qnil},
#endif
#ifdef DLT_MTP3
        {DLT_MTP3,"mtp3",Qnil},
#endif
#ifdef DLT_SCCP
        {DLT_SCCP,"sccp",Qnil},
#endif
#ifdef DLT_DOCSIS
        {DLT_DOCSIS,"docsis",Qnil},
#endif
#ifdef DLT_LINUX_IRDA
        {DLT_LINUX_IRDA,"linux_irda",Qnil},
#endif
#ifdef DLT_IBM_SP
        {DLT_IBM_SP,"ibm_sp",Qnil},
#endif
#ifdef DLT_IBM_SN
        {DLT_IBM_SN,"ibm_sn",Qnil},
#endif
#ifdef DLT_USER0
        {DLT_USER0,"user0",Qnil},
#endif
#ifdef DLT_USER1
        {DLT_USER1,"user1",Qnil},
#endif
#ifdef DLT_USER2
        {DLT_USER2,"user2",Qnil},
#endif
#ifdef DLT_USER3
        {DLT_USER3,"user3",Qnil},
#endif
#ifdef DLT_USER4
        {DLT_USER4,"user4",Qnil},
#endif
#ifdef DLT_USER5
        {DLT_USER5,"user5",Qnil},
#endif
#ifdef DLT_USER6
        {DLT_USER6,"user6",Qnil},
#endif
#ifdef DLT_USER7
        {DLT_USER7,"user7",Qnil},
#endif
#ifdef DLT_USER8
        {DLT_USER8,"user8",Qnil},
#endif
#ifdef DLT_USER9
        {DLT_USER9,"user9",Qnil},
#endif
#ifdef DLT_USER10
        {DLT_USER10,"user10",Qnil},
#endif
#ifdef DLT_USER11
        {DLT_USER11,"user11",Qnil},
#endif
#ifdef DLT_USER12
        {DLT_USER12,"user12",Qnil},
#endif
#ifdef DLT_USER13
        {DLT_USER13,"user13",Qnil},
#endif
#ifdef DLT_USER14
        {DLT_USER14,"user14",Qnil},
#endif
#ifdef DLT_USER15
        {DLT_USER15,"user15",Qnil},
#endif
#ifdef DLT_IEEE802_11_RADIO_AVS
        {DLT_IEEE802_11_RADIO_AVS,"ieee802_11_radio_avs",Qnil},
#endif
#ifdef DLT_JUNIPER_MONITOR
        {DLT_JUNIPER_MONITOR,"juniper_monitor",Qnil},
#endif
#ifdef DLT_BACNET_MS_TP
        {DLT_BACNET_MS_TP,"bacnet_ms_tp",Qnil},
#endif
#ifdef DLT_PPP_PPPD
        {DLT_PPP_PPPD,"ppp_pppd",Qnil},
#endif
#ifdef DLT_PPP_WITH_DIRECTION
        {DLT_PPP_WITH_DIRECTION,"ppp_with_direction",Qnil},
#endif
#ifdef DLT_LINUX_PPP_WITHDIRECTION
        {DLT_LINUX_PPP_WITHDIRECTION,"linux_ppp_withdirection",Qnil},
#endif
#ifdef DLT_JUNIPER_PPPOE
        {DLT_JUNIPER_PPPOE,"juniper_pppoe",Qnil},
#endif
#ifdef DLT_JUNIPER_PPPOE_ATM
        {DLT_JUNIPER_PPPOE_ATM,"juniper_pppoe_atm",Qnil},
#endif
#ifdef DLT_GPRS_LLC
        {DLT_GPRS_LLC,"gprs_llc",Qnil},
#endif
#ifdef DLT_GPF_T
        {DLT_GPF_T,"gpf_t",Qnil},
#endif
#ifdef DLT_GPF_F
        {DLT_GPF_F,"gpf_f",Qnil},
#endif
#ifdef DLT_GCOM_T1E1
        {DLT_GCOM_T1E1,"gcom_t1e1",Qnil},
#endif
#ifdef DLT_GCOM_SERIAL
        {DLT_GCOM_SERIAL,"gcom_serial",Qnil},
#endif
#ifdef DLT_JUNIPER_PIC_PEER
        {DLT_JUNIPER_PIC_PEER,"juniper_pic_peer",Qnil},
#endif
#ifdef DLT_ERF_ETH
        {DLT_ERF_ETH,"erf_eth",Qnil},
#endif
#ifdef DLT_ERF_POS
        {DLT_ERF_POS,"erf_pos",Qnil},
#endif
#ifdef DLT_LINUX_LAPD
        {DLT_LINUX_LAPD,"linux_lapd",Qnil},
#endif
#ifdef DLT_JUNIPER_ETHER
        {DLT_JUNIPER_ETHER,"juniper_ether",Qnil},
#endif
#ifdef DLT_JUNIPER_PPP
        {DLT_JUNIPER_PPP,"juniper_ppp",Qnil},
#endif
#ifdef DLT_JUNIPER_FRELAY
        {DLT_JUNIPER_FRELAY,"juniper_frelay",Qnil},
#endif
#ifdef DLT_JUNIPER_CHDLC
        {DLT_JUNIPER_CHDLC,"juniper_chdlc",Qnil},
#endif
#ifdef DLT_MFR
        {DLT_MFR,"mfr",Qnil},
#endif
#ifdef DLT_JUNIPER_VP
        {DLT_JUNIPER_VP,"juniper_vp",Qnil},
#endif
#ifdef DLT_A429
        {DLT_A429,"a429",Qnil},
#endif
#ifdef DLT_A653_ICM
        {DLT_A653_ICM,"a653_icm",Qnil},
#endif
#ifdef DLT_USB
        {DLT_USB,"usb",Qnil},
#endif
#ifdef DLT_BLUETOOTH_HCI_H4
        {DLT_BLUETOOTH_HCI_H4,"bluetooth_hci_h4",Qnil},
#endif
#ifdef DLT_IEEE802_16_MAC_CPS
        {DLT_IEEE802_16_MAC_CPS,"ieee802_16_mac_cps",Qnil},
#endif
#ifdef DLT_USB_LINUX
        {DLT_USB_LINUX,"usb_linux",Qnil},
#endif
#ifdef DLT_CAN20B
        {DLT_CAN20B,"can20b",Qnil},
#endif
#ifdef DLT_IEEE802_15_4_LINUX
        {DLT_IEEE802_15_4_LINUX,"ieee802_15_4_linux",Qnil},
#endif
#ifdef DLT_PPI
        {DLT_PPI,"ppi",Qnil},
#endif
#ifdef DLT_IEEE802_16_MAC_CPS_RADIO
        {DLT_IEEE802_16_MAC_CPS_RADIO,"ieee802_16_mac_cps_radio",Qnil},
#endif
#ifdef DLT_JUNIPER_ISM
        {DLT_JUNIPER_ISM,"juniper_ism",Qnil},
#endif
#ifdef DLT_IEEE802_15_4
        {DLT_IEEE802_15_4,"ieee802_15_4",Qnil},
#endif
#ifdef DLT_SITA
        {DLT_SITA,"sita",Qnil},
#endif
#ifdef DLT_ERF
        {DLT_ERF,"erf",Qnil},
#endif
#ifdef DLT_RAIF1
        {DLT_RAIF1,"raif1",Qnil},
#endif
#ifdef DLT_IPMB
        {DLT_IPMB,"ipmb",Qnil},
#endif
#ifdef DLT_JUNIPER_ST
        {DLT_JUNIPER_ST,"juniper_st",Qnil},
#endif
#ifdef DLT_BLUETOOTH_HCI_H4_WITH_PHDR
        {DLT_BLUETOOTH_HCI_H4_WITH_PHDR,"bluetooth_hci_h4_with_phdr",Qnil},
#endif
#ifdef DLT_AX25_KISS
        {DLT_AX25_KISS,"ax25_kiss",Qnil},
#endif
#ifdef DLT_LAPD
        {DLT_LAPD,"lapd",Qnil},
#endif
#ifdef DLT_PPP_WITH_DIR
        {DLT_PPP_WITH_DIR,"ppp_with_dir",Qnil},
#endif
#ifdef DLT_C_HDLC_WITH_DIR
        {DLT_C_HDLC_WITH_DIR,"c_hdlc_with_dir",Qnil},
#endif
#ifdef DLT_FRELAY_WITH_DIR
        {DLT_FRELAY_WITH_DIR,"frelay_with_dir",Qnil},
#endif
#ifdef DLT_LAPB_WITH_DIR
        {DLT_LAPB_WITH_DIR,"lapb_with_dir",Qnil},
#endif
#ifdef DLT_IPMB_LINUX
        {DLT_IPMB_LINUX,"ipmb_linux",Qnil},
#endif
#ifdef DLT_FLEXRAY
        {DLT_FLEXRAY,"flexray",Qnil},
#endif
#ifdef DLT_MOST
        {DLT_MOST,"most",Qnil},
#endif
#ifdef DLT_LIN
        {DLT_LIN,"lin",Qnil},
#endif
#ifdef DLT_X2E_SERIAL
        {DLT_X2E_SERIAL,"x2e_serial",Qnil},
#endif
#ifdef DLT_X2E_XORAYA
        {DLT_X2E_XORAYA,"x2e_xoraya",Qnil},
#endif
#ifdef DLT_IEEE802_15_4_NONASK_PHY
        {DLT_IEEE802_15_4_NONASK_PHY,"ieee802_15_4_nonask_phy",Qnil},
#endif
        {-1, NULL, Qnil}
};

__capby_global__ 
struct __capby_version_record __capby_version_records[] = {
        /* Store at compile time the various library version numbers */
#ifndef RUBY_19
        {"RUBY_VERSION", ruby_version},
#else
	{"RUBY_VERSION", "1.9.x"},
#endif
        {"CAPBY_VERSION", CAPBY_VERSION},
        /* {"PCAP_VERSION", pcap_lib_version()}, */ //TODO: perform +/- that
        {NULL, NULL}
};

/* Shared functions */
__capby_global__ int capby_SYM2DLT(VALUE);
__capby_global__ VALUE capby_DLT2SYM(int);
__capby_global__ void capby_warn_not_equal(VALUE, VALUE, const char *); //TODO: check if there is not a builtin function
