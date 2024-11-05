#!/usr/bin/env python

"""
Script to setup Prisma SDWAN Simplified PoV using a CSV
Author: tkamath@paloaltonetworks.com
Version: 1.0.0b11
"""
import prisma_sase
import argparse
import os
import time
import sys
import datetime
import copy
import pandas as pd
import numpy as np
import csv
##############################################################################
# Service Account Details -
# Create a Service Account at the Master tenant level
# Grant All Apps & MSP Super Privileges
##############################################################################
try:
    from prismasase_settings import PRISMASASE_CLIENT_ID, PRISMASASE_CLIENT_SECRET, PRISMASASE_TSG_ID

except ImportError:
    PRISMASASE_CLIENT_ID = None
    PRISMASASE_CLIENT_SECRET = None
    PRISMASASE_TSG_ID = None

##############################################################################
# CSV HEADER from Google Form
##############################################################################
CSV_HEADER_MANDATORY=["customer_name","device_model","enable_ha",
                      "site_name","address_city","address_country","address_street",
                      "address_street2","address_zipcode","address_state",
                      "latitude","longitude","internet_circuit_count","private_circuit_count","default_settings",
                      "branch_domain","domain_list",
                      "primary_internet_circuitname","primary_internet_provider","primary_internet_category",
                      "primary_internet_interface","primary_internet_ip_prefix","primary_internet_default_gw","primary_internet_dns",
                      "secondary_internet_circuitname","secondary_internet_provider","secondary_internet_category",
                      "secondary_internet_interface","secondary_internet_ip_prefix","secondary_internet_default_gw","secondary_internet_dns",
                      "private_wan_circuitname","private_wan_provider","private_wan_category",
                      "private_wan_interface","private_wan_ip_prefix","private_wan_default_gw","private_wan_dns",
                      "lan_interface","num_vlans","lan_ip_prefix","lan_dns","lan_scope"]

CSV_HEADER_VLAN=["vlan_id","vlan_name","vlan_ip_prefix","vlan_scope", "vlan_used_for"]

##############################################################################
# Default Config
##############################################################################
DEFAULT_VALUES = {
    #############################################################
    # Topology
    #############################################################
    "device_model":"1200S",
    "enable_ha": True,
    #############################################################
    # Site Details
    #############################################################
    "site_name": "Branch_DualInternet_1200S_HA",
    "address_city": "New York",
    "address_country": "United States",
    "address_street": "",
    "address_street2": "",
    "address_zipcode": "",
    "address_state": "",
    "latitude": "40.7127492",
    "longitude": "-74.0059945",
    #############################################################
    # Domains
    #############################################################
    "branch_domain": "Preset Domain",
    "domain_list": ["EMEA", "NAM", "JPAC"],
    #############################################################
    # Primary Internet
    #############################################################
    "internet_circuit_count": 2,
    "primary_internet_circuitname": "Primary Internet Circuit",
    "primary_internet_provider": "ISP 1",
    "primary_internet_category": "Primary Internet",
    "primary_internet_interface": "1",
    "primary_internet_ip_prefix": "10.20.30.1/24",
    "primary_internet_default_gw": "10.20.30.10",
    "primary_internet_dns": ["8.8.8.8","8.8.4.4"],
    #############################################################
    # Secondary Internet
    #############################################################
    "secondary_internet_circuitname": "Secondary Internet Circuit",
    "secondary_internet_provider": "ISP 2",
    "secondary_internet_category": "Secondary Internet",
    "secondary_internet_interface": "34",
    "secondary_internet_ip_prefix": "dhcp",
    "secondary_internet_default_gw": "dhcp",
    "secondary_internet_dns": ["8.8.8.8","8.8.4.4"],
    #############################################################
    # Private WAN
    #############################################################
    "private_circuit_count": 0,
    "private_wan_circuitname": "MPLS Circuit",
    "private_wan_provider": "Carrier 1",
    "private_wan_category": "MPLS",
    "private_wan_interface": "34",
    "private_wan_ip_prefix": "dhcp",
    "private_wan_default_gw": "dhcp",
    "private_wan_dns": ["8.8.8.8","8.8.4.4"],
    #############################################################
    # LAN Interface
    #############################################################
    "lan_interface": "5",
    "num_vlans": "4",
    "lan_ip_prefix": "",
    "lan_dns": "",
    "lan_scope": "",
    #############################################################
    # VLAN Config
    #############################################################
    "vlan_id_1": 510,
    "vlan_name_1": "HA",
    "vlan_ip_prefix_1": "10.20.10.1/24",
    "vlan_used_for_1": "ha",
    "vlan_scope_1": "global",

    "vlan_id_2": 520,
    "vlan_name_2": "GUEST",
    "vlan_ip_prefix_2": "10.20.20.1/24",
    "vlan_used_for_2": "lan",
    "vlan_scope_2": "local",

    "vlan_id_3": 530,
    "vlan_name_3": "VOICE",
    "vlan_ip_prefix_3": "10.20.30.1/24",
    "vlan_used_for_3": "lan",
    "vlan_scope_3": "local",

    "vlan_id_4": 540,
    "vlan_name_4": "DATA",
    "vlan_ip_prefix_4": "10.20.40.1/24",
    "vlan_used_for_4": "lan",
    "vlan_scope_4": "local"
}


##############################################################################
# Default Global Config
##############################################################################
#############################################################
# Topology
#############################################################
CUSTOMER_NAME=None
BRANCH_MODEL="1200S"
HA=True
#############################################################
# Site Details
#############################################################
SITE_NAME="Branch_DualInternet_1200S_HA"
ADDRESS_CITY="New York"
ADDRESS_COUNTRY="United States"
ADDRESS_STREET=None
ADDRESS_STREET2=None
ADDRESS_STATE=None
ADDRESS_ZIPCODE=None
ADDRESS_LATITUDE="40.7127492"
ADDRESS_LONGITUDE="-74.0059945"
#############################################################
# Domains
#############################################################
BRANCH_DOMAIN="Preset Domain"
DOMAIN_LIST = ["EMEA", "NAM", "JPAC"]
#############################################################
# Primary Internet
#############################################################
NUM_INTERNET=2
PRIMARY_INTERNET_CATEGORY="Primary Internet"
PRIMARY_INTERNET_PROVIDER="ISP 1"
PRIMARY_INTERNET_CIRCUITNAME="Primary Internet Circuit"
PRIMARY_INTERNET_INTERFACE="1"
PRIMARY_INTERNET_IP_PREFIX="10.20.30.1/24"
PRIMARY_INTERNET_GW="10.20.30.10"
PRIMARY_INTERNET_DNS=["8.8.8.8", "8.8.4.4"]
#############################################################
# Secondary Internet
#############################################################
SECONDARY_INTERNET_CATEGORY="Secondary Internet"
SECONDARY_INTERNET_PROVIDER="ISP 2"
SECONDARY_INTERNET_CIRCUITNAME="Secondary Internet Circuit"
SECONDARY_INTERNET_INTERFACE="34"
SECONDARY_INTERNET_IP_PREFIX="dhcp"
SECONDARY_INTERNET_GW="dhcp"
SECONDARY_INTERNET_DNS=["8.8.8.8", "8.8.4.4"]
#############################################################
# Private WAN
#############################################################
NUM_PRIVATE=0
PRIVATEWAN_CATEGORY="MPLS"
PRIVATEWAN_PROVIDER="Carrier 1"
PRIVATEWAN_CIRCUITNAME="MPLS Circuit"
PRIVATEWAN_INTERFACE="34"
PRIVATEWAN_IP_PREFIX="dhcp"
PRIVATEWAN_GW="dhcp"
PRIVATEWAN_DNS=["8.8.8.8", "8.8.4.4"]
#############################################################
# LAN Interface
#############################################################
LAN_INTERFACE="5"
LAN_IP_PREFIX="dhcp"
LAN_SCOPE="local"
LAN_DNS = None
#############################################################
# VLAN Config
#############################################################
NUM_VLANS = 4
VLAN_CONFIG = [ {"vlan_id": 510, "name": "HA", "ip_prefix": "10.20.10.1/24", "gw": "10.20.10.10", "dns": ["8.8.8.8", "8.8.4.4"], "used_for": "ha", "scope": "global"},
                {"vlan_id": 520, "name": "GUEST", "ip_prefix": "10.20.20.1/24", "gw": "10.20.20.10", "dns": ["8.8.8.8", "8.8.4.4"], "used_for": "lan", "scope": "local"},
                {"vlan_id": 530, "name": "VOICE", "ip_prefix": "10.20.30.1/24", "gw": "10.20.30.10", "dns": ["8.8.8.8", "8.8.4.4"], "used_for": "lan", "scope": "local"},
                {"vlan_id": 540, "name": "DATA", "ip_prefix": "10.20.40.1/24", "gw": "10.20.40.10", "dns": ["8.8.8.8", "8.8.4.4"], "used_for": "lan", "scope": "local"}]


##############################################################################
# Set Global dicts & variables
##############################################################################
def transpose_config(rowdata):
    global SITE_NAME
    global BRANCH_MODEL
    global HA
    global ADDRESS_CITY
    global ADDRESS_COUNTRY
    global ADDRESS_STREET
    global ADDRESS_STREET2
    global ADDRESS_ZIPCODE
    global ADDRESS_STATE
    global ADDRESS_LATITUDE
    global ADDRESS_LONGITUDE
    global NUM_INTERNET
    global NUM_PRIVATE
    global BRANCH_DOMAIN
    global DOMAIN_LIST

    global PRIMARY_INTERNET_CATEGORY
    global PRIMARY_INTERNET_PROVIDER
    global PRIMARY_INTERNET_CIRCUITNAME
    global PRIMARY_INTERNET_INTERFACE
    global PRIMARY_INTERNET_IP_PREFIX
    global PRIMARY_INTERNET_GW
    global PRIMARY_INTERNET_DNS

    global SECONDARY_INTERNET_CATEGORY
    global SECONDARY_INTERNET_PROVIDER
    global SECONDARY_INTERNET_CIRCUITNAME
    global SECONDARY_INTERNET_INTERFACE
    global SECONDARY_INTERNET_IP_PREFIX
    global SECONDARY_INTERNET_GW
    global SECONDARY_INTERNET_DNS

    global PRIVATEWAN_CATEGORY
    global PRIVATEWAN_PROVIDER
    global PRIVATEWAN_CIRCUITNAME
    global PRIVATEWAN_INTERFACE
    global PRIVATEWAN_IP_PREFIX
    global PRIVATEWAN_GW
    global PRIVATEWAN_DNS

    global LAN_INTERFACE
    global LAN_IP_PREFIX
    global LAN_SCOPE
    global LAN_DNS
    global VLAN_CONFIG
    global CUSTOMER_NAME
    global NUM_VLANS
    global ION_SOFTWARE_VERSION

    #
    # Extract values from passed CSV for mandatory form fields
    #
    CUSTOMER_NAME = rowdata["customer_name"]
    SITE_NAME = rowdata["site_name"]
    BRANCH_MODEL = rowdata["device_model"]
    ION_SOFTWARE_VERSION = rowdata["software_version"]

    if rowdata["enable_ha"] in ["No", "no", "NO"]:
        HA = False
    else:
        HA = True

    ADDRESS_CITY = rowdata["address_city"]
    ADDRESS_COUNTRY = rowdata["address_country"]
    ADDRESS_STREET = rowdata["address_street"]
    ADDRESS_STREET2 = rowdata["address_street2"]
    ADDRESS_ZIPCODE = rowdata["address_zipcode"]
    ADDRESS_STATE = rowdata["address_state"]
    ADDRESS_LATITUDE = rowdata["latitude"]
    ADDRESS_LONGITUDE = rowdata["longitude"]
    NUM_INTERNET = int(rowdata["internet_circuit_count"])
    NUM_PRIVATE = int(rowdata["private_circuit_count"])

    if rowdata["default_settings"] in ["No", "no", "NO"]:
        BRANCH_DOMAIN = rowdata["branch_domain"]
        DOMAIN_LIST = rowdata["domain_list"]
        PRIMARY_INTERNET_CATEGORY = rowdata["primary_internet_category"]
        PRIMARY_INTERNET_PROVIDER = rowdata["primary_internet_provider"]
        PRIMARY_INTERNET_CIRCUITNAME = rowdata["primary_internet_circuitname"]
        PRIMARY_INTERNET_INTERFACE = rowdata["primary_internet_interface"]
        PRIMARY_INTERNET_IP_PREFIX = rowdata["primary_internet_ip_prefix"]
        PRIMARY_INTERNET_GW = rowdata["primary_internet_default_gw"]
        pri_dns_entries = rowdata["primary_internet_dns"]
        PRIMARY_INTERNET_DNS=[]
        if pri_dns_entries is not None:
            tmp = pri_dns_entries.split(",")
            for item in tmp:
                PRIMARY_INTERNET_DNS.append(item)
        #############################################################
        # Secondary Internet
        #############################################################
        SECONDARY_INTERNET_CATEGORY = rowdata["secondary_internet_category"]
        SECONDARY_INTERNET_PROVIDER = rowdata["secondary_internet_provider"]
        SECONDARY_INTERNET_CIRCUITNAME = rowdata["secondary_internet_circuitname"]
        SECONDARY_INTERNET_INTERFACE = rowdata["secondary_internet_interface"]
        SECONDARY_INTERNET_IP_PREFIX = rowdata["secondary_internet_ip_prefix"]
        SECONDARY_INTERNET_GW = rowdata["secondary_internet_default_gw"]
        SECONDARY_INTERNET_DNS = rowdata["secondary_internet_dns"]
        sec_dns_entries = rowdata["secondary_internet_dns"]
        SECONDARY_INTERNET_DNS = []
        if sec_dns_entries is not None:
            tmp = sec_dns_entries.split(",")
            for item in tmp:
                SECONDARY_INTERNET_DNS.append(item)
        #############################################################
        # Private WAN
        #############################################################
        PRIVATEWAN_CATEGORY = rowdata["private_wan_category"]
        PRIVATEWAN_PROVIDER = rowdata["private_wan_provider"]
        PRIVATEWAN_CIRCUITNAME = rowdata["private_wan_circuitname"]
        PRIVATEWAN_INTERFACE = rowdata["private_wan_interface"]
        PRIVATEWAN_IP_PREFIX = rowdata["private_wan_ip_prefix"]
        PRIVATEWAN_GW = rowdata["private_wan_default_gw"]
        PRIVATEWAN_DNS = rowdata["private_wan_dns"]
        #############################################################
        # LAN Interface
        #############################################################
        LAN_INTERFACE = rowdata["lan_interface"]
        LAN_IP_PREFIX = rowdata["lan_ip_prefix"]
        LAN_SCOPE = rowdata["lan_scope"]
        LAN_DNS = rowdata["lan_dns"]
        #############################################################
        # VLAN Config
        #############################################################
        vlanlist = []
        configuredvlans = 1
        NUM_VLANS = int(rowdata["num_vlans"])
        if NUM_VLANS > 0:
            while configuredvlans <= NUM_VLANS:
                vlankey = "vlan_id_{}".format(configuredvlans)
                namekey = "vlan_name_{}".format(configuredvlans)
                ipprefixkey = "vlan_ip_prefix_{}".format(configuredvlans)
                usedforkey = "vlan_used_for_{}".format(configuredvlans)
                scopekey = "vlan_scope_{}".format(configuredvlans)

                if (vlankey not in rowdata.keys()) or \
                        (namekey not in rowdata.keys()) or \
                        (ipprefixkey not in rowdata.keys()) or \
                        (usedforkey not in rowdata.keys()) or \
                        (scopekey not in rowdata.keys()):
                    print("WARN: Mismatch in number of VLANs to be configured and VLAN config provided. Some configuration will be missing!!!")

                vlanconf = {
                    "vlan_id": rowdata[vlankey],
                    "name": rowdata[namekey],
                    "ip_prefix": rowdata[ipprefixkey],
                    "used_for": rowdata[usedforkey],
                    "scope": rowdata[scopekey]
                }

                vlanlist.append(vlanconf)
                configuredvlans += 1

        VLAN_CONFIG = vlanlist

    return

##############################################################################
# Set Global dicts & variables
##############################################################################
DC_AS_NUM="65101"
BRANCH_AS_NUM="65111"
NWSTACKID = None
QOSSTACKID = None
NATSTACKID = None
NGFWSTACKID = None
NGFWPOLICYSETID = None
PERFSTACKID = None
SERVICEBINDINGID = None
NATZONEINTERNETID = None
GLOBALVRFID = None
wannwpub_name_id = {}
wannwpri_name_id = {}
label_name_id = {}
site_id_name = {}
site_name_id = {}
zone_name_id = {}
secset_name_id = {}
secstack_name_id = {}
servicebinding_name_id = {}

ION_MODEL_MAPPING = {
    "1200": "ion 1200",
    "1200S": "ion 1200-s",
    "3200": "ion 3200",
    "5200": "ion 5200",
    "3102v": "ion 3102v",
    "3104v": "ion 3104v",
    "3108v": "ion 3108v",
    "7108v": "ion 7108v"
}
ION_SOFTWARE_VERSION = "6.1.9-b2"
##############################################################################
# SVI Template
##############################################################################
SVI_TEMPLATE ={
    "name": "SVI_Name",
    "description": None,
    "type": "vlan",
    "attached_lan_networks": None,
    "site_wan_interface_ids": None,
    "mac_address": None,
    "mtu": 1500,
    "ipv4_config": {
        "dhcp_config": None,
        "type": "dhcp",
        "routes": None,
        "dns_v4_config": None,
        "static_config": None
    },
    "ipv6_config": None,
    "dhcp_relay": None,
    "ethernet_port": {
        "full_duplex": False,
        "speed": 0
    },
    "admin_up": True,
    "nat_address": None,
    "nat_port": 0,
    "nat_address_v6": None,
    "nat_port_v6": 0,
    "used_for": "lan",
    "bound_interfaces": None,
    "sub_interface": None,
    "pppoe_config": None,
    "parent": None,
    "network_context_id": None,
    "bypass_pair": None,
    "peer_bypasspair_wan_port_type": "none",
    "service_link_config": None,
    "scope": "global",
    "tags": None,
    "nat_zone_id": None,
    "devicemgmt_policysetstack_id": None,
    "nat_pools": None,
    "directed_broadcast": False,
    "ipfixcollectorcontext_id": None,
    "ipfixfiltercontext_id": None,
    "secondary_ip_configs": None,
    "static_arp_configs": None,
    "cellular_config": None,
    "multicast_config": None,
    "poe_enabled": False,
    "power_usage_threshold": 0,
    "lldp_enabled": False,
    "switch_port_config": None,
    "authentication_config": None,
    "vlan_config": {
        "voice_enabled": False,
        "vlan_id": 510,
        "mstp_instance": 0,
        "auto_op_state": False
    },
    "interface_profile_id": None,
    "vrf_context_id": "global_vrf_id"
}

SUBINTERFACE_TEMPLATE = {
    "parent": "parent_interface_id",
    "type": "subinterface",
    "used_for": "lan",
    "power_usage_threshold": 0,
    "mtu": 0,
    "name": "",
    "description": "",
    "attached_lan_networks": None,
    "site_wan_interface_ids": None,
    "mac_address": None,
    "ipv4_config": {
        "dhcp_config": None,
        "type": "dhcp",
        "routes": None,
        "dns_v4_config": None,
        "static_config": None
    },
    "ipv6_config": None,
    "dhcp_relay": None,
    "ethernet_port": {
        "full_duplex": False,
        "speed": 0
    },
    "admin_up": True,
    "nat_address": None,
    "nat_port": None,
    "nat_address_v6": None,
    "nat_port_v6": 0,
    "bound_interfaces": None,
    "sub_interface": {
        "vlan_id": "vlan_id",
        "native_vlan": None
    },
    "pppoe_config": None,
    "network_context_id": None,
    "bypass_pair": None,
    "peer_bypasspair_wan_port_type": "none",
    "service_link_config": None,
    "scope": "local",
    "tags": None,
    "nat_zone_id": None,
    "devicemgmt_policysetstack_id": None,
    "nat_pools": None,
    "directed_broadcast": False,
    "ipfixcollectorcontext_id": None,
    "ipfixfiltercontext_id": None,
    "secondary_ip_configs": None,
    "static_arp_configs": None,
    "cellular_config": None,
    "multicast_config": None,
    "poe_enabled": False,
    "lldp_enabled": None,
    "switch_port_config": None,
    "authentication_config": None,
    "vlan_config": None,
    "interface_profile_id": None,
    "vrf_context_id": "global_vrf_id"
}

SITE_TEMPLATE = {
        "name": "sitename",
        "description": "Auto-created site for Simplified PoV",
        "address": {
            "street": None,
            "state": None,
            "post_code": None,
            "country": "United States",
            "city": "New York",
            "street2": None
        },
        "location": {
            "latitude": 0,
            "longitude": 0,
            "description": None
        },
        "service_binding": "servicebinding_id",
        "network_policysetstack_id": "stack_id",
        "perfmgmt_policysetstack_id": "stack_id",
        "priority_policysetstack_id": "stack_id",
        "security_policysetstack_id": "stack_id",
        "nat_policysetstack_id": "stack_id",
        "tags": [],
        "element_cluster_role": "SPOKE",
        "admin_state": "active",
        "policy_set_id": None,
        "security_policyset_id": None,
        "extended_tags": None,
        "multicast_peer_group_id": None
}

SWI_TEMPLATE = {
        "name": "circuit_name",
        "description": None,
        "tags": None,
        "type": "publicwan",
        "network_id": "network_id",
        "link_bw_down": 50,
        "link_bw_up": 50,
        "bw_config_mode": "manual",
        "label_id": "label_id",
        "bfd_mode": "aggressive",
        "lqm_enabled": True,
        "use_lqm_for_non_hub_paths": None,
        "bwc_enabled": True,
        "cost": 128,
        "lqm_config": {
            "inter_packet_gap": 100,
            "use_hub_sites": True,
            "use_prisma_access_service_endpoints": False,
            "hub_site_ids": None,
            "statistic": "min"
        },
        "vpnlink_configuration": None,
        "use_for_controller_connections": None,
        "use_for_application_reachability_probes": None,
        "probe_profile_id": None,
        "l3_reachability": None
}

BYPASSPAIR_TEMPLATE = {
        "tags": None,
        "attached_lan_networks": None,
        "site_wan_interface_ids": None,
        "mtu": 1500,
        "ethernet_port": {
            "full_duplex": False,
            "speed": 0
        },
        "nat_address": None,
        "nat_port": 0,
        "nat_zone_id": None,
        "nat_address_v6": None,
        "nat_port_v6": 0,
        "nat_pools": None,
        "mac_address": None,
        "ipv4_config": None,
        "ipv6_config": None,
        "dhcp_relay": None,
        "sub_interface": None,
        "pppoe_config": None,
        "secondary_ip_configs": None,
        "static_arp_configs": None,
        "used_for": "none",
        "peer_bypasspair_wan_port_type": "none",
        "network_context_id": None,
        "ipfixcollectorcontext_id": None,
        "ipfixfiltercontext_id": None,
        "devicemgmt_policysetstack_id": None,
        "directed_broadcast": False,
        "service_link_config": None,
        "cellular_config": None,
        "multicast_config": {
            "multicast_enabled": False,
            "igmp_version": "IGMPV3",
            "dr_priority": 1,
            "igmp_static_joins": None
        },
        "switch_port_config": None,
        "authentication_config": None,
        "vlan_config": None,
        "poe_enabled": False,
        "lldp_enabled": False,
        "power_usage_threshold": 0,
        "interface_profile_id": None,
        "vrf_context_id": None,
        "name": None,
        "description": None,
        "bound_interfaces": None,
        "parent": None,
        "scope": "local",
        "type": "bypasspair",
        "admin_up": True,
        "bypass_pair": {
            "lan": "lan_id",
            "wan": "wan_id",
            "use_relay": True,
            "lan_state_propagation": False
        }
}

IPV4_TEMPLATE_STATIC = {
  "dhcp_config": None,
  "dns_v4_config": {
    "name_servers": ["8.8.8.8", "8.8.4.4"]
  },
  "routes": [
    {
      "destination": "0.0.0.0/0",
      "via": "gw"
    }
  ],
  "static_config": {
    "address": "ip_prefix"
  },
  "type": "static"
}

IPV4_TEMPLATE_DHCP = {"dhcp_config":None,"dns_v4_config":None,"routes":None,"static_config":None,"type":"dhcp"}


def create_dicts(sase_session):
    global NWSTACKID
    global QOSSTACKID
    global NATSTACKID
    global NGFWSTACKID
    global NGFWPOLICYSETID
    global PERFSTACKID
    global SERVICEBINDINGID
    global GLOBALVRFID
    global wannwpub_name_id
    global wannwpri_name_id
    global label_name_id
    global NATZONEINTERNETID
    global site_id_name
    global site_name_id
    global zone_name_id
    global secset_name_id
    global secstack_name_id
    global servicebinding_name_id


    print("Building Translation Dicts..")
    #
    # VRF Context
    #
    print("\tVRF Context")
    resp = sase_session.get.vrfcontexts()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            if item["name"]=="Global":
                GLOBALVRFID=item["id"]
    else:
        print("ERR: Could not retrieve Network Policy Set Stacks")
        prisma_sase.jd_detailed(resp)
    #
    # Sites
    #
    print("\tSites")
    resp = sase_session.get.sites()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            site_id_name[item["id"]] = item["name"]
            site_name_id[item["name"]] = item["id"]
    else:
        print("ERR: Could not retrieve Network Policy Set Stacks")
        prisma_sase.jd_detailed(resp)
    #
    # NAT Zones
    #
    print("\tNAT Zones")
    resp = sase_session.get.natzones()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            if item["name"] == "internet":
                NATZONEINTERNETID = item["id"]
    else:
        print("ERR: Could not retrieve Network Policy Set Stacks")
        prisma_sase.jd_detailed(resp)

    #
    # Network Stack
    #
    print("\tNetwork Stack")
    resp = sase_session.get.networkpolicysetstacks()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            if item["default_policysetstack"]:
                NWSTACKID=item["id"]

                if CUSTOMER_NAME not in item["name"]:
                    #newname = "{}{}".format(CUSTOMER_NAME, item["name"])
                    newname = "{} Default Path Stack (Simple)".format(CUSTOMER_NAME)

                    item["name"] = newname
                    resp = sase_session.put.networkpolicysetstacks(networkpolicysetstack_id=item["id"], data=item)
                    if resp.cgx_status:
                        print("\t\tDefault Network Stack updated to {}".format(item["name"]))
                    else:
                        print("ERR: Could not update Default Network Stack Name")
                        prisma_sase.jd_detailed(resp)

    else:
        print("ERR: Could not retrieve Network Policy Set Stacks")
        prisma_sase.jd_detailed(resp)

    #
    # Network Sets
    #
    print("\tNetwork Sets")
    resp = sase_session.get.networkpolicysets()
    if resp.cgx_status:
        policysets = resp.cgx_content.get("items", None)
        for ps in policysets:
            if CUSTOMER_NAME not in ps["name"]:
                if ps["defaultrule_policyset"]:
                    newname = "{} Default Path Set (Simple)".format(CUSTOMER_NAME)
                else:
                    newname = "{} Path Set (Simple)".format(CUSTOMER_NAME)

                ps["name"]=newname
                resp = sase_session.put.networkpolicysets(networkpolicyset_id=ps["id"], data=ps)
                if resp.cgx_status:
                    print("\t\tPath Policy Set Name updated to {}".format(ps["name"]))
                else:
                    print("ERR: Could not edit Path Policy Set Name")
                    prisma_sase.jd_detailed(resp)
    else:
        print("ERR: Could not retrieve Path Policy Sets")
        prisma_sase.jd_detailed(resp)

    #
    # QoS Stack
    #
    print("\tQoS Stack")
    resp = sase_session.get.prioritypolicysetstacks()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            if item["default_policysetstack"]:
                QOSSTACKID=item["id"]

                if CUSTOMER_NAME not in item["name"]:
                    #newname = "{}{}".format(CUSTOMER_NAME, item["name"])
                    newname = "{} Default QoS Stack (Simple)".format(CUSTOMER_NAME)

                    item["name"] = newname
                    resp = sase_session.put.prioritypolicysetstacks(prioritypolicysetstack_id=item["id"], data=item)
                    if resp.cgx_status:
                        print("\t\tDefault QoS Stack updated to {}".format(item["name"]))
                    else:
                        print("ERR: Could not update Default QoS Stack Name")
                        prisma_sase.jd_detailed(resp)
    else:
        print("ERR: Could not retrieve Priority Policy Set Stacks")
        prisma_sase.jd_detailed(resp)

    #
    # QoS Sets
    #
    print("\tQoS Set")
    resp = sase_session.get.prioritypolicysets()
    if resp.cgx_status:
        policysets = resp.cgx_content.get("items", None)
        for ps in policysets:
            if CUSTOMER_NAME not in ps["name"]:
                if ps["defaultrule_policyset"]:
                    newname = "{} Default QoS Set (Simple)".format(CUSTOMER_NAME)
                else:
                    newname = "{} QoS Set (Simple)".format(CUSTOMER_NAME)

                ps["name"] = newname
                resp = sase_session.put.prioritypolicysets(prioritypolicyset_id=ps["id"], data=ps)
                if resp.cgx_status:
                    print("\t\tQoS Policy Set Name updated to {}".format(ps["name"]))
                else:
                    print("ERR: Could not edit QoS Policy Set Name")
                    prisma_sase.jd_detailed(resp)
    else:
        print("ERR: Could not retrieve QoS Policy Sets")
        prisma_sase.jd_detailed(resp)

    #
    # NAT Stack
    #
    print("\tNAT Stack")
    resp = sase_session.get.natpolicysetstacks()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            if item["default_policysetstack"]:
                NATSTACKID=item["id"]

                if CUSTOMER_NAME not in item["name"]:
                    #newname = "{}{}".format(CUSTOMER_NAME, item["name"])
                    newname = "{} Default NAT Stack (Simple)".format(CUSTOMER_NAME)

                    item["name"] = newname
                    resp = sase_session.put.natpolicysetstacks(natpolicysetstack_id=item["id"], data=item)
                    if resp.cgx_status:
                        print("\t\tDefault NAT Stack updated to {}".format(item["name"]))
                    else:
                        print("ERR: Could not update Default NAT Stack Name")
                        prisma_sase.jd_detailed(resp)

    else:
        print("ERR: Could not retrieve NAT Policy Set Stacks")
        prisma_sase.jd_detailed(resp)


    #
    # NAT Sets
    #
    print("\tNAT Set")
    resp = sase_session.get.natpolicysets()
    if resp.cgx_status:
        policysets = resp.cgx_content.get("items", None)
        for ps in policysets:
            if CUSTOMER_NAME not in ps["name"]:
                newname = "{} NAT Set (Simple)".format(CUSTOMER_NAME)
                ps["name"] = newname
                resp = sase_session.put.natpolicysets(natpolicyset_id=ps["id"], data=ps)
                if resp.cgx_status:
                    print("\t\tNAT Policy Set Name updated to {}".format(ps["name"]))
                else:
                    print("ERR: Could not edit NAT Policy Set Name")
                    prisma_sase.jd_detailed(resp)
    else:
        print("ERR: Could not retrieve NAT Policy Sets")
        prisma_sase.jd_detailed(resp)

    #
    # Performance Stack
    #
    print("\tPerformance Stack")
    resp = sase_session.get.perfmgmtpolicysetstacks()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            if item["default_policysetstack"]:
                PERFSTACKID=item["id"]

                # newname = "{}{}".format(CUSTOMER_NAME, item["name"])
                # item["name"] = newname
                # resp = sase_session.put.perfmgmtpolicysetstacks(perfmgmtpolicysetstack_id=item["id"], data=item)
                # if resp.cgx_status:
                #     print("\t\tDefault Performance Policy Stack updated to {}".format(item["name"]))
                # else:
                #     print("ERR: Could not update Default Performance Policy Stack Name")
                #     prisma_sase.jd_detailed(resp)

    else:
        print("ERR: Could not retrieve Performance Policy Set Stacks")
        prisma_sase.jd_detailed(resp)

    #
    # Security Stack
    #
    print("\tSecurity Sets")
    # resp = sase_session.get.ngfwsecuritypolicysetstacks()
    # if resp.cgx_status:
    #     itemlist = resp.cgx_content.get("items", None)
    #     for item in itemlist:
    #         if "Default" in item["name"]:
    #             NGFWSTACKID=item["id"]
    # else:
    #     print("ERR: Could not retrieve NGFW Policy Set Stacks")
    #     prisma_sase.jd_detailed(resp)

    resp = sase_session.get.ngfwsecuritypolicysets()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            secset_name_id[item["name"]] = item["id"]
    else:
        print("ERR: Could not retrieve NGFW Security Policy Sets")
        prisma_sase.jd_detailed(resp)

    defpol_id = None
    if "Branch Simple Security Policy Stack Default Rule Policy Set (Simple)" in secset_name_id.keys():
        print("\t\tBranch Simple Security Policy Stack Default Rule Policy Set (Simple) already created")
        defpol_id = secset_name_id["Branch Simple Security Policy Stack Default Rule Policy Set (Simple)"]

    else:
        data = {
            "name": "Branch Simple Security Policy Stack Default Rule Policy Set (Simple)",
            "description": None,
            "tags": None,
            "defaultrule_policyset": True,
            "policyrule_order": [],
            "clone_from": None
        }
        resp = sase_session.post.ngfwsecuritypolicysets(data=data)
        if resp.cgx_status:
            print("\t\tBranch Simple Security Policy Stack Default Rule Policy Set (Simple) policy set created")
            defpol_id = resp.cgx_content.get("id")
        else:
            print("ERR: Could not create Branch Simple Security Policy Stack Default Rule Policy Set (Simple)")
            prisma_sase.jd_detailed(resp)

    if "Branch Simple Security Policy Stack Policy Set (Simple)" in secset_name_id.keys():
        print("\tBranch Simple Security Policy Stack Policy Set (Simple) already created")
        NGFWPOLICYSETID = secset_name_id["Branch Simple Security Policy Stack Policy Set (Simple)"]

    else:
        data = {
            "name": "Branch Simple Security Policy Stack Policy Set (Simple)",
            "description": None,
            "tags": None,
            "defaultrule_policyset": False,
            "policyrule_order": [],
            "clone_from": None
        }

        resp = sase_session.post.ngfwsecuritypolicysets(data=data)
        if resp.cgx_status:
            print("\tBranch Simple Security Policy Stack Policy Set (Simple) policy set created")
            NGFWPOLICYSETID = resp.cgx_content.get("id")
        else:
            print("ERR: Could not create Branch Simple Security Policy Stack Policy Set (Simple)")
            prisma_sase.jd_detailed(resp)

    if defpol_id is None or NGFWPOLICYSETID is None:
        print("ERR: Policy ID not found")
        print(secset_name_id)
        sys.exit()

    print("\tSecurity Stack")
    resp = sase_session.get.ngfwsecuritypolicysetstacks()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            secstack_name_id[item["name"]] = item["id"]
    else:
        print("ERR: Could not retrieve Security Stack")
        prisma_sase.jd_detailed(resp)

    newname = "{} Security Stack (Simple)".format(CUSTOMER_NAME)
    if "Branch Simple Security Policy Stack (Simple)" in secstack_name_id.keys():
        print("\tBranch Simple Security Policy Stack (Simple) already exists")
        NGFWSTACKID=secstack_name_id["Branch Simple Security Policy Stack (Simple)"]

        resp = sase_session.get.ngfwsecuritypolicysetstacks(ngfwsecuritypolicysetstack_id=NGFWSTACKID)
        if resp.cgx_status:
            item = resp.cgx_content
            item["name"] = newname
            resp = sase_session.put.ngfwsecuritypolicysetstacks(ngfwsecuritypolicysetstack_id=item["id"], data=item)
            if resp.cgx_status:
                print("\t\tDefault Security Stack updated to {}".format(item["name"]))
                secstack_name_id[newname] = item["id"]
            else:
                print("ERR: Could not update Default Security Stack Name")
                prisma_sase.jd_detailed(resp)

    elif newname in secstack_name_id.keys():
        NGFWSTACKID = secstack_name_id[newname]

    elif "Security Stack (Simple)" in secstack_name_id.keys():
        NGFWSTACKID = secstack_name_id["Security Stack (Simple)"]
        resp = sase_session.get.ngfwsecuritypolicysetstacks(ngfwsecuritypolicysetstack_id=NGFWSTACKID)
        if resp.cgx_status:
            item = resp.cgx_content
            item["name"] = newname
            resp = sase_session.put.ngfwsecuritypolicysetstacks(ngfwsecuritypolicysetstack_id=item["id"], data=item)
            if resp.cgx_status:
                print("\t\tDefault Security Stack updated to {}".format(item["name"]))
                secstack_name_id[newname] = item["id"]
            else:
                print("ERR: Could not update Default Security Stack Name")
                prisma_sase.jd_detailed(resp)

    else:
        #name = "{}Branch Simple Security Policy Stack (Simple)".format(CUSTOMER_NAME)
        name = "{} Security Stack (Simple)".format(CUSTOMER_NAME)
        data = {
            "name": newname,
            "description": None,
            "tags": None,
            "policyset_ids": [NGFWPOLICYSETID],
            "defaultrule_policyset_id": defpol_id
        }
        resp = sase_session.post.ngfwsecuritypolicysetstacks(data=data)
        if resp.cgx_status:
            print("\tBranch Simple Security Policy Stack (Simple) created")
            NGFWSTACKID = resp.cgx_content.get("id")
        else:
            print("ERR: Could not create Branch Simple Security Policy Stack (Simple) created")
            prisma_sase.jd_detailed(resp)

    #
    # Service Binding
    #
    print("\tService Binding")
    resp = sase_session.get.servicebindingmaps()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            servicebinding_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve Servicebinding map")
        prisma_sase.jd_detailed(resp)

    if BRANCH_DOMAIN in servicebinding_name_id.keys():
        SERVICEBINDINGID = servicebinding_name_id[BRANCH_DOMAIN]
    else:
        servicebindingmap_data = {
            "name": BRANCH_DOMAIN,
            "description": None,
            "is_default": False,
            "service_bindings": [],
            "tags": None
        }
        resp = sase_session.post.servicebindingmaps(data=servicebindingmap_data)
        if resp.cgx_status:
            print("\t{} Domain created".format(BRANCH_DOMAIN))
            SERVICEBINDINGID = resp.cgx_content.get("id", None)
            servicebinding_name_id[servicebindingmap_data["name"]] = SERVICEBINDINGID

        else:
            print("ERR: Could not create {}".format(BRANCH_DOMAIN))
            prisma_sase.jd_detailed(resp)


    #
    # WAN Networks
    #
    print("\tWAN Networks")
    resp = sase_session.get.wannetworks()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            if item["type"] == "publicwan":
                wannwpub_name_id[item["name"]] = item["id"]
            else:
                wannwpri_name_id[item["name"]] = item["id"]
    else:
        print("ERR: Could not retrieve WAN Networks")
        prisma_sase.jd_detailed(resp)

    #
    # WAN Interface Labels
    #
    print("\tWAN Interface Labels")
    resp = sase_session.get.waninterfacelabels()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            label_name_id[item["name"]] = item["id"]
    else:
        print("ERR: Could not retrieve WAN Interface Labels")
        prisma_sase.jd_detailed(resp)

    return


def config_interfaces(sase_session, interface_mapping, interface_ipconfig, usedfor_mapping, vlan_ids, site_id, element_id, ion_model):
    interfaces = []
    interface_id_name={}
    interface_name_id = {}
    resp = sase_session.get.elementshells_interfaces(site_id=site_id,
                                                     elementshell_id=element_id)
    if resp.cgx_status:
        interfaces = resp.cgx_content.get("items", None)
        for intf in interfaces:
            interface_id_name[intf["id"]] = intf["name"]
            interface_name_id[intf["name"]] = intf["id"]
    else:
        print("ERR: Could not retrieve interfaces")
        prisma_sase.jd_detailed(resp)

    #######################################################################
    # Look for Bypass pair in interface_mapping
    # Create Bypass pair, if present
    #######################################################################
    for intfkey in interface_mapping.keys():
        if "bypass_" in intfkey:
            child_interfaces = intfkey.replace("bypass_", "")

            bp_child = {}
            for intf in interfaces:
                if intf["name"] in [child_interfaces[0], child_interfaces[1]]:
                    bp_child[intf["name"]] = intf["id"]
                    intf["admin_up"] = True
                    resp = sase_session.put.elementshells_interfaces(site_id=site_id,
                                                                     elementshell_id=element_id,
                                                                     interface_id=intf["id"],
                                                                     data=intf)
                    if resp.cgx_status:
                        print("\t\tInterface {} set to admin up".format(intf["name"]))
                    else:
                        print("ERR: Could not set interface {} admin up".format(intf["name"]))
                        prisma_sase.jd_detailed(resp)

            bypasspair_data = copy.deepcopy(BYPASSPAIR_TEMPLATE)
            if "v" in ion_model:
                bypasspair_data["bypass_pair"] = {
                    "lan": bp_child[child_interfaces[1]],
                    "wan": bp_child[child_interfaces[0]],
                    "use_relay": False,
                    "lan_state_propagation": False
                }
            else:
                bypasspair_data["bypass_pair"] = {
                    "lan": bp_child[child_interfaces[1]],
                    "wan": bp_child[child_interfaces[0]],
                    "use_relay": True,
                    "lan_state_propagation": False
                }
            resp = sase_session.post.elementshells_interfaces(site_id=site_id,
                                                              elementshell_id=element_id,
                                                              data=bypasspair_data)
            if resp.cgx_status:
                print("\t\tBypasspair {} created".format(child_interfaces))
                interfaces.append(resp.cgx_content)
            else:
                print("ERR: Could not create bypasspair {}".format(child_interfaces))
                prisma_sase.jd_detailed(resp)

    #######################################################################
    # Check for ION model and create subinterface or SVI
    #######################################################################
    vlan_config = interface_ipconfig[LAN_INTERFACE]
    #######################################################################
    # Admin up Controller Interface
    #######################################################################
    if ion_model in ["3102v", "3104v", "3108v", "7108v"]:
        for intf in interfaces:
            if "controller" in intf["name"]:
                intf["admin_up"] = True
                intf["ipv4_config"] = IPV4_TEMPLATE_DHCP

                resp = sase_session.put.elementshells_interfaces(site_id=site_id,
                                                                 elementshell_id=element_id,
                                                                 interface_id=intf["id"],
                                                                 data=intf)
                if resp.cgx_status:
                    print("\t\tController configured with DHCP & Admin up")
                else:
                    print("ERR: Could not update controller port")
                    prisma_sase.jd_detailed(resp)

    #######################################################################
    # Create Subinterface
    #######################################################################
    if ion_model in ["1200", "3200", "5200", "9200", "3102v", "3104v", "3108v", "7108v"]:
        #######################################################################
        # Get LAN Interface ID, set admin up
        #######################################################################
        laninterface_id = interface_name_id[LAN_INTERFACE]
        resp = sase_session.get.elementshells_interfaces(site_id=site_id,
                                                         elementshell_id=element_id,
                                                         interface_id=laninterface_id)
        if resp.cgx_status:
            intf = resp.cgx_content
            intf["admin_up"] = True
            if LAN_SCOPE is not None:
                intf["scope"] = LAN_SCOPE

            if len(vlan_config) == 0:
                intf["used_for"] = "lan"
                if LAN_IP_PREFIX == "dhcp":
                    intf["ipv4_config"] = IPV4_TEMPLATE_DHCP
                elif LAN_IP_PREFIX is None:
                    intf["ipv4_config"] = IPV4_TEMPLATE_DHCP
                else:
                    intf["ipv4_config"]={
                        "dhcp_config": None,
                        "dns_v4_config": None,
                        "routes": None,
                        "static_config": {"address": LAN_IP_PREFIX},
                        "type": "static"
                    }

            resp = sase_session.put.elementshells_interfaces(site_id=site_id,
                                                             elementshell_id=element_id,
                                                             interface_id=laninterface_id,
                                                             data=intf)
            if resp.cgx_status:
                print("\t\t{} set to admin up".format(intf["name"]))
            else:
                print("ERR: Could not set interface {} to admin up".format(intf["name"]))
                prisma_sase.jd_detailed(resp)
        else:
            print("ERR: Could not get LAN interface")
            prisma_sase.jd_detailed(resp)

        #######################################################################
        # Create Subinterfaces on LAN Interface
        #######################################################################
        for item in vlan_config:
            vlanid = item["vlan_id"]
            vlanname = item["name"]
            subinterface_data = copy.deepcopy(SUBINTERFACE_TEMPLATE)
            subinterface_data["scope"] = item["scope"]
            subinterface_data["used_for"] = item["used_for"]
            subinterface_data["parent"] = laninterface_id
            subinterface_data["description"] = vlanname
            subinterface_data["sub_interface"] = {
                "vlan_id": item["vlan_id"],
                "native_vlan": None
            }
            if item["ip_prefix"] != "dhcp":
                config = {
                    "dhcp_config": None,
                    "dns_v4_config": None,
                    "routes": None,
                    "static_config": {"address": item["ip_prefix"]},
                    "type": "static"
                }
                subinterface_data["ipv4_config"]=config

            subinterface_data["vrf_context_id"] = GLOBALVRFID
            resp = sase_session.post.elementshells_interfaces(site_id=site_id,
                                                              elementshell_id=element_id,
                                                              data=subinterface_data)
            if resp.cgx_status:
                print("\t\tSubinterface {}[{}] created".format(vlanname, vlanid))
            else:
                print("ERR: Could not create Subinterface {}[{}] on ION 1".format(vlanname, vlanid))
                prisma_sase.jd_detailed(resp)
                sys.exit()

    else:
        #######################################################################
        # Create SVIs
        #######################################################################
        for item in vlan_config:
            vlanname = item["name"]
            vlanid = item["vlan_id"]

            svi_data = copy.deepcopy(SVI_TEMPLATE)
            svi_data["name"] = vlanname
            svi_data["description"] = vlanname
            svi_data["admin_up"] = True
            svi_data["vrf_context_id"] = GLOBALVRFID
            svi_data["vlan_config"] = {
                "voice_enabled": False,
                "vlan_id": vlanid,
                "mstp_instance": 0,
                "auto_op_state": False
            }
            svi_data["scope"] = item["scope"]
            svi_data["used_for"] = item["used_for"]
            if item["ip_prefix"] != "dhcp":
                config = {
                    "dhcp_config": None,
                    "dns_v4_config": None,
                    "routes": None,
                    "static_config": {"address": item["ip_prefix"]},
                    "type": "static"
                }
                svi_data["ipv4_config"]=config

            resp = sase_session.post.elementshells_interfaces(site_id=site_id,
                                                              elementshell_id=element_id,
                                                              data=svi_data)
            if resp.cgx_status:
                print("\t\tSVI {}[{}] created".format(vlanname, vlanid))
            else:
                print("ERR: Could not create SVI {}[{}] on ION 1".format(vlanname, vlanid))
                prisma_sase.jd_detailed(resp)
                sys.exit()

        for intf in interfaces:
            if intf["name"] == LAN_INTERFACE:
                intf["scope"] = LAN_SCOPE
                intf["admin_up"] = True
                intf["switch_port_config"] = {
                    "vlan_mode": "trunk",
                    "voice_vlan_id": None,
                    "native_vlan_id": None,
                    "access_vlan_id": None,
                    "trunk_vlans": vlan_ids,
                    "stp_port_enabled": True,
                    "stp_port_priority": 128,
                    "stp_port_cost": 4,
                    "bpdu_guard_enabled": False,
                    "root_guard_enabled": False,
                    "forward_fast_enabled": True,
                    "storm_control_config": {
                        "unicast_threshold": None,
                        "multicast_threshold": None,
                        "broadcast_threshold": 1000
                    }
                }
                resp = sase_session.put.elementshells_interfaces(site_id=site_id,
                                                                 elementshell_id=element_id,
                                                                 interface_id=intf["id"],
                                                                 data=intf)
                if resp.cgx_status:
                    print("\t\tInterface {} updated with VLANs {}".format(intf["name"], vlan_ids))
                else:
                    print("ERR: Could not update interface {}".format(intf["name"]))
                    prisma_sase.jd_detailed(resp)
                    sys.exit()

    #
    # Update WAN Interfaces
    #
    for intf in interfaces:
        if intf["name"] in interface_mapping.keys():
            intf["used_for"] = usedfor_mapping[intf["name"]]
            if intf["used_for"] == "public":
                intf["nat_zone_id"] = NATZONEINTERNETID

            intf["site_wan_interface_ids"] = [interface_mapping[intf["name"]]]
            intf["admin_up"] = True
            intf["ipv4_config"] = interface_ipconfig[intf["name"]]
            resp = sase_session.put.elementshells_interfaces(site_id=site_id,
                                                             elementshell_id=element_id,
                                                             interface_id=intf["id"],
                                                             data=intf)
            if resp.cgx_status:
                print("\t\tInterface {} updated".format(intf["name"]))
            else:
                print("ERR: Could not update interface {}".format(intf["name"]))
                prisma_sase.jd_detailed(resp)
                sys.exit()

    return


def get_ha_interface_id(sase_session, site_id, elemshell_id):
    ha_intf_id=None
    resp = sase_session.get.elementshells_interfaces(site_id=site_id, elementshell_id=elemshell_id)
    if resp.cgx_status:
        interfaces = resp.cgx_content.get("items", None)
        for intf in interfaces:
            if intf["used_for"] == "ha":
                ha_intf_id = intf["id"]

    else:
        print("ERR: Could not retrieve element shell interfaces")
        prisma_sase.jd_detailed(resp)

    return ha_intf_id


def update_bgpconfigs(sase_session, site_id, element_id, as_num):
    ##############################################################################
    # Set Global BGP Config
    ##############################################################################
    resp = sase_session.get.bgpconfigs(site_id, element_id)
    if resp.cgx_status:
        bgpconfigs = resp.cgx_content.get("items", None)
        for bgpconf in bgpconfigs:
            bgpconf['local_as_num'] = as_num
            resp = sase_session.put.bgpconfigs(site_id=site_id,
                                               element_id=element_id,
                                               bgpconfig_id=bgpconf["id"],
                                               data=bgpconf)
            if resp.cgx_status:
                print("\tUpdated AS# to {}".format(as_num))
            else:
                print("ERR: Could not update AS#")
                prisma_sase.jd_detailed(resp)

    else:
        print("ERR: Could not get BGP Configs")
        prisma_sase.jd_detailed(resp)

    return


def create_bgp_peer(sase_session, site_id, element_id):
    ##############################################################################
    # Set Global BGP Config
    # Use AS_NUM 65101 for DC
    ##############################################################################
    update_bgpconfigs(sase_session=sase_session, site_id=site_id, element_id=element_id, as_num=DC_AS_NUM)
    ##############################################################################
    # Edge Peer
    ##############################################################################
    edge_data = {
        "name": "Edge-Peer",
        "description": None,
        "tags": None,
        "peer_ip": "198.19.0.1",
        "peer_ip_v6": None,
        "allow_v4_prefixes": True,
        "allow_v6_prefixes": False,
        "remote_as_num": "65200",
        "peer_type": "edge",
        "route_map_in_id": None,
        "route_map_out_id": None,
        "update_source": None,
        "update_source_v6": None,
        "scope": "local",
        "shutdown": False,
        "bgp_config": None,
        "vrf_context_id": GLOBALVRFID,
        "router_id": None,
        "advertise_default_route": False
    }
    resp = sase_session.post.bgppeers(site_id=site_id, element_id=element_id, data=edge_data)
    if resp.cgx_status:
        print("\t\tEdge Peer created")
    else:
        print("ERR: Could not create Edge Peer")
        prisma_sase.jd_detailed(resp)

    ##############################################################################
    # Core Peer
    ##############################################################################
    core_data = {
        "name": "Core-Peer",
        "description": None,
        "tags": None,
        "peer_ip": "192.168.102.1",
        "peer_ip_v6": None,
        "allow_v4_prefixes": True,
        "allow_v6_prefixes": False,
        "remote_as_num": "65100",
        "peer_type": "core",
        "route_map_in_id": None,
        "route_map_out_id": None,
        "update_source": None,
        "update_source_v6": None,
        "scope": "local",
        "shutdown": False,
        "bgp_config": None,
        "vrf_context_id": GLOBALVRFID,
        "router_id": None,
        "advertise_default_route": False
    }
    resp = sase_session.post.bgppeers(site_id=site_id, element_id=element_id, data=core_data)
    if resp.cgx_status:
        print("\t\tCore Peer created")
    else:
        print("ERR: Could not create Core Peer")
        prisma_sase.jd_detailed(resp)

    return


def create_bgp_peer_branch(sase_session, site_id, element_id):
    ##############################################################################
    # Set Global BGP Config
    # Use AS_NUM 65111 for Branch
    ##############################################################################
    update_bgpconfigs(sase_session=sase_session, site_id=site_id, element_id=element_id, as_num=BRANCH_AS_NUM)
    ##############################################################################
    # WAN-Rtr Peer
    ##############################################################################
    wanrtr_data = {
        "name": "WAN-Rtr",
        "description": None,
        "tags": None,
        "peer_ip": "198.19.100.1",
        "peer_ip_v6": None,
        "allow_v4_prefixes": True,
        "allow_v6_prefixes": False,
        "remote_as_num": "65200",
        "peer_type": "classic",
        "route_map_in_id": None,
        "route_map_out_id": None,
        "update_source": None,
        "update_source_v6": None,
        "scope": "local",
        "shutdown": False,
        "bgp_config": None,
        "vrf_context_id": GLOBALVRFID,
        "router_id": None,
        "advertise_default_route": False
    }
    resp = sase_session.post.bgppeers(site_id=site_id, element_id=element_id, data=wanrtr_data)
    if resp.cgx_status:
        print("\t\tWAN-Rtr created")
    else:
        print("ERR: Could not create WAN-Rtr")
        prisma_sase.jd_detailed(resp)

    ##############################################################################
    # LAN-Rtr Peer
    ##############################################################################
    lanrtr_data = {
        "name": "LAN-Rtr",
        "description": None,
        "tags": None,
        "peer_ip": "192.168.11.10",
        "peer_ip_v6": None,
        "allow_v4_prefixes": True,
        "allow_v6_prefixes": False,
        "remote_as_num": "65110",
        "peer_type": "classic",
        "route_map_in_id": None,
        "route_map_out_id": None,
        "update_source": None,
        "update_source_v6": None,
        "scope": "global",
        "shutdown": False,
        "bgp_config": None,
        "vrf_context_id": GLOBALVRFID,
        "router_id": None,
        "advertise_default_route": False
    }
    resp = sase_session.post.bgppeers(site_id=site_id, element_id=element_id, data=lanrtr_data)
    if resp.cgx_status:
        print("\t\tLAN-Rtr created")
    else:
        print("ERR: Could not create LAN-Rtr")
        prisma_sase.jd_detailed(resp)

    return


def configure_byos(sase_session, dc_site_id, dc_type):

    #
    # Create public & private SWI
    # Create two shells for 3104
    # Configure Interface:
    # port 1: dhcp, peer with nw
    # port 2: dhcp, internet
    # port 3: dhcp, private
    #
    ##############################################################################
    # Create SWIs - Public Circuits
    ##############################################################################
    print("SPoV DC")
    DC_INTERNET_CIRCUITID = None
    priint_data = copy.deepcopy(SWI_TEMPLATE)
    priint_data["name"] = "DC1 ISP Circuit"
    priint_data["type"] = "publicwan"
    priint_data["network_id"] = wannwpub_name_id[PRIMARY_INTERNET_PROVIDER]
    priint_data["label_id"] = label_name_id[PRIMARY_INTERNET_CATEGORY]
    priint_data["lqm_config"] = None
    priint_data["link_bw_down"] = 1000
    priint_data["link_bw_up"] = 1000


    resp = sase_session.post.waninterfaces(site_id=dc_site_id, data=priint_data)
    if resp.cgx_status:
        print("\tPublic Circuit: DC1 ISP Circuit created")
        DC_INTERNET_CIRCUITID = resp.cgx_content.get("id", None)

    else:
        print("ERR: Could not create Public Circuit: DC1 ISP Circuit")
        prisma_sase.jd_detailed(resp)

    ##############################################################################
    # Create SWIs - Private Circuits
    ##############################################################################
    DC_MPLS_CIRCUITID = None
    priint_data = copy.deepcopy(SWI_TEMPLATE)
    priint_data["name"] = "DC1 MPLS Circuit"
    priint_data["type"] = "privatewan"
    priint_data["network_id"] = wannwpri_name_id[PRIVATEWAN_PROVIDER]
    priint_data["label_id"] = label_name_id[PRIVATEWAN_CATEGORY]
    priint_data["lqm_config"] = None
    priint_data["link_bw_down"] = 100
    priint_data["link_bw_up"] = 100

    resp = sase_session.post.waninterfaces(site_id=dc_site_id, data=priint_data)
    if resp.cgx_status:
        print("\tPrivate Circuit: DC1 MPLS Circuit created")
        DC_MPLS_CIRCUITID = resp.cgx_content.get("id", None)

    else:
        print("ERR: Could not create Private Circuit: DC1 MPLS Circuit")
        prisma_sase.jd_detailed(resp)

    ##############################################################################
    # Get Hub Cluster ID
    ##############################################################################
    hubcluster_id=None
    resp = sase_session.get.hubclusters(site_id=dc_site_id)
    if resp.cgx_status:
        hubclusters = resp.cgx_content.get("items", None)
        for cluster in hubclusters:
            if cluster["default_cluster"]:
                hubcluster_id = cluster["id"]
    else:
        print("ERR: Could not retrieve hub clusters for SPOV DC")
        prisma_sase.jd_detailed(resp)
        sys.exit()
    ##############################################################################
    # Create Element Shell for DC ION 1
    ##############################################################################
    shell_data = {
        "tenant_id": sase_session.tenant_id,
        "site_id": dc_site_id,
        "software_version": ION_SOFTWARE_VERSION,
        "model_name": "ion 3104v",
        "name": "DC-ION-1",
        "role": "HUB",
        "cluster_id": hubcluster_id
    }
    resp = sase_session.post.elementshells(site_id=dc_site_id, data=shell_data)
    if resp.cgx_status:
        print("\tElement Shell created for DC-ION-1")
        dc_elemshell1_id = resp.cgx_content.get("id", None)
        dc_elem1_id = resp.cgx_content.get("element_id", None)

        resp = sase_session.get.elementshells_interfaces(site_id=dc_site_id, elementshell_id=dc_elemshell1_id)
        if resp.cgx_status:
            intflist = resp.cgx_content.get("items", None)
            for intf in intflist:
                if "controller" in intf["name"]:
                    intf["admin_up"] = True
                    intf["ipv4_config"] = IPV4_TEMPLATE_DHCP

                    resp = sase_session.put.elementshells_interfaces(site_id=dc_site_id,
                                                                     elementshell_id=dc_elemshell1_id,
                                                                     interface_id=intf["id"],
                                                                     data=intf)
                    if resp.cgx_status:
                        print("\tController port on DC-ION-1 configured")
                    else:
                        print("ERR: Could not configure controller port on DC-ION-1")
                        prisma_sase.jd_detailed(resp)

                elif intf["name"] == "1":
                    intf["admin_up"] = True
                    intf["ipv4_config"] = IPV4_TEMPLATE_DHCP
                    intf["used_for"] = "private"
                    resp = sase_session.put.elementshells_interfaces(site_id=dc_site_id,
                                                                     elementshell_id=dc_elemshell1_id,
                                                                     interface_id=intf["id"],
                                                                     data=intf)
                    if resp.cgx_status:
                        print("\tPort 1 on DC-ION-1 configured")
                    else:
                        print("ERR: Could not configure port 1 on DC-ION-1")
                        prisma_sase.jd_detailed(resp)

                elif intf["name"] == "2":
                    intf["admin_up"] = True
                    intf["ipv4_config"] = IPV4_TEMPLATE_DHCP
                    intf["used_for"] = "public"
                    intf["site_wan_interface_ids"] = [DC_INTERNET_CIRCUITID]
                    resp = sase_session.put.elementshells_interfaces(site_id=dc_site_id,
                                                                     elementshell_id=dc_elemshell1_id,
                                                                     interface_id=intf["id"],
                                                                     data=intf)
                    if resp.cgx_status:
                        print("\tPort 2 on DC-ION-1 configured")
                    else:
                        print("ERR: Could not configure port 2 on DC-ION-1")
                        prisma_sase.jd_detailed(resp)

                elif intf["name"] == "3":
                    intf["admin_up"] = True
                    intf["ipv4_config"] = IPV4_TEMPLATE_DHCP
                    intf["used_for"] = "private"
                    intf["site_wan_interface_ids"] = [DC_MPLS_CIRCUITID]
                    resp = sase_session.put.elementshells_interfaces(site_id=dc_site_id,
                                                                     elementshell_id=dc_elemshell1_id,
                                                                     interface_id=intf["id"],
                                                                     data=intf)
                    if resp.cgx_status:
                        print("\tPort 3 on DC-ION-1 configured")
                    else:
                        print("ERR: Could not configure port 3 on DC-ION-1")
                        prisma_sase.jd_detailed(resp)

        print("\tConfiguring BGP Peer on DC-ION-1")
        create_bgp_peer(sase_session=sase_session, site_id=dc_site_id, element_id=dc_elem1_id)

    else:
        print("ERR: Could not create element shell for DC ION 1")
        prisma_sase.jd_detailed(resp)

    ##############################################################################
    # Create Element Shell for DC ION 2
    ##############################################################################
    shell_data = {
        "tenant_id": sase_session.tenant_id,
        "site_id": dc_site_id,
        "software_version": ION_SOFTWARE_VERSION,
        "model_name": "ion 3104v",
        "name": "DC-ION-2",
        "role": "HUB",
        "cluster_id": hubcluster_id
    }
    resp = sase_session.post.elementshells(site_id=dc_site_id, data=shell_data)
    if resp.cgx_status:
        print("\tElement Shell created for DC-ION-2")
        dc_elemshell2_id = resp.cgx_content.get("id", None)
        dc_elem2_id = resp.cgx_content.get("element_id", None)

        resp = sase_session.get.elementshells_interfaces(site_id=dc_site_id, elementshell_id=dc_elemshell2_id)
        if resp.cgx_status:
            intflist = resp.cgx_content.get("items", None)
            for intf in intflist:
                if "controller" in intf["name"]:
                    intf["admin_up"] = True
                    intf["ipv4_config"] = IPV4_TEMPLATE_DHCP

                    resp = sase_session.put.elementshells_interfaces(site_id=dc_site_id,
                                                                     elementshell_id=dc_elemshell2_id,
                                                                     interface_id=intf["id"],
                                                                     data=intf)
                    if resp.cgx_status:
                        print("\tController port on DC-ION-2 configured")
                    else:
                        print("ERR: Could not configure controller port on DC-ION-2")
                        prisma_sase.jd_detailed(resp)

                elif intf["name"] == "1":
                    intf["admin_up"] = True
                    intf["ipv4_config"] = IPV4_TEMPLATE_DHCP
                    intf["used_for"] = "private"
                    resp = sase_session.put.elementshells_interfaces(site_id=dc_site_id,
                                                                     elementshell_id=dc_elemshell2_id,
                                                                     interface_id=intf["id"],
                                                                     data=intf)
                    if resp.cgx_status:
                        print("\tPort 1 on DC-ION-2 configured")
                    else:
                        print("ERR: Could not configure port 1 on DC-ION-2")
                        prisma_sase.jd_detailed(resp)

                elif intf["name"] == "2":
                    intf["admin_up"] = True
                    intf["ipv4_config"] = IPV4_TEMPLATE_DHCP
                    intf["used_for"] = "public"
                    intf["site_wan_interface_ids"] = [DC_INTERNET_CIRCUITID]
                    resp = sase_session.put.elementshells_interfaces(site_id=dc_site_id,
                                                                     elementshell_id=dc_elemshell2_id,
                                                                     interface_id=intf["id"],
                                                                     data=intf)
                    if resp.cgx_status:
                        print("\tPort 2 on DC-ION-2 configured")
                    else:
                        print("ERR: Could not configure port 2 on DC-ION-2")
                        prisma_sase.jd_detailed(resp)

                elif intf["name"] == "3":
                    intf["admin_up"] = True
                    intf["ipv4_config"] = IPV4_TEMPLATE_DHCP
                    intf["used_for"] = "private"
                    intf["site_wan_interface_ids"] = [DC_MPLS_CIRCUITID]
                    resp = sase_session.put.elementshells_interfaces(site_id=dc_site_id,
                                                                     elementshell_id=dc_elemshell2_id,
                                                                     interface_id=intf["id"],
                                                                     data=intf)
                    if resp.cgx_status:
                        print("\tPort 3 on DC-ION-2 configured")
                    else:
                        print("ERR: Could not configure port 3 on DC-ION-2")
                        prisma_sase.jd_detailed(resp)

        print("\tConfiguring BGP Peer on DC-ION-2")
        create_bgp_peer(sase_session=sase_session, site_id=dc_site_id, element_id=dc_elem2_id)

    else:
        print("ERR: Could not create element shell for DC ION 2")
        prisma_sase.jd_detailed(resp)

    ##############################################################################
    # Create DC2
    ##############################################################################
    if dc_type == "DC2":
        dc_data = {
            "name": "SPoV DC2 test",
            "description": "Auto-created DC site for Simplified PoV",
            "address": {
                "street": "",
                "state": "",
                "post_code": "",
                "city": "San Francisco",
                "country": "United States",
                "street2": None
            },
            "location": {
                "latitude": 37.7792376,
                "longitude": -122.419359,
                "description": None
            },
            "tags": [],
            "element_cluster_role": "HUB",
            "admin_state": "active",
            "policy_set_id": None,
            "security_policyset_id": None,
            "network_policysetstack_id": None,
            "priority_policysetstack_id": None,
            "security_policysetstack_id": None,
            "nat_policysetstack_id": None,
            "service_binding": None,
            "extended_tags": None,
            "multicast_peer_group_id": None,
            "perfmgmt_policysetstack_id": None
        }
        resp = sase_session.post.sites(data=dc_data)
        if resp.cgx_status:
            print("SPoV DC2 created")
            dc2_site_id = resp.cgx_content.get("id", None)

            ##############################################################################
            # Create SWIs - Public Circuits
            ##############################################################################
            DC2_INTERNET_CIRCUITID = None
            priint_data = copy.deepcopy(SWI_TEMPLATE)
            priint_data["name"] = "DC2 ISP Circuit"
            priint_data["type"] = "publicwan"
            priint_data["network_id"] = wannwpub_name_id[PRIMARY_INTERNET_PROVIDER]
            priint_data["label_id"] = label_name_id[PRIMARY_INTERNET_CATEGORY]
            priint_data["lqm_config"] = None
            priint_data["link_bw_down"] = 1000
            priint_data["link_bw_up"] = 1000

            resp = sase_session.post.waninterfaces(site_id=dc2_site_id, data=priint_data)
            if resp.cgx_status:
                print("\tPublic Circuit: DC2 ISP Circuit created")
                DC2_INTERNET_CIRCUITID = resp.cgx_content.get("id", None)

            else:
                print("ERR: Could not create Public Circuit: DC2 ISP Circuit")
                prisma_sase.jd_detailed(resp)

            ##############################################################################
            # Create SWIs - Private Circuits
            ##############################################################################
            DC2_MPLS_CIRCUITID = None
            priint_data = copy.deepcopy(SWI_TEMPLATE)
            priint_data["name"] = "DC2 MPLS Circuit"
            priint_data["type"] = "privatewan"
            priint_data["network_id"] = wannwpri_name_id[PRIVATEWAN_PROVIDER]
            priint_data["label_id"] = label_name_id[PRIVATEWAN_CATEGORY]
            priint_data["lqm_config"] = None
            priint_data["link_bw_down"] = 100
            priint_data["link_bw_up"] = 100

            resp = sase_session.post.waninterfaces(site_id=dc2_site_id, data=priint_data)
            if resp.cgx_status:
                print("\tPrivate Circuit: DC2 MPLS Circuit created")
                DC2_MPLS_CIRCUITID = resp.cgx_content.get("id", None)

            else:
                print("ERR: Could not create Private Circuit: DC2 MPLS Circuit")
                prisma_sase.jd_detailed(resp)

            ##############################################################################
            # Get Hub Cluster ID
            ##############################################################################
            hubcluster_id = None
            resp = sase_session.get.hubclusters(site_id=dc2_site_id)
            if resp.cgx_status:
                hubclusters = resp.cgx_content.get("items", None)
                for cluster in hubclusters:
                    if cluster["default_cluster"]:
                        hubcluster_id = cluster["id"]
            else:
                print("ERR: Could not retrieve hub clusters for SPOV DC2")
                prisma_sase.jd_detailed(resp)
                sys.exit()
            ##############################################################################
            # Create Element Shell for DC2 ION 1
            ##############################################################################
            shell_data = {
                "tenant_id": sase_session.tenant_id,
                "site_id": dc2_site_id,
                "software_version": ION_SOFTWARE_VERSION,
                "model_name": "ion 3108v",
                "name": "DC2-ION-1",
                "role": "HUB",
                "cluster_id": hubcluster_id
            }
            resp = sase_session.post.elementshells(site_id=dc2_site_id, data=shell_data)
            if resp.cgx_status:
                print("\tElement Shell created for DC2-ION-1")
                dc2_elemshell1_id = resp.cgx_content.get("id", None)
                dc2_elem1_id = resp.cgx_content.get("element_id", None)

                resp = sase_session.get.elementshells_interfaces(site_id=dc2_site_id, elementshell_id=dc2_elemshell1_id)
                if resp.cgx_status:
                    intflist = resp.cgx_content.get("items", None)
                    for intf in intflist:
                        if "controller" in intf["name"]:
                            intf["admin_up"] = True
                            intf["ipv4_config"] = IPV4_TEMPLATE_DHCP

                            resp = sase_session.put.elementshells_interfaces(site_id=dc2_site_id,
                                                                             elementshell_id=dc2_elemshell1_id,
                                                                             interface_id=intf["id"],
                                                                             data=intf)
                            if resp.cgx_status:
                                print("\tController port on DC2-ION-1 configured")
                            else:
                                print("ERR: Could not configure controller port on DC2-ION-1")
                                prisma_sase.jd_detailed(resp)

                        elif intf["name"] == "1":
                            intf["admin_up"] = True
                            intf["ipv4_config"] = IPV4_TEMPLATE_DHCP
                            intf["used_for"] = "private"
                            resp = sase_session.put.elementshells_interfaces(site_id=dc2_site_id,
                                                                             elementshell_id=dc2_elemshell1_id,
                                                                             interface_id=intf["id"],
                                                                             data=intf)
                            if resp.cgx_status:
                                print("\tPort 1 on DC2-ION-1 configured")
                            else:
                                print("ERR: Could not configure port 1 on DC2-ION-1")
                                prisma_sase.jd_detailed(resp)

                        elif intf["name"] == "2":
                            intf["admin_up"] = True
                            intf["ipv4_config"] = IPV4_TEMPLATE_DHCP
                            intf["used_for"] = "public"
                            intf["site_wan_interface_ids"] = [DC2_INTERNET_CIRCUITID]
                            resp = sase_session.put.elementshells_interfaces(site_id=dc2_site_id,
                                                                             elementshell_id=dc2_elemshell1_id,
                                                                             interface_id=intf["id"],
                                                                             data=intf)
                            if resp.cgx_status:
                                print("\tPort 2 on DC2-ION-1 configured")
                            else:
                                print("ERR: Could not configure port 2 on DC2-ION-1")
                                prisma_sase.jd_detailed(resp)

                        elif intf["name"] == "3":
                            intf["admin_up"] = True
                            intf["ipv4_config"] = IPV4_TEMPLATE_DHCP
                            intf["used_for"] = "private"
                            intf["site_wan_interface_ids"] = [DC2_MPLS_CIRCUITID]
                            resp = sase_session.put.elementshells_interfaces(site_id=dc2_site_id,
                                                                             elementshell_id=dc2_elemshell1_id,
                                                                             interface_id=intf["id"],
                                                                             data=intf)
                            if resp.cgx_status:
                                print("\tPort 3 on DC2-ION-1 configured")
                            else:
                                print("ERR: Could not configure port 3 on DC2-ION-1")
                                prisma_sase.jd_detailed(resp)

                print("\tConfiguring BGP Peer on DC2-ION-1")
                create_bgp_peer(sase_session=sase_session, site_id=dc2_site_id, element_id=dc2_elem1_id)

            else:
                print("ERR: Could not create element shell for DC2 ION 1")
                prisma_sase.jd_detailed(resp)

    return


def go():
    #############################################################################
    # Global Variables
    #############################################################################
    global NGFWPOLICYSETID
    #############################################################################
    # Begin Script
    ############################################################################

    parser = argparse.ArgumentParser(description="{0}.".format("Prisma SD-WAN Simplified PoV Setup"))
    config_group = parser.add_argument_group('Config', 'Configuration Details for PoV')
    config_group.add_argument("--controller", "-C", help="Controller URL",
                              default="https://api.sase.paloaltonetworks.com")
    config_group.add_argument("--filename", "-F", help="File containing configuration detail. Provide the full path",
                              default=None)
    config_group.add_argument("--byos", "-B", help="Switch to enable BYOS configurations",
                             action='store_true',
                             default=False)
    config_group.add_argument("--dctype", "-D", help="Allowed values: DC1 or DC2",
                              default="DC1")
    #############################################################################
    # Parse arguments
    #############################################################################
    args = vars(parser.parse_args())
    controller=args["controller"]
    filename=args["filename"]
    byos=args["byos"]
    dctype=args["dctype"]

    #############################################################################
    # Validate arguments
    #############################################################################
    if filename is None:
        print("ERR: Please provide a valid file name")
        sys.exit()
    else:
        if not os.path.exists(filename):
            print("ERR: File not found. Please provide a valid path")
            sys.exit()
        if "csv" not in filename:
            print("ERR: Unsupported file type. Please provide a CSV")
            sys.exit()

    if dctype not in ["DC1", "DC2"]:
        print("ERR: Invalid dctype: {}. Please select DC1 or DC2".format(dctype))
        sys.exit()
    ##############################################################################
    # Instantiate SDK & Login
    ##############################################################################
    if "qa" in controller:
        sase_session = prisma_sase.API(controller=controller, ssl_verify=False)
        sase_session.sase_qa_env = True
    else:
        sase_session = prisma_sase.API(controller=controller)

    sase_session.interactive.login_secret(client_id=PRISMASASE_CLIENT_ID,
                                          client_secret=PRISMASASE_CLIENT_SECRET,
                                          tsg_id=PRISMASASE_TSG_ID)

    if sase_session.tenant_id is None:
        print("ERR: Service Account login failure. Please check client credentials")
        sys.exit()
    #############################################################################
    # Validate file syntax
    #############################################################################
    spovdata = pd.read_csv(filename, dtype=str)
    spovdata = spovdata.astype(object).where(pd.notnull(spovdata), None)

    filecolumns = list(spovdata.columns)

    for col in CSV_HEADER_MANDATORY:
        if col not in filecolumns:
            print("ERR: Invalid configuration file. Mandatory column {} missing!".format(col))
            sys.exit()

    for i,row in spovdata.iterrows():
        #numvlans = row["num_vlans"]

        # vlan_headers = []
        # countadded=1
        # while countadded <= numvlans:
        #     for vlanattr in CSV_HEADER_VLAN:
        #
        #         col = "{}_1".format(vlanattr)
        #         vlan_headers.append(col)
        #         countadded += 1
        #
        # for col in vlan_headers:
        #     if col not in filecolumns:
        #         print("ERR: Invalid configuration file. VLAN configuration {} missing!".format(col))
        #         sys.exit()

        #############################################################################
        # Transpose Variables
        #############################################################################
        transpose_config(rowdata=row)

        #############################################################################
        # Validate software versions
        #############################################################################
        ALLOCATED_IMAGES = []
        resp = sase_session.get.element_images()
        if resp.cgx_status:
            images = resp.cgx_content.get("items", None)
            for image in images:
                if image["state"] in ["release"]:
                    ALLOCATED_IMAGES.append(image["version"])

        if ION_SOFTWARE_VERSION not in ALLOCATED_IMAGES:
            print("ERR: Software Version {} is not allocated to the tenant. Please pick a version from the list below:".format(ION_SOFTWARE_VERSION))
            for item in ALLOCATED_IMAGES:
                if item[0] != "5":
                    print("\t{}".format(item))

            sys.exit()

        #############################################################################
        # Validate config
        #############################################################################
        if row["default_settings"] in ["No", "no", "NO"]:

            #############################################################################
            # Internet Circuit
            #############################################################################
            if NUM_INTERNET > 0:
                if ((PRIMARY_INTERNET_CIRCUITNAME is None) or
                        (PRIMARY_INTERNET_PROVIDER is None) or
                        (PRIMARY_INTERNET_CATEGORY is None) or
                        (PRIMARY_INTERNET_INTERFACE is None)):
                    print("ERR: Incomplete form! Please provide all the data relevant to the PRIMARY INTERNET CIRCUIT!")
                    sys.exit()

                if NUM_INTERNET > 1:
                    if ((SECONDARY_INTERNET_CIRCUITNAME is None) or
                            (SECONDARY_INTERNET_PROVIDER is None) or
                            (SECONDARY_INTERNET_CATEGORY is None) or
                            (SECONDARY_INTERNET_INTERFACE is None)):
                        print("ERR: Incomplete form! Please provide all the data relevant to the SECONDARY INTERNET CIRCUIT!")
                        sys.exit()

                if NUM_INTERNET > 2:
                    print("ERR: Invalid internet_circuit_count! Only 2 internet circuit configuration supported!")
                    sys.exit()

            #############################################################################
            # Private WAN Circuit
            #############################################################################
            if NUM_PRIVATE > 0:
                if ((PRIVATEWAN_CIRCUITNAME is None) or
                        (PRIVATEWAN_PROVIDER is None) or
                        (PRIVATEWAN_CATEGORY is None) or
                        (PRIVATEWAN_INTERFACE is None)):
                    print("ERR: Incomplete form! Please provide all the data relevant to the PRIVATEWAN CIRCUIT!")
                    sys.exit()

                if NUM_PRIVATE > 1:
                    print("ERR: Invalid private_circuit_count! Only 1 Private circuit configuration supported!")
                    sys.exit()

            #############################################################################
            # VLAN Data
            #############################################################################
            if NUM_VLANS > 0:
                if len(VLAN_CONFIG) != NUM_VLANS:
                    print("ERR: Mismatch in number of VLANs [{}] and VLAN Config [{}]. Please provide all the configuration!".format(NUM_VLANS, len(VLAN_CONFIG)))
                    sys.exit()

        ##############################################################################
        # WAN Networks
        ##############################################################################
        WAN_NETWORKS_PUBLIC = [PRIMARY_INTERNET_PROVIDER]
        if NUM_INTERNET > 1:
            WAN_NETWORKS_PUBLIC.append(SECONDARY_INTERNET_PROVIDER)

        if NUM_PRIVATE > 0:
            WAN_NETWORKS_PRIVATE = [PRIVATEWAN_PROVIDER]
        else:
            WAN_NETWORKS_PRIVATE = []

        ###############################################################################
        # Get currently configured WAN Networks
        ###############################################################################
        configured_wannw_public = []
        configured_wannw_private = []
        resp = sase_session.get.wannetworks()
        if resp.cgx_status:
            wannwlist = resp.cgx_content.get("items", None)
            for wannw in wannwlist:
                if wannw["type"] == "publicwan":
                    configured_wannw_public.append(wannw["name"])
                else:
                    configured_wannw_private.append(wannw["name"])
        else:
            print("ERR: Could not retrieve WAN Network")
            prisma_sase.jd_detailed(resp)

        ###############################################################################
        # Create Public WAN Networks
        ###############################################################################
        for wannw in WAN_NETWORKS_PUBLIC:
            if wannw in configured_wannw_public:
                print("Public WAN Network {} already exists on tenant".format(wannw))
            else:
                data1 = {
                    "name": wannw,
                    "description": None,
                    "tags": None,
                    "provider_as_numbers": None,
                    "type": "publicwan"
                }
                resp = sase_session.post.wannetworks(data=data1)
                if resp.cgx_status:
                    print("Public WAN Network {} created".format(wannw))
                else:
                    print("ERR: Could not create Public WAN Network {}".format(wannw))
                    prisma_sase.jd_detailed(resp)

        ###############################################################################
        # Create Private WAN Networks
        ###############################################################################
        for wannw in WAN_NETWORKS_PRIVATE:
            if wannw in configured_wannw_private:
                print("Private WAN Network {} already exists on tenant".format(wannw))
            else:
                data1 = {
                    "name": wannw,
                    "description": None,
                    "tags": None,
                    "provider_as_numbers": None,
                    "type": "privatewan"
                }
                resp = sase_session.post.wannetworks(data=data1)
                if resp.cgx_status:
                    print("Private WAN Network {} created".format(wannw))
                else:
                    print("ERR: Could not create Private WAN Network {}".format(wannw))
                    prisma_sase.jd_detailed(resp)
        ##############################################################################
        # Update Circuit Labels
        ##############################################################################
        PUBLIC_CATEGORY=[PRIMARY_INTERNET_CATEGORY]
        if NUM_INTERNET > 1:
            PUBLIC_CATEGORY.append(SECONDARY_INTERNET_CATEGORY)

        if NUM_PRIVATE > 0:
            PRIVATE_CATEGORY = [PRIVATEWAN_CATEGORY]
        else:
            PRIVATE_CATEGORY = []

        #
        # Get currently configured WAN Networks
        #
        label_name_label={}
        configured_categories_public=[]
        configured_categories_private=[]
        resp = sase_session.get.waninterfacelabels()
        if resp.cgx_status:
            labels = resp.cgx_content.get("items", None)
            for label in labels:
                label_name_label[label["name"]]=label["label"]
                if "public" in label["label"]:
                    configured_categories_public.append(label["name"])
                else:
                    configured_categories_private.append(label["name"])
        else:
            print("ERR: Could not retrieve waninterface labels")
            prisma_sase.jd_detailed(resp)

        #
        # Update Circuit Labels
        #
        circuitname_label_map = {}
        # circuitname_label_map={
        #     "public-10": PRIMARY_INTERNET_CATEGORY,
        #     "public-11": SECONDARY_INTERNET_CATEGORY,
        #     "private-10": PRIVATEWAN_CATEGORY,
        # }

        for category in PUBLIC_CATEGORY:
            if category not in configured_categories_public:
                #circuitname_label_map[category] = label_name_label[category]
                if "public-10" in circuitname_label_map.keys():
                    circuitname_label_map["public-11"] = category
                else:
                    circuitname_label_map["public-10"] = category
            else:
                print("Public Circuit Label: {} already exists".format(category))

        for category in PRIVATE_CATEGORY:
            if category not in configured_categories_private:
                if "private-10" in circuitname_label_map.keys():
                    circuitname_label_map["private-11"] = category
                else:
                    circuitname_label_map["private-10"] = category
            else:
                print("Private Circuit Label: {} already exists".format(category))

        print("Enabling LQM for WAN Interface Labels")
        resp = sase_session.get.waninterfacelabels()
        if resp.cgx_status:
            labels = resp.cgx_content.get("items", None)

            for label in labels:
                if label["label"] in circuitname_label_map.keys():
                    labelname = circuitname_label_map[label["label"]]
                    label["name"] = labelname

                label["use_lqm_for_non_hub_paths"] = True
                label["lqm_enabled"] = True
                label["bwc_enabled"] = True

                resp = sase_session.put.waninterfacelabels(data=label, waninterfacelabel_id=label["id"])
                if resp.cgx_status:
                    print("\t{} updated".format(label["name"]))
                else:
                    print("ERR: Could not update WAN Interface Label {}[{}]".format(label["label"], label["name"]))
                    prisma_sase.jd_detailed(resp)
        else:
            print("ERR: Could not retrieve WAN Interface Labels")
            prisma_sase.jd_detailed(resp)

        ##############################################################################
        # Configure Security Zones
        ##############################################################################
        ZONES = ["EXTERNAL", "GUEST", "LAN", "VPN"]
        resp = sase_session.get.securityzones()
        if resp.cgx_status:
            seczones = resp.cgx_content.get("items", None)
            for seczone in seczones:
                zone_name_id[str.lower(seczone["name"])]=seczone["id"]
        else:
            print("ERR: Could not retrieve security zones")
            prisma_sase.jd_detailed(resp)

        print("Creating Security Zones:")
        for zone in ZONES:
            if str.lower(zone) in zone_name_id.keys():
                print("\t{} exists".format(zone))
            else:
                zone_data = {"name": zone, "description": None}
                resp = sase_session.post.securityzones(data=zone_data)
                if resp.cgx_status:
                    print("\t{} created".format(zone))
                    zone_name_id[str.lower(zone)] = resp.cgx_content.get("id", None)

                else:
                    print("ERR: Could not create zone {}".format(zone))
                    prisma_sase.jd_detailed(resp)
        ##############################################################################
        # Translation Dicts
        ##############################################################################
        create_dicts(sase_session)

        ##############################################################################
        # Create Site
        ##############################################################################
        if SITE_NAME in site_name_id.keys():
            print("ERR: Site {} already exists. Please choose a different site".format(SITE_NAME))
            sys.exit()

        site_data = copy.deepcopy(SITE_TEMPLATE)
        site_data["name"] = SITE_NAME
        site_data["address"] = {
            "street": ADDRESS_STREET,
            "state": ADDRESS_STATE,
            "post_code": ADDRESS_ZIPCODE,
            "country": ADDRESS_COUNTRY,
            "city": ADDRESS_CITY,
            "street2": None
        }
        site_data["location"] = {
            "latitude": ADDRESS_LATITUDE,
            "longitude": ADDRESS_LONGITUDE,
            "description": None
        }

        site_data["service_binding"] = SERVICEBINDINGID
        site_data["network_policysetstack_id"] = NWSTACKID
        site_data["perfmgmt_policysetstack_id"] = PERFSTACKID
        site_data["priority_policysetstack_id"] = QOSSTACKID
        site_data["security_policysetstack_id"] = NGFWSTACKID
        site_data["nat_policysetstack_id"] = NATSTACKID

        SITE_ID=None
        resp = sase_session.post.sites(data=site_data)
        if resp.cgx_status:
            print("Site {} created".format(SITE_NAME))
            SITE_ID = resp.cgx_content.get("id")

        else:
            print("ERR: Could not create site {}".format(SITE_NAME))
            prisma_sase.jd_detailed(resp)
            sys.exit()

        ##############################################################################
        # Create SWIs - Public Circuits
        ##############################################################################
        PRIMARY_INTERNET_CIRCUITID=None
        SECONDARY_INTERNET_CIRCUITID=None
        priint_data = copy.deepcopy(SWI_TEMPLATE)
        priint_data["name"]=PRIMARY_INTERNET_CIRCUITNAME
        priint_data["type"]="publicwan"
        priint_data["network_id"]= wannwpub_name_id[PRIMARY_INTERNET_PROVIDER]
        priint_data["label_id"] = label_name_id[PRIMARY_INTERNET_CATEGORY]

        resp = sase_session.post.waninterfaces(site_id=SITE_ID, data=priint_data)
        if resp.cgx_status:
            print("\tPublic Circuit: {} created".format(PRIMARY_INTERNET_CIRCUITNAME))
            PRIMARY_INTERNET_CIRCUITID=resp.cgx_content.get("id", None)

        else:
            print("ERR: Could not create Public Circuit: {}".format(PRIMARY_INTERNET_CIRCUITNAME))
            prisma_sase.jd_detailed(resp)
            sys.exit()

        if NUM_INTERNET == 2:
            secint_data = copy.deepcopy(SWI_TEMPLATE)
            secint_data["name"] = SECONDARY_INTERNET_CIRCUITNAME
            secint_data["type"] = "publicwan"
            secint_data["network_id"] = wannwpub_name_id[SECONDARY_INTERNET_PROVIDER]
            secint_data["label_id"] = label_name_id[SECONDARY_INTERNET_CATEGORY]

            resp = sase_session.post.waninterfaces(site_id=SITE_ID, data=secint_data)
            if resp.cgx_status:
                print("\tPublic Circuit: {} created".format(SECONDARY_INTERNET_CIRCUITNAME))
                SECONDARY_INTERNET_CIRCUITID=resp.cgx_content.get("id", None)
            else:
                print("ERR: Could not create Public Circuit: {}".format(SECONDARY_INTERNET_CIRCUITNAME))
                prisma_sase.jd_detailed(resp)
                sys.exit()

        ##############################################################################
        # Create SWIs - Private Circuit
        ##############################################################################
        PRIVATEWAN_CIRCUITID=None
        if NUM_PRIVATE > 0:
            priwan_data = copy.deepcopy(SWI_TEMPLATE)
            priwan_data["name"] = PRIVATEWAN_CIRCUITNAME
            priwan_data["type"] = "privatewan"
            priwan_data["network_id"] = wannwpri_name_id[PRIVATEWAN_PROVIDER]
            priwan_data["label_id"] = label_name_id[PRIVATEWAN_CATEGORY]
            resp = sase_session.post.waninterfaces(site_id=SITE_ID, data=priwan_data)
            if resp.cgx_status:
                print("\tPrivate Circuit: {} created".format(PRIVATEWAN_CIRCUITNAME))
                PRIVATEWAN_CIRCUITID=resp.cgx_content.get("id", None)
            else:
                print("ERR: Could not create Private Circuit: {}".format(PRIVATEWAN_CIRCUITNAME))
                prisma_sase.jd_detailed(resp)
                sys.exit()

        ##############################################################################
        # Create Device Shell
        ##############################################################################
        #
        # Model Mapping
        #
        if BRANCH_MODEL not in ION_MODEL_MAPPING.keys():
            print("ERR: Invalid Branch Model. Currently, only the following models are supported: {}".format(ION_MODEL_MAPPING.keys()))
            sys.exit()

        else:
            ION_MODEL = ION_MODEL_MAPPING[BRANCH_MODEL]

        ELEM_SHELL_ID_1 = None
        ELEM_SHELL_ID_2 = None
        ELEM_ID_1 = None
        ELEM_ID_2 = None
        elem_name = "{} ION 1".format(SITE_NAME)
        shell_data = {
            "tenant_id": sase_session.tenant_id,
            "site_id": SITE_ID,
            "software_version": ION_SOFTWARE_VERSION,
            "model_name": ION_MODEL,
            "name": elem_name,
            "role": "SPOKE"
        }
        resp = sase_session.post.elementshells(site_id=SITE_ID, data=shell_data)
        if resp.cgx_status:
            print("\tElement Shell created for {}".format(elem_name))
            payload = resp.cgx_content
            ELEM_SHELL_ID_1=resp.cgx_content.get("id", None)
            ELEM_ID_1=resp.cgx_content.get("element_id", None)

            if (payload["l3_direct_private_wan_forwarding"] == False) or (payload["l3_lan_forwarding"] == False):
                payload["l3_direct_private_wan_forwarding"] = True
                payload["l3_lan_forwarding"] = True
                resp = sase_session.put.elementshells(site_id=SITE_ID, elementshell_id=ELEM_SHELL_ID_1, data=payload)
                if resp.cgx_status:
                    print("\t\tL3 LAN Forwarding and L3 Direct Direct Private WAN Forwarding enabled")
                else:
                    print("ERR: Could not enable L3 LAN Forwarding and L3 Direct Direct Private WAN Forwarding")
                    prisma_sase.jd_detailed(resp)

        else:
            print("ERR: Could not create Element Shell for {}".format(elem_name))
            prisma_sase.jd_detailed(resp)
            sys.exit()

        if HA:
            elem_name = "{} ION 2".format(SITE_NAME)
            shell_data = {
                "tenant_id": sase_session.tenant_id,
                "site_id": SITE_ID,
                "software_version": ION_SOFTWARE_VERSION,
                "model_name": ION_MODEL,
                "name": elem_name,
                "role": "SPOKE"
            }
            resp = sase_session.post.elementshells(site_id=SITE_ID, data=shell_data)
            if resp.cgx_status:
                print("\tElement Shell created for {}".format(elem_name))
                payload = resp.cgx_content
                ELEM_SHELL_ID_2=resp.cgx_content.get("id", None)
                ELEM_ID_2 = resp.cgx_content.get("element_id", None)

                if (payload["l3_direct_private_wan_forwarding"] == False) or (payload["l3_lan_forwarding"] == False):
                    payload["l3_direct_private_wan_forwarding"] = True
                    payload["l3_lan_forwarding"] = True
                    resp = sase_session.put.elementshells(site_id=SITE_ID, elementshell_id=ELEM_SHELL_ID_2, data=payload)
                    if resp.cgx_status:
                        print("\t\tL3 LAN Forwarding and L3 Direct Direct Private WAN Forwarding enabled")
                    else:
                        print("ERR: Could not enable L3 LAN Forwarding and L3 Direct Direct Private WAN Forwarding")
                        prisma_sase.jd_detailed(resp)

            else:
                print("ERR: Could not create Element Shell for {}".format(elem_name))
                prisma_sase.jd_detailed(resp)
                sys.exit()

        ##############################################################################
        #
        # BYOS:
        # BGP Peer Configuration on Branch Site
        #
        ##############################################################################
        if byos:
            print("\tConfiguring BGP Peers on {} ION 1".format(SITE_NAME))
            create_bgp_peer_branch(sase_session=sase_session, site_id=SITE_ID, element_id=ELEM_ID_1)
            if HA:
                print("\tConfiguring BGP Peers on {} ION 2".format(SITE_NAME))
                create_bgp_peer_branch(sase_session=sase_session, site_id=SITE_ID, element_id=ELEM_ID_2)
        ##############################################################################
        # Configure Element Shell Interfaces
        ##############################################################################
        interface_mapping_ion1={}
        usedfor_mapping_ion1={}
        interface_mapping_ion2={}
        usedfor_mapping_ion2={}
        interface_ipconfig_ion1 ={}
        interface_ipconfig_ion2 ={}

        ##############################################################################
        # LAN Interface on ION 1 & ION 2
        ##############################################################################
        # if LAN_IP_PREFIX == "dhcp":
        #     interface_ipconfig_ion1[LAN_INTERFACE] = IPV4_TEMPLATE_DHCP
        #     interface_ipconfig_ion2[LAN_INTERFACE] = IPV4_TEMPLATE_DHCP
        # else:
        #     config = {
        #         "dhcp_config": None,
        #         "dns_v4_config": None,
        #         "routes": None,
        #         "static_config": {"address": LAN_IP_PREFIX},
        #         "type": "static"
        #     }
        #     interface_ipconfig_ion1[LAN_INTERFACE] = config
        #     interface_ipconfig_ion2[LAN_INTERFACE] = config
        ##############################################################################
        # VLAN IDs on ION 1 & ION 2
        ##############################################################################
        VLAN_IDS = []
        for item in VLAN_CONFIG:
            VLAN_IDS.append(item["vlan_id"])

        interface_ipconfig_ion1[LAN_INTERFACE]=VLAN_CONFIG

        if HA:
            interface_ipconfig_ion2[LAN_INTERFACE]=VLAN_CONFIG
        ##############################################################################
        # Primary Internet on ION 1
        ##############################################################################
        interface_mapping_ion1[PRIMARY_INTERNET_INTERFACE] = PRIMARY_INTERNET_CIRCUITID
        usedfor_mapping_ion1[PRIMARY_INTERNET_INTERFACE]="public"
        if PRIMARY_INTERNET_IP_PREFIX is None:
            interface_ipconfig_ion1[PRIMARY_INTERNET_INTERFACE] = IPV4_TEMPLATE_DHCP
        elif PRIMARY_INTERNET_IP_PREFIX == "dhcp":
            interface_ipconfig_ion1[PRIMARY_INTERNET_INTERFACE] = IPV4_TEMPLATE_DHCP
        else:
            if len(PRIMARY_INTERNET_DNS) > 0:
                config = {
                    "dhcp_config": None,
                    "dns_v4_config": {"name_servers": PRIMARY_INTERNET_DNS},
                    "routes": [{"destination": "0.0.0.0/0", "via": PRIMARY_INTERNET_GW}],
                    "static_config": {"address": PRIMARY_INTERNET_IP_PREFIX},
                    "type": "static"
                }
            else:
                config = {
                    "dhcp_config": None,
                    "dns_v4_config": None,
                    "routes": [{"destination": "0.0.0.0/0", "via": PRIMARY_INTERNET_GW}],
                    "static_config": {"address": PRIMARY_INTERNET_IP_PREFIX},
                    "type": "static"
                }
            interface_ipconfig_ion1[PRIMARY_INTERNET_INTERFACE] = config

        if NUM_INTERNET > 1:
            ##############################################################################
            # Secondary Internet on ION 1
            ##############################################################################
            interface_mapping_ion1[SECONDARY_INTERNET_INTERFACE] = SECONDARY_INTERNET_CIRCUITID
            usedfor_mapping_ion1[SECONDARY_INTERNET_INTERFACE] = "public"
            if SECONDARY_INTERNET_IP_PREFIX is None:
                interface_ipconfig_ion1[SECONDARY_INTERNET_INTERFACE] = IPV4_TEMPLATE_DHCP
            elif SECONDARY_INTERNET_IP_PREFIX == "dhcp":
                interface_ipconfig_ion1[SECONDARY_INTERNET_INTERFACE] = IPV4_TEMPLATE_DHCP
            else:
                if len(SECONDARY_INTERNET_DNS) > 0:
                    config = {
                        "dhcp_config": None,
                        "dns_v4_config": {"name_servers": SECONDARY_INTERNET_DNS},
                        "routes": [{"destination": "0.0.0.0/0", "via": SECONDARY_INTERNET_GW}],
                        "static_config": {"address": SECONDARY_INTERNET_IP_PREFIX},
                        "type": "static"
                    }
                else:
                    config = {
                        "dhcp_config": None,
                        "dns_v4_config": None,
                        "routes": [{"destination": "0.0.0.0/0", "via": SECONDARY_INTERNET_GW}],
                        "static_config": {"address": SECONDARY_INTERNET_IP_PREFIX},
                        "type": "static"
                    }
                interface_ipconfig_ion1[SECONDARY_INTERNET_INTERFACE] = config

            ##############################################################################
            # Primary Internet on ION 2
            ##############################################################################
            interface_mapping_ion2[SECONDARY_INTERNET_INTERFACE] = PRIMARY_INTERNET_CIRCUITID
            usedfor_mapping_ion2[SECONDARY_INTERNET_INTERFACE] = "public"
            if PRIMARY_INTERNET_IP_PREFIX is None:
                interface_ipconfig_ion2[SECONDARY_INTERNET_INTERFACE] = IPV4_TEMPLATE_DHCP
            elif PRIMARY_INTERNET_IP_PREFIX == "dhcp":
                interface_ipconfig_ion2[SECONDARY_INTERNET_INTERFACE] = IPV4_TEMPLATE_DHCP
            else:
                if len(PRIMARY_INTERNET_DNS) > 0:
                    config = {
                        "dhcp_config": None,
                        "dns_v4_config": {"name_servers": PRIMARY_INTERNET_DNS},
                        "routes": [{"destination": "0.0.0.0/0", "via": PRIMARY_INTERNET_GW}],
                        "static_config": {"address": PRIMARY_INTERNET_IP_PREFIX},
                        "type": "static"
                    }
                else:
                    config = {
                        "dhcp_config": None,
                        "dns_v4_config": None,
                        "routes": [{"destination": "0.0.0.0/0", "via": PRIMARY_INTERNET_GW}],
                        "static_config": {"address": PRIMARY_INTERNET_IP_PREFIX},
                        "type": "static"
                    }

                interface_ipconfig_ion2[SECONDARY_INTERNET_INTERFACE] = config

            ##############################################################################
            # Secondary Internet on ION 2
            ##############################################################################
            interface_mapping_ion2[PRIMARY_INTERNET_INTERFACE] = SECONDARY_INTERNET_CIRCUITID
            usedfor_mapping_ion2[PRIMARY_INTERNET_INTERFACE] = "public"
            if SECONDARY_INTERNET_IP_PREFIX is None:
                interface_ipconfig_ion2[PRIMARY_INTERNET_INTERFACE] = IPV4_TEMPLATE_DHCP
            elif SECONDARY_INTERNET_IP_PREFIX == "dhcp":
                interface_ipconfig_ion2[PRIMARY_INTERNET_INTERFACE] = IPV4_TEMPLATE_DHCP
            else:
                if len(SECONDARY_INTERNET_DNS) > 0:
                    config = {
                        "dhcp_config": None,
                        "dns_v4_config": {"name_servers": SECONDARY_INTERNET_DNS},
                        "routes": [{"destination": "0.0.0.0/0", "via": SECONDARY_INTERNET_GW}],
                        "static_config": {"address": SECONDARY_INTERNET_IP_PREFIX},
                        "type": "static"
                    }
                else:
                    config = {
                        "dhcp_config": None,
                        "dns_v4_config": None,
                        "routes": [{"destination": "0.0.0.0/0", "via": SECONDARY_INTERNET_GW}],
                        "static_config": {"address": SECONDARY_INTERNET_IP_PREFIX},
                        "type": "static"
                    }
                interface_ipconfig_ion2[PRIMARY_INTERNET_INTERFACE] = config

        if NUM_PRIVATE > 0:
            ##############################################################################
            # Private WAN on ION 1
            ##############################################################################
            interface_mapping_ion1[PRIVATEWAN_INTERFACE] = PRIVATEWAN_CIRCUITID
            usedfor_mapping_ion1[PRIVATEWAN_INTERFACE] = "private"
            if PRIVATEWAN_IP_PREFIX is None:
                interface_ipconfig_ion1[PRIVATEWAN_INTERFACE] = IPV4_TEMPLATE_DHCP
            elif PRIVATEWAN_IP_PREFIX == "dhcp":
                interface_ipconfig_ion1[PRIVATEWAN_INTERFACE] = IPV4_TEMPLATE_DHCP
            else:
                if len(PRIVATEWAN_DNS) > 0:
                    config = {
                        "dhcp_config": None,
                        "dns_v4_config": {"name_servers": PRIVATEWAN_DNS},
                        "routes": [{"destination": "0.0.0.0/0", "via": PRIVATEWAN_GW}],
                        "static_config": {"address": PRIVATEWAN_IP_PREFIX},
                        "type": "static"
                    }
                else:
                    config = {
                        "dhcp_config": None,
                        "dns_v4_config": None,
                        "routes": [{"destination": "0.0.0.0/0", "via": PRIVATEWAN_GW}],
                        "static_config": {"address": PRIVATEWAN_IP_PREFIX},
                        "type": "static"
                    }
                interface_ipconfig_ion1[PRIVATEWAN_INTERFACE] = config

            ##############################################################################
            # Primary Internet on ION 2
            ##############################################################################
            interface_mapping_ion2[PRIVATEWAN_INTERFACE] = PRIMARY_INTERNET_CIRCUITID
            usedfor_mapping_ion2[PRIVATEWAN_INTERFACE] = "public"
            if PRIMARY_INTERNET_IP_PREFIX is None:
                interface_ipconfig_ion2[PRIVATEWAN_INTERFACE] = IPV4_TEMPLATE_DHCP
            elif PRIMARY_INTERNET_IP_PREFIX == "dhcp":
                interface_ipconfig_ion2[PRIVATEWAN_INTERFACE] = IPV4_TEMPLATE_DHCP
            else:
                if len(PRIMARY_INTERNET_DNS) > 0:
                    config = {
                        "dhcp_config": None,
                        "dns_v4_config": {"name_servers": PRIMARY_INTERNET_DNS},
                        "routes": [{"destination": "0.0.0.0/0", "via": PRIMARY_INTERNET_GW}],
                        "static_config": {"address": PRIMARY_INTERNET_IP_PREFIX},
                        "type": "static"
                    }
                else:
                    config = {
                        "dhcp_config": None,
                        "dns_v4_config": None,
                        "routes": [{"destination": "0.0.0.0/0", "via": PRIMARY_INTERNET_GW}],
                        "static_config": {"address": PRIMARY_INTERNET_IP_PREFIX},
                        "type": "static"
                    }
                interface_ipconfig_ion2[PRIVATEWAN_INTERFACE] = config

            ##############################################################################
            # Primary WAN on ION 2
            ##############################################################################
            interface_mapping_ion2[PRIMARY_INTERNET_INTERFACE] = PRIVATEWAN_CIRCUITID
            usedfor_mapping_ion2[PRIMARY_INTERNET_INTERFACE] = "private"
            if PRIVATEWAN_IP_PREFIX is None:
                interface_ipconfig_ion2[PRIMARY_INTERNET_INTERFACE] = IPV4_TEMPLATE_DHCP
            elif PRIVATEWAN_IP_PREFIX == "dhcp":
                interface_ipconfig_ion2[PRIMARY_INTERNET_INTERFACE] = IPV4_TEMPLATE_DHCP
            else:
                if len(PRIVATEWAN_DNS) > 0:
                    config = {
                        "dhcp_config": None,
                        "dns_v4_config": {"name_servers": PRIVATEWAN_DNS},
                        "routes": [{"destination": "0.0.0.0/0", "via": PRIVATEWAN_GW}],
                        "static_config": {"address": PRIVATEWAN_IP_PREFIX},
                        "type": "static"
                    }
                else:
                    config = {
                        "dhcp_config": None,
                        "dns_v4_config": None,
                        "routes": [{"destination": "0.0.0.0/0", "via": PRIVATEWAN_GW}],
                        "static_config": {"address": PRIVATEWAN_IP_PREFIX},
                        "type": "static"
                    }
                interface_ipconfig_ion2[PRIMARY_INTERNET_INTERFACE] = config


        print("\t{} ION 1".format(SITE_NAME))
        config_interfaces(sase_session=sase_session, interface_mapping=interface_mapping_ion1,
                          interface_ipconfig=interface_ipconfig_ion1, usedfor_mapping=usedfor_mapping_ion1,
                          vlan_ids=VLAN_IDS, site_id=SITE_ID,
                          element_id=ELEM_SHELL_ID_1, ion_model=BRANCH_MODEL)

        if HA:
            print("\t{} ION 2".format(SITE_NAME))
            config_interfaces(sase_session=sase_session, interface_mapping=interface_mapping_ion2,
                              interface_ipconfig=interface_ipconfig_ion2, usedfor_mapping=usedfor_mapping_ion2,
                              vlan_ids=VLAN_IDS, site_id=SITE_ID,
                              element_id=ELEM_SHELL_ID_2, ion_model=BRANCH_MODEL)

        ##############################################################################
        #
        # ZONE BINDING
        #
        ##############################################################################
        print("Zone binding")
        ##############################################################################
        # Bind Zones to Interface: VPN
        ##############################################################################
        ###############################################################################
        # Get WAN Overlay IDs for binding
        # Bind VPN zone to WAN Overlay
        ###############################################################################
        print("\tRetrieving WAN Overlays")
        wanoverlay_id = None
        resp = sase_session.get.wanoverlays()
        if resp.cgx_status:
            overlays = resp.cgx_content.get("items", None)
            if len(overlays) == 0:
                print("\tNo WAN Overlay. Configuring now..")
                data = {"name": "VPN", "description": None, "vni": 1}
                resp = sase_session.post.wanoverlays(data=data)
                if resp.cgx_status:
                    print("\tWAN Overlay created")
                    wanoverlay_id = resp.cgx_content.get("id", None)
                else:
                    print("ERR: Could not create wanoverlay")
                    prisma_sase.jd_detailed(resp)

            for item in overlays:
                if item["name"] in ["zbfw_overlay", "VPN"]:
                    wanoverlay_id = item["id"]
        else:
            print("ERR: Could not retrieve WAN Overlays")
            prisma_sase.jd_detailed(resp)

        print("\tBinding Zone: VPN")
        zone_data = {
            "zone_id": zone_name_id["vpn"],
            "lannetwork_ids": [],
            "interface_ids": [],
            "wanoverlay_ids": [wanoverlay_id],
            "waninterface_ids": []
        }
        ###############################################################################
        # ION 1
        ###############################################################################
        resp = sase_session.post.elementsecurityzones(site_id=SITE_ID, element_id=ELEM_ID_1, data=zone_data)
        if resp.cgx_status:
            print("\t\tVPN bound to wanoverlay on ION 1")
        else:
            print("ERR: Could not bind VPN to wanoverlay on ION 1")
            prisma_sase.jd_detailed(resp)

        if HA:
            ###############################################################################
            # ION 2
            ###############################################################################
            resp = sase_session.post.elementsecurityzones(site_id=SITE_ID, element_id=ELEM_ID_2, data=zone_data)
            if resp.cgx_status:
                print("\t\tVPN bound to wanoverlay on ION 2")
            else:
                print("ERR: Could not bind VPN to wanoverlay on ION 2")
                prisma_sase.jd_detailed(resp)

        ##############################################################################
        # Bind Zones to Interface: EXTERNAL
        ##############################################################################
        external_swis = []
        external_swis_names = []

        if PRIMARY_INTERNET_CIRCUITID is not None:
            external_swis.append(PRIMARY_INTERNET_CIRCUITID)
            external_swis_names.append(PRIMARY_INTERNET_CIRCUITNAME)

        if SECONDARY_INTERNET_CIRCUITID is not None:
            external_swis.append(SECONDARY_INTERNET_CIRCUITID)
            external_swis_names.append(SECONDARY_INTERNET_CIRCUITNAME)

        if PRIVATEWAN_CIRCUITID is not None:
            external_swis.append(PRIVATEWAN_CIRCUITID)
            external_swis_names.append(PRIVATEWAN_CIRCUITNAME)


        print("\tBinding Zone: EXTERNAL")
        zone_data = {
            "zone_id": zone_name_id["external"],
            "lannetwork_ids": [],
            "interface_ids": [],
            "wanoverlay_ids": [],
            "waninterface_ids": external_swis
        }
        ###############################################################################
        # ION 1
        ###############################################################################
        resp = sase_session.post.elementsecurityzones(site_id=SITE_ID, element_id=ELEM_ID_1, data=zone_data)
        if resp.cgx_status:
            print("\t\tEXTERNAL bound to SWIs {} on ION 1".format(external_swis_names))
        else:
            print("ERR: Could not bind EXTERNAL to SWIs {} on ION 1".format(external_swis_names))
            prisma_sase.jd_detailed(resp)

        if HA:
            ###############################################################################
            # ION 2
            ###############################################################################
            resp = sase_session.post.elementsecurityzones(site_id=SITE_ID, element_id=ELEM_ID_2, data=zone_data)
            if resp.cgx_status:
                print("\t\tEXTERNAL bound to SWIs {} on ION 2".format(external_swis_names))
            else:
                print("ERR: Could not bind EXTERNAL to SWIs {} on ION 2".format(external_swis_names))
                prisma_sase.jd_detailed(resp)

        ##############################################################################
        # Bind Zones to Interface: GUEST
        ##############################################################################
        ###############################################################################
        # ION 1
        ###############################################################################
        if NUM_VLANS > 0:
            guest_interface_id = None
            guest_interface_name = None
            resp = sase_session.get.interfaces(site_id=SITE_ID, element_id=ELEM_ID_1)
            if resp.cgx_status:
                interfaces = resp.cgx_content.get("items", None)
                for intf in interfaces:
                    if intf["description"] == "GUEST":
                        guest_interface_id = intf["id"]
                        guest_interface_name = intf["name"]

            else:
                print("ERR: Could not retrieve interfaces")
                prisma_sase.jd_detailed(resp)

            print("\tBinding Zone: GUEST")
            if guest_interface_id is not None:
                zone_data = {
                    "zone_id": zone_name_id["guest"],
                    "lannetwork_ids": [],
                    "interface_ids": [guest_interface_id],
                    "wanoverlay_ids": [],
                    "waninterface_ids": []
                }

                resp = sase_session.post.elementsecurityzones(site_id=SITE_ID, element_id=ELEM_ID_1, data=zone_data)
                if resp.cgx_status:
                    print("\t\tGUEST bound to interface {} on ION 1".format(guest_interface_name))
                else:
                    print("ERR: Could not bind GUEST to interface {} on ION 1".format(guest_interface_name))
                    prisma_sase.jd_detailed(resp)
            else:
                print("\t\tGUEST zone not bound. No mapping interface!")

            if HA:
                ###############################################################################
                # ION 2
                ###############################################################################
                guest_interface_id = None
                guest_interface_name = None
                resp = sase_session.get.interfaces(site_id=SITE_ID, element_id=ELEM_ID_2)
                if resp.cgx_status:
                    interfaces = resp.cgx_content.get("items", None)
                    for intf in interfaces:
                        if intf["description"] == "GUEST":
                            guest_interface_id = intf["id"]
                            guest_interface_name = intf["name"]

                else:
                    print("ERR: Could not retrieve interfaces")
                    prisma_sase.jd_detailed(resp)

                if guest_interface_id is not None:
                    zone_data = {
                        "zone_id": zone_name_id["guest"],
                        "lannetwork_ids": [],
                        "interface_ids": [guest_interface_id],
                        "wanoverlay_ids": [],
                        "waninterface_ids": []
                    }
                    resp = sase_session.post.elementsecurityzones(site_id=SITE_ID, element_id=ELEM_ID_2, data=zone_data)
                    if resp.cgx_status:
                        print("\t\tGUEST bound to interface {} on ION 2".format(guest_interface_name))
                    else:
                        print("ERR: Could not bind GUEST to interface {} on ION 2".format(guest_interface_name))
                        prisma_sase.jd_detailed(resp)
                else:
                    print("\t\tGUEST zone not bound. No mapping interface!")

            ##############################################################################
            # Bind Zones to Interface: LAN
            ##############################################################################
            ###############################################################################
            # ION 1
            ###############################################################################
            lan_interface_ids = []
            lan_interface_names = []
            resp = sase_session.get.interfaces(site_id=SITE_ID, element_id=ELEM_ID_1)
            if resp.cgx_status:
                interfaces = resp.cgx_content.get("items", None)
                for intf in interfaces:
                    if intf["description"] in ["DATA", "VOICE"]:
                        lan_interface_ids.append(intf["id"])
                        lan_interface_names.append(intf["name"])

                    if intf["name"] == LAN_INTERFACE:
                        lan_interface_ids.append(intf["id"])
                        lan_interface_names.append(intf["name"])

            else:
                print("ERR: Could not retrieve interfaces")
                prisma_sase.jd_detailed(resp)

            print("\tBinding Zone: LAN")
            if len(lan_interface_ids) > 0:
                zone_data = {
                    "zone_id": zone_name_id["lan"],
                    "lannetwork_ids": [],
                    "interface_ids": lan_interface_ids,
                    "wanoverlay_ids": [],
                    "waninterface_ids": []
                }

                resp = sase_session.post.elementsecurityzones(site_id=SITE_ID, element_id=ELEM_ID_1, data=zone_data)
                if resp.cgx_status:
                    print("\t\tLAN bound to interface {} on ION 1".format(lan_interface_names))
                else:
                    print("ERR: Could not bind LAN to interface {} on ION 1".format(lan_interface_names))
                    prisma_sase.jd_detailed(resp)
            else:
                print("\t\tLAN zone not bound. No mapping interface!")

            if HA:
                ###############################################################################
                # ION 2
                ###############################################################################
                lan_interface_ids = []
                lan_interface_names = []
                resp = sase_session.get.interfaces(site_id=SITE_ID, element_id=ELEM_ID_2)
                if resp.cgx_status:
                    interfaces = resp.cgx_content.get("items", None)
                    for intf in interfaces:
                        if intf["description"] in ["DATA", "VOICE"]:
                            lan_interface_ids.append(intf["id"])
                            lan_interface_names.append(intf["name"])

                        if intf["name"] == LAN_INTERFACE:
                            lan_interface_ids.append(intf["id"])
                            lan_interface_names.append(intf["name"])

                else:
                    print("ERR: Could not retrieve interfaces")
                    prisma_sase.jd_detailed(resp)

                if len(lan_interface_ids) > 0:
                    zone_data = {
                        "zone_id": zone_name_id["lan"],
                        "lannetwork_ids": [],
                        "interface_ids": lan_interface_ids,
                        "wanoverlay_ids": [],
                        "waninterface_ids": []
                    }
                    resp = sase_session.post.elementsecurityzones(site_id=SITE_ID, element_id=ELEM_ID_2, data=zone_data)
                    if resp.cgx_status:
                        print("\t\tLAN bound to interface {} on ION 2".format(lan_interface_names))
                    else:
                        print("ERR: Could not bind LAN to interface {} on ION 2".format(lan_interface_names))
                        prisma_sase.jd_detailed(resp)
                else:
                    print("\t\tLAN zone not bound. No mapping interface!")

        ##############################################################################
        # Create Spoke Cluster
        ##############################################################################
        if HA:
            cluster_id = None
            ha_name = "{} HA".format(SITE_NAME)
            ha_data = {
                "name": ha_name,
                "description": None,
                "tags": None,
                "preempt": None,
                "advertisement_interval": 1
            }
            resp = sase_session.post.spokeclusters(site_id=SITE_ID, data=ha_data)
            if resp.cgx_status:
                print("Spoke HA: {} configured".format(ha_name))
                cluster_id = resp.cgx_content.get("id", None)

                ##############################################################################
                # Assign ION 1 to Spoke Cluster
                ##############################################################################
                ha_intf_id = get_ha_interface_id(sase_session=sase_session, site_id=SITE_ID,
                                                 elemshell_id=ELEM_SHELL_ID_1)
                if ha_intf_id is None:
                    print("WARN: No HA interface configured! Device cannot be bound to Spoke Cluster")
                else:
                    resp = sase_session.get.elementshells(site_id=SITE_ID, elementshell_id=ELEM_SHELL_ID_1)
                    if resp.cgx_status:
                        elem_data = resp.cgx_content
                        elem_data["spoke_ha_config"] = {
                            "cluster_id": cluster_id,
                            "enable": True,
                            "priority": 250,
                            "source_interface": ha_intf_id,
                            "track": None
                        }
                        resp = sase_session.put.elementshells(site_id=SITE_ID, elementshell_id=ELEM_SHELL_ID_1,
                                                              data=elem_data)
                        if resp.cgx_status:
                            print("\t{} added to HA Cluster".format(elem_data["name"]))
                        else:
                            print("ERR: Could not add {} to HA cluster".format(elem_data["name"]))
                            prisma_sase.jd_detailed(resp)
                    else:
                        print("ERR: Could not retrieve elementshells")
                        prisma_sase.jd_detailed(resp)

                ##############################################################################
                # Assign ION 2 to Spoke Cluster
                ##############################################################################
                ha_intf_id = get_ha_interface_id(sase_session=sase_session, site_id=SITE_ID,
                                                 elemshell_id=ELEM_SHELL_ID_2)

                if ha_intf_id is None:
                    print("WARN: No HA interface configured! Device cannot be bound to Spoke Cluster")
                else:
                    resp = sase_session.get.elementshells(site_id=SITE_ID, elementshell_id=ELEM_SHELL_ID_2)
                    if resp.cgx_status:
                        elem_data = resp.cgx_content
                        elem_data["spoke_ha_config"] = {
                            "cluster_id": cluster_id,
                            "enable": True,
                            "priority": 210,
                            "source_interface": ha_intf_id,
                            "track": None
                        }
                        resp = sase_session.put.elementshells(site_id=SITE_ID, elementshell_id=ELEM_SHELL_ID_2,
                                                              data=elem_data)
                        if resp.cgx_status:
                            print("\t{} added to HA Cluster".format(elem_data["name"]))
                        else:
                            print("ERR: Could not add {} to HA cluster".format(elem_data["name"]))
                            prisma_sase.jd_detailed(resp)
                    else:
                        print("ERR: Could not retrieve elementshells")
                        prisma_sase.jd_detailed(resp)

            else:
                print("ERR: Could not create spokeclusters")
                prisma_sase.jd_detailed(resp)


    ##############################################################################
    #
    # Create DC Site
    # Service & DC Groups
    # Modify Network Policy Rule
    #
    ##############################################################################
    DC_SITE_ID=None
    if "SPoV DC test" in site_name_id.keys():
        print("DC Site SPoV DC already exists")
        DC_SITE_ID = site_name_id["SPoV DC test"]
    else:
        print("Creating DC Site + Service Binding")
        dc_data = {
            "name": "SPoV DC test",
            "description": "Auto-created DC site for Simplified PoV",
            "address": {
                "street": "",
                "state": "",
                "post_code": "",
                "city": "San Francisco",
                "country": "United States",
                "street2": None
            },
            "location": {
                "latitude": 37.7792376,
                "longitude": -122.419359,
                "description": None
            },
            "tags": [],
            "element_cluster_role": "HUB",
            "admin_state": "active",
            "policy_set_id": None,
            "security_policyset_id": None,
            "network_policysetstack_id": None,
            "priority_policysetstack_id": None,
            "security_policysetstack_id": None,
            "nat_policysetstack_id": None,
            "service_binding": None,
            "extended_tags": None,
            "multicast_peer_group_id": None,
            "perfmgmt_policysetstack_id": None
        }
        resp = sase_session.post.sites(data=dc_data)
        if resp.cgx_status:
            print("\tSPoV DC created")
            DC_SITE_ID=resp.cgx_content.get("id", None)
        else:
            print("ERR: Could not create DC Site")
            prisma_sase.jd_detailed(resp)
    ##############################################################################
    # Retrieve Existing Service Label Configuration
    ##############################################################################
    configured_servicelabels = []
    servicelabel_id = None
    resp = sase_session.get.servicelabels()
    if resp.cgx_status:
        slabellist = resp.cgx_content.get("items", None)
        for slabel in slabellist:
            configured_servicelabels.append(slabel["name"])
            if slabel["name"] == "Primary Data Centers":
                servicelabel_id = slabel["id"]
    else:
        print("ERR: Could not retrieve servicelabels")
        prisma_sase.jd_detailed(resp)
    ##############################################################################
    # Creating DC Group
    ##############################################################################
    if "Primary Data Centers" in configured_servicelabels:
        print("\tService Label Primary Data Centers already configured")
    else:
        data = {
            "name": "Primary Data Centers",
            "description": None,
            "tags": None,
            "type": "cg-transit"
        }
        resp = sase_session.post.servicelabels(data=data)
        if resp.cgx_status:
            print("\tDC Group {} created".format(data["name"]))
            servicelabel_id = resp.cgx_content.get("id")
        else:
            print("ERR: Could not create DC Group")
            prisma_sase.jd_detailed(resp)

    ##############################################################################
    # Create Service Endpoint
    ##############################################################################
    serviceendpoints_name_id = {}
    resp = sase_session.get.serviceendpoints()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            serviceendpoints_name_id[item["name"]] = item["id"]
    else:
        print("ERR: Could not retrieve service endpoints")
        prisma_sase.jd_detailed(resp)

    if "SPoV DC" in serviceendpoints_name_id.keys():
        print("\tService Endpoint SPoV DC already exists")
        serviceendpoint_id = serviceendpoints_name_id["SPoV DC"]

    else:
        data = {
            "name": "SPoV DC",
            "description": None,
            "tags": None,
            "type": "cg-transit",
            "site_id": DC_SITE_ID,
            "admin_up": True,
            "service_link_peers": None,
            "allow_enterprise_traffic": False,
            "liveliness_probe": None,
            "address": {
                "city": None,
                "country": None,
                "post_code": None,
                "state": None,
                "street": None,
                "street2": None
            },
            "location": {
                "description": None,
                "latitude": 0,
                "longitude": 0
            }
        }

        serviceendpoint_id = None
        resp = sase_session.post.serviceendpoints(data=data)
        if resp.cgx_status:
            print("\tService Endpoint SpoV DC created")
            serviceendpoint_id = resp.cgx_content.get("id")
        else:
            print("ERR: Could not create service endpoint")
            prisma_sase.jd_detailed(resp)

    ##############################################################################
    # Update Service Bindingmap
    ##############################################################################
    resp = sase_session.get.servicebindingmaps(servicebindingmap_id=SERVICEBINDINGID)
    if resp.cgx_status:
        servicebindingmap_data = resp.cgx_content
        servicebindingmap_data["service_bindings"] = [{"service_label_id": servicelabel_id, "service_endpoint_ids": [serviceendpoint_id]}]

        resp = sase_session.put.servicebindingmaps(servicebindingmap_id=servicebindingmap_data["id"],
                                          data=servicebindingmap_data)
        if resp.cgx_status:
            print("\tService Binding Map updated")
        else:
            print("ERR: Service Binding Map could not be updated")
            prisma_sase.jd_detailed(resp)

    ##############################################################################
    # Create Security Policy Rules
    # - Guest to External
    # - LAN to External
    # - LAN to VPN
    # - VPN to LAN
    ##############################################################################
    print("Creating Security Policy Rules:")
    if NGFWPOLICYSETID is None:
        NGFWPOLICYSETID = secset_name_id["Branch Simple Security Policy Stack Policy Set (Simple)"]

    ##############################################################################
    # Get Current Rules
    ##############################################################################
    secrules_name_id = {}
    resp = sase_session.get.ngfwsecuritypolicyrules(ngfwsecuritypolicyset_id=NGFWPOLICYSETID)
    if resp.cgx_status:
        rules = resp.cgx_content.get("items", None)
        for rule in rules:
            secrules_name_id[rule["name"]] = rule["id"]
    else:
        print("ERR: Could not retrieve security rules")
        prisma_sase.jd_detailed(resp)
    ##############################################################################
    # Guest to External
    ##############################################################################
    rule1_id = None
    if "GUEST to EXTERNAL" in secrules_name_id.keys():
        print("\tGUEST to EXTERNAL already exists")
        rule1_id = secrules_name_id["GUEST to EXTERNAL"]
    else:
        data = {
            "name": "GUEST to EXTERNAL",
            "description": None,
            "tags": None,
            "source_zone_ids": [zone_name_id["guest"]],
            "source_prefix_ids": None,
            "destination_zone_ids": [zone_name_id["external"]],
            "destination_prefix_ids": None,
            "app_def_ids": None,
            "action": "allow",
            "enabled": True,
            "services": None,
            "user_or_group": None
        }
        resp = sase_session.post.ngfwsecuritypolicyrules(ngfwsecuritypolicyset_id=NGFWPOLICYSETID, data=data)
        if resp.cgx_status:
            print("\tGUEST to EXTERNAL rule created")
            rule1_id = resp.cgx_content.get("id")
        else:
            print("ERR: Could not create GUEST to EXTERNAL rule")
            prisma_sase.jd_detailed(resp)

    ##############################################################################
    # LAN to External
    ##############################################################################
    rule2_id = None
    if "LAN to EXTERNAL" in secrules_name_id.keys():
        print("\tLAN to EXTERNAL already exists")
        rule2_id = secrules_name_id["LAN to EXTERNAL"]
    else:
        data = {
            "name": "LAN to EXTERNAL",
            "description": None,
            "tags": None,
            "source_zone_ids": [zone_name_id["lan"]],
            "source_prefix_ids": None,
            "destination_zone_ids": [zone_name_id["external"]],
            "destination_prefix_ids": None,
            "app_def_ids": None,
            "action": "allow",
            "enabled": True,
            "services": None,
            "user_or_group": None
        }
        resp = sase_session.post.ngfwsecuritypolicyrules(ngfwsecuritypolicyset_id=NGFWPOLICYSETID, data=data)
        if resp.cgx_status:
            print("\tLAN to EXTERNAL rule created")
            rule2_id = resp.cgx_content.get("id")
        else:
            print("ERR: Could not create LAN to EXTERNAL rule")
            prisma_sase.jd_detailed(resp)

    ##############################################################################
    # LAN to VPN
    ##############################################################################
    rule3_id = None
    if "LAN to VPN" in secrules_name_id.keys():
        print("\tLAN to VPN already exists")
        rule3_id = secrules_name_id["LAN to VPN"]
    else:
        data = {
            "name": "LAN to VPN",
            "description": None,
            "tags": None,
            "source_zone_ids": [zone_name_id["lan"]],
            "source_prefix_ids": None,
            "destination_zone_ids": [zone_name_id["vpn"]],
            "destination_prefix_ids": None,
            "app_def_ids": None,
            "action": "allow",
            "enabled": True,
            "services": None,
            "user_or_group": None
        }
        resp = sase_session.post.ngfwsecuritypolicyrules(ngfwsecuritypolicyset_id=NGFWPOLICYSETID, data=data)
        if resp.cgx_status:
            print("\tLAN to VPN rule created")
            rule3_id = resp.cgx_content.get("id")
        else:
            print("ERR: Could not create LAN to VPN rule")
            prisma_sase.jd_detailed(resp)

    ##############################################################################
    # VPN to LAN
    ##############################################################################
    rule4_id = None
    if "VPN to LAN" in secrules_name_id.keys():
        print("\tVPN to LAN already exists")
        rule4_id = secrules_name_id["VPN to LAN"]
    else:
        data = {
            "name": "VPN to LAN",
            "description": None,
            "tags": None,
            "source_zone_ids": [zone_name_id["vpn"]],
            "source_prefix_ids": None,
            "destination_zone_ids": [zone_name_id["lan"]],
            "destination_prefix_ids": None,
            "app_def_ids": None,
            "action": "allow",
            "enabled": True,
            "services": None,
            "user_or_group": None
        }
        resp = sase_session.post.ngfwsecuritypolicyrules(ngfwsecuritypolicyset_id=NGFWPOLICYSETID, data=data)
        if resp.cgx_status:
            print("\tVPN to LAN rule created")
            rule4_id = resp.cgx_content.get("id")
        else:
            print("ERR: Could not create VPN to LAN rule")
            prisma_sase.jd_detailed(resp)

    ##############################################################################
    # Update Rule Order
    ##############################################################################
    ruleorder = [rule1_id, rule2_id, rule3_id, rule4_id]
    resp = sase_session.get.ngfwsecuritypolicysets(ngfwsecuritypolicyset_id=NGFWPOLICYSETID)
    if resp.cgx_status:
        data = resp.cgx_content
        data["policyrule_order"] = ruleorder

        resp = sase_session.put.ngfwsecuritypolicysets(ngfwsecuritypolicyset_id=NGFWPOLICYSETID, data=data)
        if resp.cgx_status:
            print("\tPolicy rule order updated")
        else:
            print("ERR: Could not update policy rule order")
            prisma_sase.jd_detailed(resp)

    else:
        print("ERR: Could not retrieve Security Policy Set")
        prisma_sase.jd_detailed(resp)

    ##############################################################################
    # Modify Network Policy Rule
    ##############################################################################
    print("Updating Network Policy Rules")
    resp = sase_session.get.networkpolicysetstacks()
    if resp.cgx_status:
        stacks = resp.cgx_content.get("items", None)
        for stack in stacks:
            if stack["default_policysetstack"] == True:
                defaultrule_policyset_id = stack["defaultrule_policyset_id"]
                resp = sase_session.get.networkpolicyrules(networkpolicyset_id=defaultrule_policyset_id)
                if resp.cgx_status:
                    rulelist = resp.cgx_content.get("items", None)
                    for rule in rulelist:
                        ##############################################################################
                        # Modify Rule: default
                        ##############################################################################
                        # if rule["name"] == "default":
                        # #     rule["paths_allowed"] = {
                        # #         "active_paths": [{"path_type": "servicelink", "label": "public-*"}],
                        # #         "backup_paths": [{"path_type": "direct", "label": "public-*"}],
                        # #         "l3_failure_paths": None
                        # #     }
                        #     rule["service_context"] = {
                        #         "type": "allowed-transit",
                        #         "backup_service_label_id": None,
                        #         "active_service_label_id": servicelabel_id,
                        #     }
                        #     resp = sase_session.put.networkpolicyrules(networkpolicyset_id=defaultrule_policyset_id,
                        #                                       networkpolicyrule_id=rule["id"],
                        #                                       data=rule)
                        #     if resp.cgx_status:
                        #         print("\tdefault rule modified")
                        #     else:
                        #         print("ERR: Could not modify the default rule")
                        #         prisma_sase.jd_detailed(resp)
                        ##############################################################################
                        # Modify Rule: enterprise-default
                        ##############################################################################
                        if rule["name"] == "enterprise-default":
                            rule["service_context"] = {
                                "type": "allowed-transit",
                                "backup_service_label_id": None,
                                "active_service_label_id": servicelabel_id
                            }
                            resp = sase_session.put.networkpolicyrules(networkpolicyset_id=defaultrule_policyset_id,
                                                              networkpolicyrule_id=rule["id"],
                                                              data=rule)
                            if resp.cgx_status:
                                print("\tenterprise-default rule modified")
                            else:
                                print("ERR: Could not modify the enterprise-default rule")
                                prisma_sase.jd_detailed(resp)
                else:
                    print("ERR: Could not retrieve network policy rules")
                    prisma_sase.jd_detailed(resp)
    else:
        print("ERR: Could not retrieve network stack")
        prisma_sase.jd_detailed(resp)

    ##############################################################################
    # BYOS Configuration
    ##############################################################################
    if byos:
        configure_byos(sase_session=sase_session, dc_site_id=DC_SITE_ID, dc_type=dctype)

    ##############################################################################
    # End of script
    ##############################################################################
    print("LAB SETUP COMPLETE!!")
    return

if __name__ == "__main__":
    go()