#!/usr/bin/env python

"""
Script to setup Prisma SDWAN Simplified PoV
Author: tkamath@paloaltonetworks.com
Version: 1.0.0b1
"""
import prisma_sase
import argparse
import os
import time
import sys
import datetime
import copy
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

try:
    from prismasase_settings import BRANCH_MODEL, HA, \
        BRANCH_DOMAIN, \
        SITE_NAME, ADDRESS_CITY, ADDRESS_COUNTRY, \
        ADDRESS_STREET, ADDRESS_STATE, ADDRESS_ZIPCODE, ADDRESS_LONGITUDE, ADDRESS_LATITUDE, \
        NUM_INTERNET, PRIMARY_INTERNET_CATEGORY, PRIMARY_INTERNET_PROVIDER, PRIMARY_INTERNET_CIRCUITNAME, \
        PRIMARY_INTERNET_IP_PREFIX, PRIMARY_INTERNET_GW, PRIMARY_INTERNET_DNS, \
        SECONDARY_INTERNET_CATEGORY, SECONDARY_INTERNET_PROVIDER, SECONDARY_INTERNET_CIRCUITNAME, \
        SECONDARY_INTERNET_IP_PREFIX, SECONDARY_INTERNET_GW, SECONDARY_INTERNET_DNS, \
        NUM_PRIVATE, PRIVATEWAN_CATEGORY, PRIVATEWAN_PROVIDER, \
        PRIVATEWAN_IP_PREFIX, PRIVATEWAN_GW, PRIVATEWAN_DNS, \
        PRIMARY_INTERNET_INTERFACE, SECONDARY_INTERNET_INTERFACE, PRIVATEWAN_INTERFACE, PRIVATEWAN_CIRCUITNAME, \
        VLAN_IDS, LAN_INTERFACE, VLAN_CONFIG

except ImportError:
    print("ERR: Could not import PoV configuration settings from prismasase_settings.py. Using default values to configure Branch site")
    BRANCH_MODEL = "1200S"
    HA = False
    BRANCH_DOMAIN = "Preset Domain"
    SITE_NAME = "Branch 1"
    ADDRESS_CITY = "New York"
    ADDRESS_COUNTRY = "United States"
    ADDRESS_STREET = None
    ADDRESS_STATE = None
    ADDRESS_ZIPCODE = None
    NUM_INTERNET = 2
    PRIMARY_INTERNET_CATEGORY = "Primary Internet"
    PRIMARY_INTERNET_PROVIDER = "AT&T"
    SECONDARY_INTERNET_CATEGORY = "Secondary Internet"
    SECONDARY_INTERNET_PROVIDER = "Verizon"
    NUM_PRIVATE = 0
    PRIVATEWAN_CATEGORY = "MPLS"
    PRIVATEWAN_PROVIDER = "Verizon"
    PRIMARY_INTERNET_INTERFACE = "1"
    SECONDARY_INTERNET_INTERFACE = "2"
    PRIVATEWAN_INTERFACE = "2"
    VLAN_IDS = {
        510: "HA",
        520: "GUEST",
        530: "VOICE",
        540: "DATA"
    }
    LAN_INTERFACE = "5"

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
        "multicast_peer_group_id": None,
        "app_acceleration_enabled": False
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

##############################################################################
# Set Global dicts & variables
##############################################################################
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
    "1200S": "ion 1200-s",
    "3200": "ion 3200",
    "5200": "ion 5200",
    "3102v": "ion 3102v",
    "3104v": "ion 3104v",
    "3108v": "ion 3108v"
}
ION_SOFTWARE_VERSION = "6.1.9-b2"

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
    else:
        print("ERR: Could not retrieve Network Policy Set Stacks")
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
    else:
        print("ERR: Could not retrieve Priority Policy Set Stacks")
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
    else:
        print("ERR: Could not retrieve NAT Policy Set Stacks")
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
        print("\tBranch Simple Security Policy Stack Default Rule Policy Set (Simple) already created")
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
            print("\tBranch Simple Security Policy Stack Default Rule Policy Set (Simple) policy set created")
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

    if "Branch Simple Security Policy Stack (Simple)" in secstack_name_id.keys():
        print("\tBranch Simple Security Policy Stack (Simple) already exists")
        NGFWSTACKID=secstack_name_id["Branch Simple Security Policy Stack (Simple)"]
    else:
        data = {
            "name": "Branch Simple Security Policy Stack (Simple)",
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
    # Create Bypass Pair 34
    # todo: Look for bypasspairs in the interface names and create ports
    #######################################################################
    bp_child = {}
    for intf in interfaces:
        if intf["name"] in ["3", "4"]:
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
            "lan": bp_child["4"],
            "wan": bp_child["3"],
            "use_relay": False,
            "lan_state_propagation": False
        }
    else:
        bypasspair_data["bypass_pair"] = {
            "lan": bp_child["4"],
            "wan": bp_child["3"],
            "use_relay": True,
            "lan_state_propagation": False
        }
    resp = sase_session.post.elementshells_interfaces(site_id=site_id,
                                                      elementshell_id=element_id,
                                                      data=bypasspair_data)
    if resp.cgx_status:
        print("\t\tBypasspair 34 created")
        interfaces.append(resp.cgx_content)
    else:
        print("ERR: Could not create bypasspair 34")
        prisma_sase.jd_detailed(resp)

    #######################################################################
    # Check for ION model and create subinterface or SVI
    #######################################################################
    vlan_config = interface_ipconfig[LAN_INTERFACE]
    #######################################################################
    # Create Subinterface
    #######################################################################
    if ion_model in ["3200", "5200", "9200", "3102v", "3104v", "3108v"]:
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
            #intf["ipv4_config"]=interface_ipconfig[intf["name"]]

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
                    "dns_v4_config": {"name_servers": item["dns"]},
                    "routes": [{"destination": "0.0.0.0/0", "via": item["gw"]}],
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
                    "dns_v4_config": {"name_servers": item["dns"]},
                    "routes": [{"destination": "0.0.0.0/0", "via": item["gw"]}],
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
                intf["admin_up"] = True
                #intf["ipv4_config"]=interface_ipconfig[intf["name"]]
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


def go():
    #############################################################################
    # Begin Script
    ############################################################################

    parser = argparse.ArgumentParser(description="{0}.".format("Prisma SD-WAN Simplified PoV Setup"))
    config_group = parser.add_argument_group('Config', 'Configuration Details for PoV')
    config_group.add_argument("--controller", "-C", help="Controller URL",
                              default="https://api.sase.paloaltonetworks.com")

    #############################################################################
    # Parse arguments.
    #############################################################################
    args = vars(parser.parse_args())
    controller=args["controller"]
    #############################################################################
    # Global Variables
    #############################################################################
    global NGFWPOLICYSETID
    ##############################################################################
    # Instantiate SDK & Login
    ##############################################################################
    sase_session = prisma_sase.API(controller=controller, ssl_verify=False)
    if "qa" in controller:
        sase_session.sase_qa_env=True

    sase_session.interactive.login_secret(client_id=PRISMASASE_CLIENT_ID,
                                          client_secret=PRISMASASE_CLIENT_SECRET,
                                          tsg_id=PRISMASASE_TSG_ID)

    if sase_session.tenant_id is None:
        print("ERR: Service Account login failure. Please check client credentials")
        sys.exit()
    ##############################################################################
    # WAN Networks
    ##############################################################################
    WAN_NETWORKS_PUBLIC = [PRIMARY_INTERNET_PROVIDER, SECONDARY_INTERNET_PROVIDER]
    WAN_NETWORKS_PRIVATE = [PRIVATEWAN_PROVIDER]

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
    PUBLIC_CATEGORY=[PRIMARY_INTERNET_CATEGORY, SECONDARY_INTERNET_CATEGORY]
    PRIVATE_CATEGORY=[PRIVATEWAN_CATEGORY]

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
    circuitname_label_map={}
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
        if category in configured_categories_public:
            if "private-10" in circuitname_label_map.keys():
                circuitname_label_map["private-11"] = category
            else:
                circuitname_label_map["private-10"] = category
        else:
            print("Private Circuit Label: {} already exists".format(category))

    # print("Enabling LQM for WAN Interface Labels")
    # resp = sase_session.get.waninterfacelabels()
    # if resp.cgx_status:
    #     labels = resp.cgx_content.get("items", None)
    #
    #     for label in labels:
    #         if label["label"] in circuitname_label_map.keys():
    #             labelname = circuitname_label_map[label["label"]]
    #             label["name"] = labelname
    #
    #         label["use_lqm_for_non_hub_paths"] = True
    #         label["lqm_enabled"] = True
    #         label["bwc_enabled"] = True
    #
    #         resp = sase_session.put.waninterfacelabels(data=label, waninterfacelabel_id=label["id"])
    #         if resp.cgx_status:
    #             print("\t{} updated".format(label["name"]))
    #         else:
    #             print("ERR: Could not update WAN Interface Label {}[{}]".format(label["label"], label["name"]))
    #             prisma_sase.jd_detailed(resp)
    # else:
    #     print("ERR: Could not retrieve WAN Interface Labels")
    #     prisma_sase.jd_detailed(resp)

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
                zone_name_id[zone] = resp.cgx_content.get("id", None)

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
    resp = sase_session.post.sites(data=site_data, api_version='v4.11')
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
    #         "dns_v4_config": {"name_servers": LAN_DNS},
    #         "routes": [{"destination": "0.0.0.0/0", "via": LAN_GW}],
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
    interface_ipconfig_ion2[LAN_INTERFACE]=VLAN_CONFIG
    ##############################################################################
    # Primary Internet on ION 1
    ##############################################################################
    interface_mapping_ion1[PRIMARY_INTERNET_INTERFACE] = PRIMARY_INTERNET_CIRCUITID
    usedfor_mapping_ion1[PRIMARY_INTERNET_INTERFACE]="public"
    if PRIMARY_INTERNET_IP_PREFIX == "dhcp":
        interface_ipconfig_ion1[PRIMARY_INTERNET_INTERFACE] = IPV4_TEMPLATE_DHCP
    else:
        config = {
            "dhcp_config": None,
            "dns_v4_config": {"name_servers": PRIMARY_INTERNET_DNS},
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
        if SECONDARY_INTERNET_IP_PREFIX == "dhcp":
            interface_ipconfig_ion1[SECONDARY_INTERNET_INTERFACE] = IPV4_TEMPLATE_DHCP
        else:
            config = {
                "dhcp_config": None,
                "dns_v4_config": {"name_servers": SECONDARY_INTERNET_DNS},
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
        if PRIMARY_INTERNET_IP_PREFIX == "dhcp":
            interface_ipconfig_ion2[SECONDARY_INTERNET_INTERFACE] = IPV4_TEMPLATE_DHCP
        else:
            config = {
                "dhcp_config": None,
                "dns_v4_config": {"name_servers": PRIMARY_INTERNET_DNS},
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
        if SECONDARY_INTERNET_IP_PREFIX == "dhcp":
            interface_ipconfig_ion2[PRIMARY_INTERNET_INTERFACE] = IPV4_TEMPLATE_DHCP
        else:
            config = {
                "dhcp_config": None,
                "dns_v4_config": {"name_servers": SECONDARY_INTERNET_DNS},
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
        if PRIVATEWAN_IP_PREFIX == "dhcp":
            interface_ipconfig_ion1[PRIVATEWAN_INTERFACE] = IPV4_TEMPLATE_DHCP
        else:
            config = {
                "dhcp_config": None,
                "dns_v4_config": {"name_servers": PRIVATEWAN_DNS},
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
        if PRIMARY_INTERNET_IP_PREFIX == "dhcp":
            interface_ipconfig_ion2[PRIVATEWAN_INTERFACE] = IPV4_TEMPLATE_DHCP
        else:
            config = {
                "dhcp_config": None,
                "dns_v4_config": {"name_servers": PRIMARY_INTERNET_DNS},
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
        if PRIVATEWAN_IP_PREFIX == "dhcp":
            interface_ipconfig_ion2[PRIMARY_INTERNET_INTERFACE] = IPV4_TEMPLATE_DHCP
        else:
            config = {
                "dhcp_config": None,
                "dns_v4_config": {"name_servers": PRIVATEWAN_DNS},
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
    secrules_name_id={}
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
        rule2_id=secrules_name_id["LAN to EXTERNAL"]
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
        rule3_id=secrules_name_id["LAN to VPN"]
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
        rule4_id=secrules_name_id["VPN to LAN"]
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
    # Bind Zones to Interface: VPN
    ##############################################################################
    print("Zone binding")
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

    else:
        print("ERR: Could not retrieve interfaces")
        prisma_sase.jd_detailed(resp)

    print("\tBinding Zone: LAN")
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

        else:
            print("ERR: Could not retrieve interfaces")
            prisma_sase.jd_detailed(resp)

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


    ##############################################################################
    #
    # Create DC Site
    # Service & DC Groups
    # Modify Network Policy Rule
    #
    ##############################################################################
    DC_SITE_ID=None
    if "SPoV DC" in site_name_id.keys():
        print("DC Site SPoV DC already exists")
        DC_SITE_ID = site_name_id["SPoV DC"]
    else:
        print("Creating DC Site + Service Binding")
        dc_data = {
            "name": "SPoV DC",
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
            "admin_state": "disabled",
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
    # Create Spoke Cluster
    ##############################################################################
    if HA:
        cluster_id = None
        ha_name = "{} HA".format(SITE_NAME)
        ha_data = {
            "name":ha_name,
            "description":None,
            "tags":None,
            "preempt":None,
            "advertisement_interval":1
        }
        resp = sase_session.post.spokeclusters(site_id=SITE_ID, data=ha_data)
        if resp.cgx_status:
            print("Spoke HA: {} configured".format(ha_name))
            cluster_id=resp.cgx_content.get("id", None)

            ##############################################################################
            # Assign ION 1 to Spoke Cluster
            ##############################################################################
            ha_intf_id = get_ha_interface_id(sase_session=sase_session, site_id=SITE_ID, elemshell_id=ELEM_SHELL_ID_1)
            resp = sase_session.get.elementshells(site_id=SITE_ID, elementshell_id=ELEM_SHELL_ID_1)
            if resp.cgx_status:
                elem_data = resp.cgx_content
                elem_data["spoke_ha_config"] = {
                    "cluster_id":cluster_id,
                    "enable":True,
                    "priority":250,
                    "source_interface":ha_intf_id,
                    "track":None
                }
                resp = sase_session.put.elementshells(site_id=SITE_ID, elementshell_id=ELEM_SHELL_ID_1, data=elem_data)
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
            ha_intf_id = get_ha_interface_id(sase_session=sase_session, site_id=SITE_ID, elemshell_id=ELEM_SHELL_ID_2)
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
                resp = sase_session.put.elementshells(site_id=SITE_ID, elementshell_id=ELEM_SHELL_ID_2, data=elem_data)
                if resp.cgx_status:
                    print("\t{} added to HA Cluster".format(elem_data["name"]))
                else:
                    print("ERR: Could not add {} to HA cluster".format(elem_data["name"]))
                    prisma_sase.jd_detailed(resp)
            else:
                print("ERR: Could not retrieve elementshells")
                prisma_sase.jd_detailed(resp)

        else:
            print("ERR: Could not configure spokeclusters")
            prisma_sase.jd_detailed(resp)

    ##############################################################################
    # End of script
    ##############################################################################
    print("LAB SETUP COMPLETE!!")
    return

if __name__ == "__main__":
    go()