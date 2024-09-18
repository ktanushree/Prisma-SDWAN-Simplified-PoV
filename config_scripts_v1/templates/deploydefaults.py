#!/usr/bin/env python

"""
Script to setup Prisma SDWAN Simplified PoV
Author: tkamath@paloaltonetworks.com
Version: 1.0.0b6
"""
import prisma_sase
import argparse
import os
import time
import sys
import datetime
import importlib.util

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

def import_variables_from_file(file_path):
    # Get the module name from the file path
    module_name = os.path.splitext(os.path.basename(file_path))[0]

    # Load the module
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module

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
    "used_for": "ha",
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
CONF_SPOV=None

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
            if item["is_default"]:
                SERVICEBINDINGID=item["id"]
    else:
        print("ERR: Could not retrieve Servicebinding map")
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


def config_interfaces(sase_session, interface_mapping, usedfor_mapping, vlan_ids, site_id, element_id, ion_model):
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

    #
    # Create Bypass Pair 34
    # todo: Look for bypasspairs in the interface names and create ports
    #
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
                print("\tInterface {} set to admin up".format(intf["name"]))
            else:
                print("ERR: Could not set interface {} admin up".format(intf["name"]))
                prisma_sase.jd_detailed(resp)

    bypasspair_data = BYPASSPAIR_TEMPLATE
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
        print("\tBypasspair 34 created")
        interfaces.append(resp.cgx_content)
    else:
        print("ERR: Could not create bypasspair 34")
        prisma_sase.jd_detailed(resp)

    #
    # Check for ION model and create subinterface or SVI
    #
    if ion_model in ["3200", "5200", "9200", "3102v", "3104v", "3108v"]:
        #
        # Get LAN Interface ID, set admin up
        #
        laninterface_id = interface_name_id[CONF_SPOV.LAN_INTERFACE]
        resp = sase_session.get.elementshells_interfaces(site_id=site_id,
                                                         elementshell_id=element_id,
                                                         interface_id=laninterface_id)
        if resp.cgx_status:
            intf = resp.cgx_content
            intf["admin_up"] = True

            resp = sase_session.put.elementshells_interfaces(site_id=site_id,
                                                             elementshell_id=element_id,
                                                             interface_id=laninterface_id,
                                                             data=intf)
            if resp.cgx_status:
                print("\t{} set to admin up".format(intf["name"]))
            else:
                print("ERR: Could not set interface {} to admin up".format(intf["name"]))
                prisma_sase.jd_detailed(resp)
        else:
            print("ERR: Could not get LAN interface")
            prisma_sase.jd_detailed(resp)

        #
        # Create Subinterfaces on LAN Interface
        #
        for vlanid in vlan_ids.keys():
            vlanname = vlan_ids[vlanid]
            subinterface_data = SUBINTERFACE_TEMPLATE
            if vlanname == "HA":
                subinterface_data["scope"] = "global"
                subinterface_data["used_for"] = "ha"
            else:
                subinterface_data["scope"] = "local"

            subinterface_data["parent"] = laninterface_id
            subinterface_data["description"] = vlanname
            subinterface_data["sub_interface"] = {
                "vlan_id": vlanid,
                "native_vlan": None
            }
            subinterface_data["vrf_context_id"] = GLOBALVRFID
            resp = sase_session.post.elementshells_interfaces(site_id=site_id,
                                                              elementshell_id=element_id,
                                                              data=subinterface_data)
            if resp.cgx_status:
                print("\tSubinterface {}[{}] created".format(vlanname, vlanid))
            else:
                print("ERR: Could not create Subinterface {}[{}] on ION 1".format(vlanname, vlanid))
                prisma_sase.jd_detailed(resp)
                sys.exit()

    else:
        #
        # Create SVIs
        #
        print("{} ION 1: ".format(CONF_SPOV.SITE_NAME))
        for vlanid in vlan_ids.keys():
            vlanname = vlan_ids[vlanid]

            svi_data = SVI_TEMPLATE
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
            if vlanname == "HA":
                svi_data["scope"] = "global"
            else:
                svi_data["scope"] = "local"

            resp = sase_session.post.elementshells_interfaces(site_id=site_id,
                                                              elementshell_id=element_id,
                                                              data=svi_data)
            if resp.cgx_status:
                print("\tSVI {}[{}] created".format(vlanname, vlanid))
            else:
                print("ERR: Could not create SVI {}[{}] on ION 1".format(vlanname, vlanid))
                prisma_sase.jd_detailed(resp)
                sys.exit()

        vlans = list(vlan_ids.keys())
        for intf in interfaces:
            if intf["name"] == CONF_SPOV.LAN_INTERFACE:
                intf["admin_up"] = True
                intf["switch_port_config"] = {
                    "vlan_mode": "trunk",
                    "voice_vlan_id": None,
                    "native_vlan_id": None,
                    "access_vlan_id": None,
                    "trunk_vlans": vlans,
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
                    print("\tInterface {} updated with VLANs {}".format(intf["name"], vlans))
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
            intf["ipv4_config"] = {
                "type": "dhcp",
                "static_config": None,
                "dhcp_config": None,
                "dns_v4_config": None,
                "routes": None
            }
            resp = sase_session.put.elementshells_interfaces(site_id=site_id,
                                                             elementshell_id=element_id,
                                                             interface_id=intf["id"],
                                                             data=intf)
            if resp.cgx_status:
                print("\tInterface {} updated".format(intf["name"]))
            else:
                print("ERR: Could not update interface {}".format(intf["name"]))
                prisma_sase.jd_detailed(resp)
                sys.exit()

    return


def go():
    #############################################################################
    # Begin Script
    ############################################################################

    parser = argparse.ArgumentParser(description="{0}.".format("Prisma SD-WAN Simplified PoV Setup"))
    config_group = parser.add_argument_group('Config', 'Configuration Details for PoV')
    config_group.add_argument("--controller", "-C", help="Controller URL",
                              default="https://api.sase.paloaltonetworks.com")
    config_group.add_argument("--filename", "-F", help="Configuration Filename",
                              default="prismasase_settings.py")

    #############################################################################
    # Parse arguments.
    #############################################################################
    args = vars(parser.parse_args())
    controller=args["controller"]
    filename=args["filename"]

    #############################################################################
    # Export Configuration Data
    #############################################################################
    global CONF_SPOV
    CONF_SPOV = import_variables_from_file(filename)
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
    #
    # WAN Networks from 1200S_DualInternet.py
    #
    WAN_NETWORKS_PUBLIC = [CONF_SPOV.PRIMARY_INTERNET_PROVIDER, CONF_SPOV.SECONDARY_INTERNET_PROVIDER]
    WAN_NETWORKS_PRIVATE = [CONF_SPOV.PRIVATEWAN_PROVIDER]

    #
    # Get currently configured WAN Networks
    #
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

    #
    # Create Public WAN Networks
    #
    for wannw in WAN_NETWORKS_PUBLIC:
        if wannw in configured_wannw_public:
            print("Public WAN Network {} already exists on tenant. Skipping.. ".format(wannw))
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

    #
    # Create Private WAN Networks
    #
    for wannw in WAN_NETWORKS_PRIVATE:
        if wannw in configured_wannw_private:
            print("Private WAN Network {} already exists on tenant. Skipping.. ".format(wannw))
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
    #
    # Circuit Labels from 1200S_DualInternet.py
    #
    PUBLIC_CATEGORY=[CONF_SPOV.PRIMARY_INTERNET_CATEGORY, CONF_SPOV.SECONDARY_INTERNET_CATEGORY]
    PRIVATE_CATEGORY=[CONF_SPOV.PRIVATEWAN_CATEGORY]

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
    circuitname_label_map={
        CONF_SPOV.PRIMARY_INTERNET_CATEGORY: "public-10",
        CONF_SPOV.SECONDARY_INTERNET_CATEGORY: "public-11",
        CONF_SPOV.PRIVATEWAN_CATEGORY: "private-10"
    }
    for category in PUBLIC_CATEGORY:
        if category in configured_categories_public:
            circuitname_label_map[category] = label_name_label[category]

    for category in PRIVATE_CATEGORY:
        if category in configured_categories_public:
            circuitname_label_map[category] = label_name_label[category]

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
    if CONF_SPOV.SITE_NAME in site_name_id.keys():
        print("ERR: Site {} already exists. Please choose a different site".format(CONF_SPOV.SITE_NAME))
        sys.exit()

    site_data = SITE_TEMPLATE
    site_data["name"] = CONF_SPOV.SITE_NAME
    site_data["address"] = {
        "street": CONF_SPOV.ADDRESS_STREET,
        "state": CONF_SPOV.ADDRESS_STATE,
        "post_code": CONF_SPOV.ADDRESS_ZIPCODE,
        "country": CONF_SPOV.ADDRESS_COUNTRY,
        "city": CONF_SPOV.ADDRESS_CITY,
        "street2": None
    }
    site_data["location"] = {
        "latitude": CONF_SPOV.ADDRESS_LATITUDE,
        "longitude": CONF_SPOV.ADDRESS_LONGITUDE,
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
        print("Site {} created".format(CONF_SPOV.SITE_NAME))
        SITE_ID = resp.cgx_content.get("id")

    else:
        print("ERR: Could not create site {}".format(CONF_SPOV.SITE_NAME))
        prisma_sase.jd_detailed(resp)
        sys.exit()


    ##############################################################################
    # Create SWIs
    ##############################################################################
    #
    # Public Circuits
    #
    PRIMARY_INTERNET_CIRCUITID=None
    SECONDARY_INTERNET_CIRCUITID=None
    priint_data = SWI_TEMPLATE
    priint_data["name"]=CONF_SPOV.PRIMARY_INTERNET_CIRCUITNAME
    priint_data["type"]="publicwan"
    priint_data["network_id"]= wannwpub_name_id[CONF_SPOV.PRIMARY_INTERNET_PROVIDER]
    priint_data["label_id"] = label_name_id[CONF_SPOV.PRIMARY_INTERNET_CATEGORY]

    resp = sase_session.post.waninterfaces(site_id=SITE_ID, data=priint_data)
    if resp.cgx_status:
        print("Public Circuit: {} created".format(CONF_SPOV.PRIMARY_INTERNET_CIRCUITNAME))
        PRIMARY_INTERNET_CIRCUITID=resp.cgx_content.get("id", None)

    else:
        print("ERR: Could not create Public Circuit: {}".format(CONF_SPOV.PRIMARY_INTERNET_CIRCUITNAME))
        prisma_sase.jd_detailed(resp)
        sys.exit()

    if CONF_SPOV.NUM_INTERNET == 2:
        secint_data = SWI_TEMPLATE
        secint_data["name"] = CONF_SPOV.SECONDARY_INTERNET_CIRCUITNAME
        secint_data["type"] = "publicwan"
        secint_data["network_id"] = wannwpub_name_id[CONF_SPOV.SECONDARY_INTERNET_PROVIDER]
        secint_data["label_id"] = label_name_id[CONF_SPOV.SECONDARY_INTERNET_CATEGORY]

        resp = sase_session.post.waninterfaces(site_id=SITE_ID, data=secint_data)
        if resp.cgx_status:
            print("Public Circuit: {} created".format(CONF_SPOV.SECONDARY_INTERNET_CIRCUITNAME))
            SECONDARY_INTERNET_CIRCUITID=resp.cgx_content.get("id", None)
        else:
            print("ERR: Could not create Public Circuit: {}".format(CONF_SPOV.SECONDARY_INTERNET_CIRCUITNAME))
            prisma_sase.jd_detailed(resp)
            sys.exit()

    #
    # Private Circuit
    #
    PRIVATEWAN_CIRCUITID=None
    if CONF_SPOV.NUM_PRIVATE > 0:
        priwan_data = SWI_TEMPLATE
        priwan_data["name"] = CONF_SPOV.PRIVATEWAN_CIRCUITNAME
        priwan_data["type"] = "privatewan"
        priwan_data["network_id"] = wannwpri_name_id[CONF_SPOV.PRIVATEWAN_PROVIDER]
        priwan_data["label_id"] = label_name_id[CONF_SPOV.PRIVATEWAN_CATEGORY]
        resp = sase_session.post.waninterfaces(site_id=SITE_ID, data=priwan_data)
        if resp.cgx_status:
            print("Private Circuit: {} created".format(CONF_SPOV.PRIVATEWAN_CIRCUITNAME))
            PRIVATEWAN_CIRCUITID=resp.cgx_content.get("id", None)
        else:
            print("ERR: Could not create Private Circuit: {}".format(CONF_SPOV.PRIVATEWAN_CIRCUITNAME))
            prisma_sase.jd_detailed(resp)
            sys.exit()

    ##############################################################################
    # Create Device Shell
    ##############################################################################
    #
    # Model Mapping
    #
    if CONF_SPOV.BRANCH_MODEL not in ION_MODEL_MAPPING.keys():
        print("ERR: Invalid Branch Model. Currently, only the following models are supported: {}".format(ION_MODEL_MAPPING.keys()))
        sys.exit()

    else:
        ION_MODEL = ION_MODEL_MAPPING[CONF_SPOV.BRANCH_MODEL]

    ELEM_SHELL_ID_1 = None
    ELEM_SHELL_ID_2 = None
    ELEM_ID_1 = None
    ELEM_ID_2 = None
    elem_name = "{} ION 1".format(CONF_SPOV.SITE_NAME)
    shell_data = {
        "tenant_id": sase_session.tenant_id,
        "site_id": SITE_ID,
        "software_version": ION_SOFTWARE_VERSION,
        "model_name": ION_MODEL,
        "name": elem_name,
        "role": "SPOKE"
    }
    elem_shell_url = "https://qa.api.sase.paloaltonetworks.com/sdwan/v2.0/api/sites/{}/elementshells".format(SITE_ID)
    resp = sase_session.rest_call(url=elem_shell_url, method="POST", data=shell_data)
    if resp.cgx_status:
        print("Element Shell created for {}".format(elem_name))
        ELEM_SHELL_ID_1=resp.cgx_content.get("id", None)
        ELEM_ID_1=resp.cgx_content.get("element_id", None)

    else:
        print("ERR: Could not create Element Shell for {}".format(elem_name))
        prisma_sase.jd_detailed(resp)
        sys.exit()

    if CONF_SPOV.HA:
        elem_name = "{} ION 2".format(CONF_SPOV.SITE_NAME)
        shell_data = {
            "tenant_id": sase_session.tenant_id,
            "site_id": SITE_ID,
            "software_version": ION_SOFTWARE_VERSION,
            "model_name": ION_MODEL,
            "name": elem_name,
            "role": "SPOKE"
        }
        resp = sase_session.rest_call(url=elem_shell_url, method="POST", data=shell_data)
        if resp.cgx_status:
            print("Element Shell created for {}".format(elem_name))
            ELEM_SHELL_ID_2=resp.cgx_content.get("id", None)
            ELEM_ID_2 = resp.cgx_content.get("element_id", None)

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

    interface_mapping_ion1[CONF_SPOV.PRIMARY_INTERNET_INTERFACE] = PRIMARY_INTERNET_CIRCUITID
    usedfor_mapping_ion1[CONF_SPOV.PRIMARY_INTERNET_INTERFACE]="public"

    if CONF_SPOV.NUM_INTERNET > 1:
        interface_mapping_ion1[CONF_SPOV.SECONDARY_INTERNET_INTERFACE] = SECONDARY_INTERNET_CIRCUITID
        usedfor_mapping_ion1[CONF_SPOV.SECONDARY_INTERNET_INTERFACE] = "public"

        interface_mapping_ion2[CONF_SPOV.SECONDARY_INTERNET_INTERFACE] = PRIMARY_INTERNET_CIRCUITID
        usedfor_mapping_ion2[CONF_SPOV.SECONDARY_INTERNET_INTERFACE] = "public"
        interface_mapping_ion2[CONF_SPOV.PRIMARY_INTERNET_INTERFACE] = SECONDARY_INTERNET_CIRCUITID
        usedfor_mapping_ion2[CONF_SPOV.PRIMARY_INTERNET_INTERFACE] = "public"

    if CONF_SPOV.NUM_PRIVATE > 0:
        interface_mapping_ion1[CONF_SPOV.PRIVATEWAN_INTERFACE] = PRIVATEWAN_CIRCUITID
        usedfor_mapping_ion1[CONF_SPOV.PRIVATEWAN_INTERFACE] = "private"

        interface_mapping_ion2[CONF_SPOV.PRIVATEWAN_INTERFACE] = PRIMARY_INTERNET_CIRCUITID
        usedfor_mapping_ion2[CONF_SPOV.PRIVATEWAN_INTERFACE] = "public"
        interface_mapping_ion2[CONF_SPOV.PRIMARY_INTERNET_INTERFACE] = PRIVATEWAN_CIRCUITID
        usedfor_mapping_ion2[CONF_SPOV.PRIMARY_INTERNET_INTERFACE] = "private"


    print("{} ION 1".format(CONF_SPOV.SITE_NAME))
    config_interfaces(sase_session=sase_session, interface_mapping=interface_mapping_ion1,
                      usedfor_mapping=usedfor_mapping_ion1, vlan_ids=CONF_SPOV.VLAN_IDS,
                      site_id=SITE_ID, element_id=ELEM_SHELL_ID_1, ion_model=CONF_SPOV.BRANCH_MODEL)

    if CONF_SPOV.HA:
        print("{} ION 2".format(CONF_SPOV.SITE_NAME))
        config_interfaces(sase_session=sase_session, interface_mapping=interface_mapping_ion2,
                          usedfor_mapping=usedfor_mapping_ion2, vlan_ids=CONF_SPOV.VLAN_IDS,
                          site_id=SITE_ID, element_id=ELEM_SHELL_ID_2, ion_model=CONF_SPOV.BRANCH_MODEL)


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
    #
    # Get WAN Overlay IDs for binding
    # Bind VPN zone to WAN Overlay
    #
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

    #
    # Bind Zone: "VPN"
    #
    print("\tBinding Zone: VPN")
    zone_data = {
        "zone_id": zone_name_id["vpn"],
        "lannetwork_ids": [],
        "interface_ids": [],
        "wanoverlay_ids": [wanoverlay_id],
        "waninterface_ids": []
    }

    #
    # ION 1
    #
    resp = sase_session.post.elementsecurityzones(site_id=SITE_ID, element_id=ELEM_ID_1, data=zone_data)
    if resp.cgx_status:
        print("\t\tVPN bound to wanoverlay on ION 1")
    else:
        print("ERR: Could not bind VPN to wanoverlay on ION 1")
        prisma_sase.jd_detailed(resp)

    if CONF_SPOV.HA:
        #
        # ION 2
        #
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
        external_swis_names.append(CONF_SPOV.PRIMARY_INTERNET_CIRCUITNAME)

    if SECONDARY_INTERNET_CIRCUITID is not None:
        external_swis.append(SECONDARY_INTERNET_CIRCUITID)
        external_swis_names.append(CONF_SPOV.SECONDARY_INTERNET_CIRCUITNAME)

    if PRIVATEWAN_CIRCUITID is not None:
        external_swis.append(PRIVATEWAN_CIRCUITID)
        external_swis_names.append(CONF_SPOV.PRIVATEWAN_CIRCUITNAME)


    print("\tBinding Zone: EXTERNAL")
    zone_data = {
        "zone_id": zone_name_id["external"],
        "lannetwork_ids": [],
        "interface_ids": [],
        "wanoverlay_ids": [],
        "waninterface_ids": external_swis
    }

    #
    # ION 1
    #
    resp = sase_session.post.elementsecurityzones(site_id=SITE_ID, element_id=ELEM_ID_1, data=zone_data)
    if resp.cgx_status:
        print("\t\tEXTERNAL bound to SWIs {} on ION 1".format(external_swis_names))
    else:
        print("ERR: Could not bind EXTERNAL to SWIs {} on ION 1".format(external_swis_names))
        prisma_sase.jd_detailed(resp)

    if CONF_SPOV.HA:
        #
        # ION 2
        #
        resp = sase_session.post.elementsecurityzones(site_id=SITE_ID, element_id=ELEM_ID_2, data=zone_data)
        if resp.cgx_status:
            print("\t\tEXTERNAL bound to SWIs {} on ION 2".format(external_swis_names))
        else:
            print("ERR: Could not bind EXTERNAL to SWIs {} on ION 2".format(external_swis_names))
            prisma_sase.jd_detailed(resp)

    ##############################################################################
    # Bind Zones to Interface: GUEST
    ##############################################################################
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

    #
    # ION 1
    #
    resp = sase_session.post.elementsecurityzones(site_id=SITE_ID, element_id=ELEM_ID_1, data=zone_data)
    if resp.cgx_status:
        print("\t\tGUEST bound to interface {} on ION 1".format(guest_interface_name))
    else:
        print("ERR: Could not bind GUEST to interface {} on ION 1".format(guest_interface_name))
        prisma_sase.jd_detailed(resp)

    if CONF_SPOV.HA:
        #
        # ION 2
        #
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

    #
    # ION 1
    #
    resp = sase_session.post.elementsecurityzones(site_id=SITE_ID, element_id=ELEM_ID_1, data=zone_data)
    if resp.cgx_status:
        print("\t\tLAN bound to interface {} on ION 1".format(lan_interface_names))
    else:
        print("ERR: Could not bind LAN to interface {} on ION 1".format(lan_interface_names))
        prisma_sase.jd_detailed(resp)

    if CONF_SPOV.HA:
        #
        # ION 2
        #
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
    # End of script
    ##############################################################################
    print("LAB SETUP COMPLETE!!")
    return

if __name__ == "__main__":
    go()
