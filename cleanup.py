#!/usr/bin/env python

"""
Script to setup Prisma SDWAN Simplified PoV
Author: tkamath@paloaltonetworks.com
Version: 1.0.0b11
"""
import prisma_sase
import argparse
import os
import time
import sys
import datetime
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
# Set Global dicts & variables
##############################################################################

def create_dicts(sase_session):
    print("Building Translation Dicts..")
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

    return


def go():
    #############################################################################
    # Begin Script
    ############################################################################

    parser = argparse.ArgumentParser(description="{0}.".format("Prisma SD-WAN Simplified PoV Setup"))
    config_group = parser.add_argument_group('Config', 'Configuration Details to clean up PoV lab')
    config_group.add_argument("--controller", "-C", help="Controller URL",
                              default="https://api.sase.paloaltonetworks.com")
    config_group.add_argument("--site_name", "-S", help="Name of the Site",default=None)
    config_group.add_argument("--customer_name", "-CN", help="Name of the Customer",default=None)
    config_group.add_argument("--policy_only", "-P", help="Clean up Policy Only",default=False)


    #############################################################################
    # Parse arguments.
    #############################################################################
    args = vars(parser.parse_args())
    controller = args["controller"]
    site_name = args["site_name"]
    customer_name = args["customer_name"]
    policy_only = args["policy_only"]
    #############################################################################
    # Global Variables
    #############################################################################
    global site_id_name
    global site_name_id

    site_id_name = {}
    site_name_id = {}
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
    # Translation Dicts
    ##############################################################################
    create_dicts(sase_session)
    customer_name = "{} ".format(customer_name)

    ##############################################################################
    # Reset NW Stack Name
    ##############################################################################
    resp = sase_session.get.networkpolicysetstacks()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            if item["default_policysetstack"]:
                name = item["name"].replace(customer_name,"")
                item["name"] = name
                resp = sase_session.put.networkpolicysetstacks(networkpolicysetstack_id=item["id"], data=item)
                if resp.cgx_status:
                    print("NW Stack name updated to {}".format(item["name"]))
                else:
                    print("ERR: Could not update NW Stack name")
                    prisma_sase.jd_detailed(resp)
    else:
        print("ERR: Could not retrieve NW Stack")
        prisma_sase.jd_detailed(resp)

    ##############################################################################
    # Reset NW Set Name
    ##############################################################################
    resp = sase_session.get.networkpolicysets()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            if customer_name in item["name"]:
                name = item["name"].replace(customer_name,"")
                item["name"] = name
                resp = sase_session.put.networkpolicysets(networkpolicyset_id=item["id"], data=item)
                if resp.cgx_status:
                    print("NW Set name updated to {}".format(item["name"]))
                else:
                    print("ERR: Could not update NW Set name")
                    prisma_sase.jd_detailed(resp)
    else:
        print("ERR: Could not retrieve NW Sets")
        prisma_sase.jd_detailed(resp)
    ##############################################################################
    # Reset QoS Stack Name
    ##############################################################################
    resp = sase_session.get.prioritypolicysetstacks()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            if item["default_policysetstack"]:
                name = item["name"].replace(customer_name,"")
                item["name"] = name
                resp = sase_session.put.prioritypolicysetstacks(prioritypolicysetstack_id=item["id"], data=item)
                if resp.cgx_status:
                    print("QoS Stack name updated to {}".format(item["name"]))
                else:
                    print("ERR: Could not update QoS Stack name")
                    prisma_sase.jd_detailed(resp)
    else:
        print("ERR: Could not retrieve QoS Stack")
        prisma_sase.jd_detailed(resp)

    ##############################################################################
    # Reset QoS Set Name
    ##############################################################################
    resp = sase_session.get.prioritypolicysets()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            if customer_name in item["name"]:
                name = item["name"].replace(customer_name,"")
                item["name"] = name
                resp = sase_session.put.prioritypolicysets(prioritypolicyset_id=item["id"], data=item)
                if resp.cgx_status:
                    print("QoS Set name updated to {}".format(item["name"]))
                else:
                    print("ERR: Could not update QoS Set name")
                    prisma_sase.jd_detailed(resp)
    else:
        print("ERR: Could not retrieve QoS Sets")
        prisma_sase.jd_detailed(resp)

    ##############################################################################
    # Reset NAT Stack Name
    ##############################################################################
    resp = sase_session.get.natpolicysetstacks()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            if item["default_policysetstack"]:
                name = item["name"].replace(customer_name,"")
                item["name"] = name
                resp = sase_session.put.natpolicysetstacks(natpolicysetstack_id=item["id"], data=item)
                if resp.cgx_status:
                    print("NAT Stack name updated to {}".format(item["name"]))
                else:
                    print("ERR: Could not update NAT Stack name")
                    prisma_sase.jd_detailed(resp)
    else:
        print("ERR: Could not retrieve NAT Stack")
        prisma_sase.jd_detailed(resp)

    ##############################################################################
    # Reset NAT Set Name
    ##############################################################################
    resp = sase_session.get.natpolicysets()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            if customer_name in item["name"]:
                name = item["name"].replace(customer_name,"")
                item["name"] = name
                resp = sase_session.put.natpolicysets(natpolicyset_id=item["id"], data=item)
                if resp.cgx_status:
                    print("NAT Set name updated to {}".format(item["name"]))
                else:
                    print("ERR: Could not update NAT Set name")
                    prisma_sase.jd_detailed(resp)
    else:
        print("ERR: Could not retrieve NAT Sets")
        prisma_sase.jd_detailed(resp)
    ##############################################################################
    # Reset NGFW Stack Name
    ##############################################################################
    resp = sase_session.get.ngfwsecuritypolicysetstacks()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            if customer_name in item["name"]:
                name = item["name"].replace(customer_name,"")
                item["name"] = name
                resp = sase_session.put.ngfwsecuritypolicysetstacks(ngfwsecuritypolicysetstack_id=item["id"], data=item)
                if resp.cgx_status:
                    print("NGFW Stack name updated to {}".format(item["name"]))
                else:
                    print("ERR: Could not update NGFW Stack name")
                    prisma_sase.jd_detailed(resp)
    else:
        print("ERR: Could not retrieve NGFW Stack")
        prisma_sase.jd_detailed(resp)

    ##############################################################################
    # Reset NAT Set Name
    ##############################################################################
    resp = sase_session.get.ngfwsecuritypolicysets()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            if customer_name in item["name"]:
                name = item["name"].replace(customer_name,"")
                item["name"] = name
                resp = sase_session.put.ngfwsecuritypolicysets(ngfwsecuritypolicyset_id=item["id"], data=item)
                if resp.cgx_status:
                    print("NGFW Set name updated to {}".format(item["name"]))
                else:
                    print("ERR: Could not update NGFW Set name")
                    prisma_sase.jd_detailed(resp)
    else:
        print("ERR: Could not retrieve NGFW Sets")
        prisma_sase.jd_detailed(resp)

    ##############################################################################
    # Check if only policies need to be updates
    ##############################################################################
    if policy_only == "True":
        sys.exit()
    ##############################################################################
    # Create Site
    ##############################################################################
    if site_name not in site_name_id.keys():
        print("ERR: Site {} not found. Please select a valid site to cleanup".format(site_name))

    else:
        site_id=site_name_id[site_name]

        #
        # Cleanup Steps:
        # 1. Delete Element
        # 2. Delete SWIs from Site
        # 3. Disable Site
        # 4. Delete Site
        #

        ##############################################################################
        # Delete Element Shell
        ##############################################################################
        data = {
            "query_params": {
                "site_id": {"in": [site_id]}
            }
        }
        resp = sase_session.post.elementshells_query(data=data)
        if resp.cgx_status:
            elementshells = resp.cgx_content.get("items", None)
            print("Num Shells at Site: {}".format(len(elementshells)))

            for elemshell in elementshells:
                resp = sase_session.delete.elementshells(site_id=site_id, elementshell_id=elemshell["id"])
                if resp.cgx_status:
                    print("Element Shell: {} deleted".format(elemshell["name"]))
                else:
                    print("ERR: Could not delete Element Shell: {}".format(elemshell["name"]))
                    prisma_sase.jd_detailed(resp)

        else:
            print("ERR: Could not retrieve Element Shells")
            prisma_sase.jd_detailed(resp)


        ##############################################################################
        # Delete SWIs at Site
        ##############################################################################

        resp = sase_session.get.waninterfaces(site_id=site_id)
        if resp.cgx_status:
            waninterfaces = resp.cgx_content.get("items", None)
            for swi in waninterfaces:
                resp = sase_session.delete.waninterfaces(site_id=site_id, waninterface_id=swi["id"])
                if resp.cgx_status:
                    print("WAN Interface: {} deleted".format(swi["name"]))
                else:
                    print("ERR: Could not delete WAN Interface: {}".format(swi["name"]))
                    prisma_sase.jd_detailed(resp)
        else:
            print("ERR: Could not retrieve WAN Interfaces")
            prisma_sase.jd_detailed(resp)


        ##############################################################################
        # Disable Site
        ##############################################################################
        resp = sase_session.get.sites(site_id=site_id)
        if resp.cgx_status:
            siteobj = resp.cgx_content
            siteobj["admin_state"] = "disabled"
            resp = sase_session.put.sites(site_id=site_id, data=siteobj)
            if resp.cgx_status:
                print("Site {} Disabled".format(site_name))
            else:
                print("ERR: Could not disable Site {}".format(site_name))
                prisma_sase.jd_detailed(resp)
        else:
            print("ERR: Could not retrieve site {}".format(site_name))
            prisma_sase.jd_detailed(resp)

        ##############################################################################
        # Delete Site
        ##############################################################################
        resp = sase_session.delete.sites(site_id=site_id)
        if resp.cgx_status:
            print("Site {} Deleted!".format(site_name))
        else:
            print("ERR: Could not delete Site {}".format(site_name))
            prisma_sase.jd_detailed(resp)

    ##############################################################################
    # Get DC Site ID
    ##############################################################################
    DCSites = ["SPoV DC test", "SPoV DC2 test"]
    for dcsite in DCSites:
        if dcsite in site_name_id.keys():
            dcsite_id = site_name_id[dcsite]

            ##############################################################################
            # Delete Element Shell
            ##############################################################################
            data = {
                "query_params": {
                    "site_id": {"in": [dcsite_id]}
                }
            }
            resp = sase_session.post.elementshells_query(data=data)
            if resp.cgx_status:
                elementshells = resp.cgx_content.get("items", None)
                print("Num Shells at Site: {}".format(len(elementshells)))

                for elemshell in elementshells:
                    resp = sase_session.delete.elementshells(site_id=dcsite_id, elementshell_id=elemshell["id"])
                    if resp.cgx_status:
                        print("Element Shell: {} deleted".format(elemshell["name"]))
                    else:
                        print("ERR: Could not delete Element Shell: {}".format(elemshell["name"]))
                        prisma_sase.jd_detailed(resp)

            else:
                print("ERR: Could not retrieve Element Shells")
                prisma_sase.jd_detailed(resp)

            ##############################################################################
            # Delete SWIs at Site
            ##############################################################################
            resp = sase_session.get.waninterfaces(site_id=dcsite_id)
            if resp.cgx_status:
                waninterfaces = resp.cgx_content.get("items", None)
                for swi in waninterfaces:
                    resp = sase_session.delete.waninterfaces(site_id=dcsite_id, waninterface_id=swi["id"])
                    if resp.cgx_status:
                        print("WAN Interface: {} deleted".format(swi["name"]))
                    else:
                        print("ERR: Could not delete WAN Interface: {}".format(swi["name"]))
                        prisma_sase.jd_detailed(resp)
            else:
                print("ERR: Could not retrieve WAN Interfaces")
                prisma_sase.jd_detailed(resp)
            ##############################################################################
            # Delete Servicebinding
            ##############################################################################
            resp = sase_session.get.servicebindingmaps()
            if resp.cgx_status:
                smaps = resp.cgx_content.get("items", None)
                for smap in smaps:
                    smap["service_bindings"] = []
                    resp = sase_session.put.servicebindingmaps(servicebindingmap_id=smap["id"], data=smap)
                    if resp.cgx_status:
                        print("Servicebinding removed from {}".format(smap["name"]))

                        resp = sase_session.delete.servicebindingmaps(servicebindingmap_id=smap["id"])
                        if resp.cgx_status:
                            print("Preset Domain deleted")
                        else:
                            print("ERR: Could not delete Preset Domain")
                            prisma_sase.jd_detailed(resp)
                    else:
                        print("ERR: Could not update Preset Domain")
                        prisma_sase.jd_detailed(resp)
            else:
                print("ERR: Could not get servicebindingmaps")
                prisma_sase.jd_detailed(resp)
            ##############################################################################
            # Delete Service Endpoint
            ##############################################################################
            resp = sase_session.get.serviceendpoints()
            if resp.cgx_status:
                itemlist = resp.cgx_content.get("items", None)
                for item in itemlist:
                    if item["site_id"] == dcsite_id:
                        resp = sase_session.delete.serviceendpoints(serviceendpoint_id=item["id"])
                        if resp.cgx_status:
                            print("Serviceendpoint deleted")
                        else:
                            print("ERR: Could not delete serviceendpoints")
                            prisma_sase.jd_detailed(resp)
            else:
                print("ERR: Could not get serviceendpoints")
                prisma_sase.jd_detailed(resp)
            ##############################################################################
            # Disable DC Site
            ##############################################################################
            resp = sase_session.get.sites(site_id=dcsite_id)
            if resp.cgx_status:
                siteobj = resp.cgx_content
                siteobj["admin_state"] = "disabled"
                resp = sase_session.put.sites(site_id=dcsite_id, data=siteobj)
                if resp.cgx_status:
                    print("Site {} Disabled".format(dcsite))
                else:
                    print("ERR: Could not disable Site {}".format(dcsite))
                    prisma_sase.jd_detailed(resp)
            else:
                print("ERR: Could not retrieve site {}".format(dcsite))
                prisma_sase.jd_detailed(resp)
            ##############################################################################
            # Delete DC Site
            ##############################################################################
            resp = sase_session.delete.sites(site_id=dcsite_id)
            if resp.cgx_status:
                print("Site {} Deleted!".format(dcsite))
            else:
                print("ERR: Could not delete Site {}".format(dcsite))
                prisma_sase.jd_detailed(resp)

        else:
            print("DC Site {} not found".format(dcsite))

    ##############################################################################
    # Delete WAN Networks
    ##############################################################################
    print("Deleting WAN Networks")
    resp = sase_session.get.wannetworks()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            resp = sase_session.delete.wannetworks(wannetwork_id=item["id"])
            if resp.cgx_status:
                print("\t{} Deleted".format(item["name"]))
            else:
                print("\t{} Could not be deleted".format(item["name"]))
    else:
        print("ERR: Could not retrieve WAN Networks")
        prisma_sase.jd_detailed(resp)

    return

if __name__ == "__main__":
    go()