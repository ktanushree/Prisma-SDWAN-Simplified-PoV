#!/usr/bin/env python

"""
Script to setup Prisma SDWAN Simplified PoV
Author: tkamath@paloaltonetworks.com
Version: 1.0.0b2
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

    #############################################################################
    # Parse arguments.
    #############################################################################
    args = vars(parser.parse_args())
    controller = args["controller"]
    site_name = args["site_name"]

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
    if "SPoV DC" in site_name_id.keys():
        dcsite_id = site_name_id["SPoV DC"]
    else:
        print("DC Site not found")
        return

    ##############################################################################
    # Delete Servicebinding
    ##############################################################################
    resp = sase_session.get.servicebindingmaps()
    if resp.cgx_status:
        smaps = resp.cgx_content.get("items", None)
        for smap in smaps:
            if smap["name"] == "Preset Domain":
                smap["service_bindings"] = []
                resp = sase_session.put.servicebindingmaps(servicebindingmap_id=smap["id"], data=smap)
                if resp.cgx_status:
                    print("Servicebinding removed from Preset Domain")

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
    # Delete DC Site
    ##############################################################################
    resp = sase_session.delete.sites(site_id=dcsite_id)
    if resp.cgx_status:
        print("Site SPoV DC Deleted!")
    else:
        print("ERR: Could not delete Site SPoV DC")
        prisma_sase.jd_detailed(resp)

    return

if __name__ == "__main__":
    go()