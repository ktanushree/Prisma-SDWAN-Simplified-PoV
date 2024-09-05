######################################################
# Branch Topology
######################################################
SITE_NAME="Model_1200S_DualInternet_HA"
ADDRESS_CITY="New York"
ADDRESS_COUNTRY="United States"

#
# Optional
#
ADDRESS_STREET=""
ADDRESS_STATE=""
ADDRESS_ZIPCODE=""
ADDRESS_LATITUDE="40.7127492"
ADDRESS_LONGITUDE="-74.0059945"

#
# MODEL - Allowed values: 1200S, 3200, 5200
#
BRANCH_MODEL="1200S"

#
# HA - Allowed values: True, False
#
HA=True
######################################################
# Circuit Configuration
######################################################
#
# Internet Circuit
#
NUM_INTERNET=2

PRIMARY_INTERNET_CATEGORY="Primary Internet"
PRIMARY_INTERNET_PROVIDER="AT&T"
PRIMARY_INTERNET_CIRCUITNAME="Primary Internet Circuit"

SECONDARY_INTERNET_CATEGORY="Secondary Internet"
SECONDARY_INTERNET_PROVIDER="Verizon"
SECONDARY_INTERNET_CIRCUITNAME="Secondary Internet Circuit"
#
#  Private WAN Circuit
#
NUM_PRIVATE=0

PRIVATEWAN_CATEGORY="MPLS"
PRIVATEWAN_PROVIDER="Verizon"
PRIVATEWAN_CIRCUITNAME="MPLS Circuit"
######################################################
# Interface Configuration
######################################################
PRIMARY_INTERNET_INTERFACE="1"
SECONDARY_INTERNET_INTERFACE="34"
PRIVATEWAN_INTERFACE=""
LAN_INTERFACE="5"
######################################################
# LAN Configuration
######################################################
VLAN_IDS = {
    510: "HA",
    520: "GUEST",
    530: "VOICE",
    540:"DATA"
}
######################################################
# Optional Policy Configuration
######################################################
DEFAULT_NETWORK_STACK_NAME=""
DEFAULT_PRIORITY_STACK_NAME=""
DEFAULT_SECURITY_STACK_NAME=""
