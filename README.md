## Simplified PoV Configuration Scripts
These are scripts for configuring Prisma SDWAN branch sites and policies on tenants spun up for Simplified PoV.

The script will refer to the CSV file provided by user for configuration details. The CSV is auto-generated once the SPOV Google form is filled out.
Credentials to access the Prisma SDWAN Controller need to be stored in [prismasase_settings.py](https://bitbucket.paloaltonetworks.local/projects/CGTME/repos/spov/browse/prismasase_settings.py.example).

### Usage
To configure the Simplified PoV tenant:
1. Create a Service Account and assign it SuperUser access to the Prisma SDWAN App
2. Save the Service Account details in the **prismasase_settings.py** file
```angular2html
######################################################
# Service Account
######################################################
PRISMASASE_CLIENT_ID="client_id"
PRISMASASE_CLIENT_SECRET="client_secret"
PRISMASASE_TSG_ID="tsg_id"
```

3. Download the CSV file with the configuration details as provided in the Google Form. 

Important Note: If using a bypasspair interface, please prefix the interface name with the string **_bypass__** i.e. **bypass_< wanport >< lanport>** in the google form. Eg: for bypasspair 34, the interface name in the form should be **bypass_34**. 
- Port 3 will be configured as the WAN port
- Port 4 will be configured as the LAN port

5. Execute the **setup_prismasdwanspov.py** script
```angular2html
./setup_prismasdwanspov.py -F <csvfilename>
```
To run command on the QA environment, provide the QA controller URL.
```angular2html
./setup_prismasdwanspov.py -C https://qa.api.sase.paloaltonetworks.com -F <csvfilename>
```

5. To delete a site deployed using the above script, you can use the **cleanup.py** script.
```angular2html
./cleanup.py -S <site_name> -CN <customer_name>
```
This deletes the device shells, circuits, disables the site and then deletes the site object.


### Requirements
* Active Prisma SD-WAN Account
* Python >=3.6
* Python modules:
  * Prisma SASE Python SDK >= 6.2.3b1 - <https://github.com/PaloAltoNetworks/prisma-sase-sdk-python>

### License
MIT

### Installation:
 - **Github:** Download files to a local directory, manually run the scripts


### Help Text:
#### setup_spov_prisma_sdwan.py
```
(base) TanushreeMacbook:spov tkamath$ ./setup_prismasdwanspov.py -h
usage: setup_prismasdwanspov.py [-h] [--controller CONTROLLER]
                                [--filename FILENAME]

Prisma SD-WAN Simplified PoV Setup.

optional arguments:
  -h, --help            show this help message and exit

Config:
  Configuration Details for PoV

  --controller CONTROLLER, -C CONTROLLER
                        Controller URL
  --filename FILENAME, -F FILENAME
                        File containing configuration detail. Provide the full
                        path
(base) TanushreeMacbook:spov tkamath$ 
```

#### cleanup.py
```
(base) TanushreeMacbook:spov tkamath$ ./cleanup.py -h
usage: cleanup.py [-h] [--controller CONTROLLER] [--site_name SITE_NAME]

Prisma SD-WAN Simplified PoV Setup.

optional arguments:
  -h, --help            show this help message and exit

Config:
  Configuration Details to clean up PoV lab

  --controller CONTROLLER, -C CONTROLLER
                        Controller URL
  --site_name SITE_NAME, -S SITE_NAME
                        Name of the Site
(base) TanushreeMacbook:spov tkamath$ 

```


## Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b13** | Fixed naming convention for policies, LAN zone binding and DC naming convention |
|           | **b12** | Updated LAN-Rtr IP for BYOS |
|           | **b11** | Bug fixes, updated policy set names with Customer name, updated cleanup to rename sets |
|           | **b10** | Bug fixes, Support for 7108v, Updated Policy Stack naming convention |
|           | **b9** | Bug fixes, BYOS: BGP peers for DC & Branch |
|           | **b8** | Bug fixes, BYOS DC set to active |
|           | **b7** | Bug fixes, Support for BYOS switch, cleanup updated for BYOS |
|           | **b6** | Bug fix for zone binding error |
|           | **b5** | Bug fixes. Validate ION software version |
|           | **b4** | Bug fixes. Added enhancement to handle bypass pair ports. See Important Note for details |
|           | **b3** | Added script **setup_prismasdwanspov.py** that configures based on data provided via CSV. Moved older scripts to folder **config_scripts_v1**  |
|           | **b2** | Added support for static IP configuration |
|           | **b1** | Initial Release |
