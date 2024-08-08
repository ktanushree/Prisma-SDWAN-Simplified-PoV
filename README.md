## Simplified PoV Configuration Scripts
These are scripts for configuring Prisma SDWAN branch sites and policies on tenants spun up for Simplified PoV.

The script will refer to the [prismasase_settings.py](https://bitbucket.paloaltonetworks.local/projects/CGTME/repos/spov/browse/prismasase_settings.py.example) file for details on how the SDWAN brnach must be configured.
Configuration parameters like device model, site name, HA, circuit provider, interface details can all be provided via the **prismasase_settings.py** file. Default values are included in the prismasase_settings.py file, which the users can choose to override. 

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

3. Provide the Branch Topology details like site name, device model, number of circuits, HA etc.
4. Execute the **setup_spov_prisma_sdwan.py** script
```angular2html
./setup_spov_prisma_sdwan.py
```
To run command on the QA environment, provide the QA controller URL.
```angular2html
./setup_spov_prisma_sdwan.py -C https://qa.api.sase.paloaltonetworks.com
```

5. To delete a site deployed using the above script, you can use the **cleanup.py** script.
```angular2html
./cleanup.py -S <sitename>
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
(base) TanushreeMacbook:spov tkamath$ ./setup_spov_prisma_sdwan.py -h
usage: setup_spov_prisma_sdwan.py [-h] [--controller CONTROLLER]

Prisma SD-WAN Simplified PoV Setup.

optional arguments:
  -h, --help            show this help message and exit

Config:
  Configuration Details for PoV

  --controller CONTROLLER, -C CONTROLLER
                        Controller URL
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
| **1.0.0** | **b1** | Initial Release |
