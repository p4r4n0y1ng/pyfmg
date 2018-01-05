## Synopsis

Represents the base components of the Fortinet FortiManager JSON-RPC interface. This code is based on the fmg_jsonapi.py code provided in the ftntlib package as provided on the Fortinet Developer Network (FNDN) that was originally written by Ashton Turpin. It has since been modified by JP Forcioli as well as several others within Fortinet. This has now been streamlined and modified to utilize the standard **\**kwargs** functionality as well as has been modified extensively to be more scalable and provide context management and other aspects.

## Code Example

Standard format for a FortiManager JSON-RPC is utilized.

**Of Importance** is that this package uses context behavior for the FortiManager instance, so the **with** keyword can be utilized. This ensures that the FortiManager instance is logged into upon instantiation and is logged out of once the scope of the **with** statement is completed. For instance, to instantiate a FortiManager instance with the IP address of 10.1.1.1, with the user name admin and a password of <blank>, the user would simply type:

```
with FortiManager('10.1.1.1', 'admin', '') as fmg_instance:
```
Continuing, when a FortiManager instance is instantiated, the following attributes are configured (or can be configured by the user). The list provided lists the defaults.

```
- debug (default False),
- use_ssl (default True),
- verify_ssl (default False),
- timeout (default 300)
```
For instance, to instantiate a FortiManager instance with the IP address of 10.1.1.1, with the user name admin and a password of <blank>, that uses http instead of https, is in debug mode, and warns after the verification of the SSL certificate upon each request and has a timeout of 100 the user would simply type:

```
with FortiManager('10.1.1.1', 'admin', '', debug=True, use_ssl=False, debug=True, disable_request_warnings=False, timeout=100) as fmg_instance:
```

## Motivation

This package is being established to support Ansible requirements and proper mod_utils utilization, however, it can be utilized for contact with any Fortinet FortiManager appliance or VM asset. 

## Installation

Installation of this package will be via the pip interface

## Tests

Utilizing the library is relatively simple.

Assuming you are within the with context and still using **fmg_instance** as before, to get all managed devices in the **root** adom, the following would be used:

```
fmg_instance.get(url to get devices for FortiManager version)
```

To **add** an address group the following would be used:

```
data = {
            'allow-routing': 1,
            'associated-interface': 'any',
            'name': 'test_addr_object',
            'subnet': ['10.1.1.0', '255.255.255.255'],
            'type': 0,
        }
        fmg_instance.add(URL to add address group objects for FortiManager version, **data)
```

Notice how the **data** dictionary is created and then sent in as **\**data**. This is because there are dashes in the keys of the dictionary that is required and dashes are not allowed in a keyword argument setup. For instance, let's assume that **allow-routing** and **associated-interface** are not required for this call. In that case, the call could have been:

```
fmg_instance.add(URL to add address object for FortiManager version, name='test_addr_object', subnet=['10.1.1.0', '255.255.255.255'],type=0)
```

Notice that all you have to do is send in the data that needs to be sent to the FortiManager appliance in the **\**kwargs** field - this makes calls extremely simple - send in a URL and the keyword arguments and the rest is taken care of.
