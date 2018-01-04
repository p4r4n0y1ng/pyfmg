## Synopsis

Represents the base components of the Fortinet FortiManager JSON-RPC interface.

## Code Example

Standard format for a FortiManager JSON-RPC is as follows:
```
{
  "method": "get|add|update|set|delete|replace|clone|exec|move",
  "params": [ ... ],
  "session": "...",
  "id": 1,
}
```        
The *method* *id* and *session* attributes are abstracted and are not required to be submitted by the calling class. As the calling code calls the 'get, add, delete, execute, etc...' operation, this abstraction fills in the correct *method* value as required.

The *session* attribute is filled in after each response object is received and thus carried over for subsequent calls.

The *id* field is also provided in the call and can be used to track calls based on each REQUEST.

The *params* attribute is where the FortiManager gets the standard 'data' that it requires to fulfill a request.
Therefore most of what is required for the FortiManager to have the appropriate information for an API call, is
a JSON object in the appropriate format provided in the *params* attribute. However, the outside portion of
this call (*method*, *id*, and *session* attributes) are also required. For the sake of allowing changes in future
code, this package utilizes the python **\**kwargs** parameter for the params input. The **\*args** parameter is included throughout the package, but is only added for future expansion and is not utilized currently.

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
fmg_instance.get('/dvmdb/adom/root/device')
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
        fmg_instance.add('pm/config/adom/root/obj/firewall/address', **data)
```

Notice how the **data** dictionary is created and then sent in as **\**data**. This is because there are dashes in the keys of the dictionary that is required and dashes are not allowed in a keyword argument setup. For instance, let's assume that **allow-routing** and **associated-interface** are not required for this call. In that case, the call could have been:

```
fmg_instance.add('pm/config/adom/root/obj/firewall/address', name='test_addr_object', subnet=['10.1.1.0', '255.255.255.255'],type=0)
```

Notice that all you have to do is send in the data that needs to be sent to the FortiManager appliance in the **\**kwargs** field - this makes calls extremely simple - send in a URL and the keyword arguments and the rest is taken care of.
