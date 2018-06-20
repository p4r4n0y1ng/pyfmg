## Synopsis

Represents the base components of the Fortinet FortiManager JSON-RPC interface. This code is based on the fmg_jsonapi.py code provided in the ftntlib package as provided on the Fortinet Developer Network (FNDN) that was originally written by Ashton Turpin. It has since been modified by JP Forcioli as well as several others within Fortinet. This has now been streamlined and modified to utilize the standard **\**kwargs** functionality as well as has been modified extensively to be more scalable and provide context management and other aspects.

## Code Example

Standard format for a FortiManager JSON-RPC is utilized.

**Of Importance** is that this package uses context behavior for the FortiManager instance, so the **with** keyword can be utilized. This ensures that the FortiManager instance is logged into upon instantiation and is logged out of once the scope of the **with** statement is completed. For instance, to instantiate a FortiManager instance with the IP address of 10.1.1.1, with the user name admin and a password of <blank>, the user would simply type:

```
with FortiManager('10.1.1.1', 'admin', '') as fmg_instance:
```

The context manager does not HAVE to be utilized obviously. However, if it is not utilized, the *login* and *logout* functionality is not handled for the caller. It is expected that these methods will be called if the context manager is not utilized. An example would be:

```
fmg_instance = FortiManager('10.1.1.1', 'admin', '')
fmg_instance.login()
*something of importance accomplished here*
fmg_instance.logout()
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

Obviously these same parameters would be used in the standard call if the context manager is not utilized so:

```
fmg_instance = FortiManager('10.1.1.1', 'admin', '', debug=True, use_ssl=False, debug=True, disable_request_warnings=False, timeout=100)
```

A solution has been provided to ensure workspace mode can be handled. When a FMG instance is created, either using the **with** statement as shown above or in a standard scenario (also shown above), the instance checks the FMG for status. At login a call is made to check for status and if *workspace-mode* is returned as anything other than a **0** then workspace capabilities are provided. Standard calls to *lock*, *commit*, and *unlock* are required and are passed through to the workspace manager object for ease of use. If a caller is using the context manager, the workspace manager will now ensure an errant exception does not leave an ADOM stranded in a locked state. The workspace manager functionality will **NOT** call an automatic *commit*, it will simply ensure the *unlock_adom* function is called on any locked ADOM and then will logout. This happens in *logout*, thus a caller could lock an ADOM (or multiple ADOMs), do his work, call *commit* on any ADOM he wants to commit, and then simply call *logout* and then the workspace manager will take care of the unlocks. A common example (using an explicit call to *unlock_adom*) to add an address object might be:

```
fmg_instance.lock_adom("root")
fmg_instance.add('pm/config/adom/{adom}/obj/firewall/address'.format(adom="root"), allow__routing=0, associated__interface='any', name='add_obj_name', subnet=["192.168.1.0", "255.255.255.0"], type=0, comment='API address obj addition')
fmg_instance.commit_changes("root")
fmg_instance.unlock_adom("root")
fmg_instance.logout()
```
The following would perform the same and would also unlock the *root* ADOM on the way out (notice no call to *unlock_adom is required here):

```
fmg_instance.lock_adom("root")
fmg_instance.add('pm/config/adom/{adom}/obj/firewall/address'.format(adom="root"), allow__routing=0, associated__interface='any', name='add_obj_name', subnet=["192.168.1.0", "255.255.255.0"], type=0, comment='API address obj addition')
fmg_instance.commit_changes("root")
fmg_instance.logout()
```

While this module is meant to be utilized with another caller-written abstraction, there is no reason that this module could not be utilized by itself to make detailed, multi-parameter calls. To that end, a capability has been provided that enables keyword/value arguments to be passed into any of the *get*, *add*, *update* ,*delete* ,*set* ,*replace* ,*clone* ,*execute* , or *move* helper methods. Since there are many keywords in the FortiManager body that require a dash (and since the dash character is not allowed as a keyword argument handled by the **\**kwargs** pointer), a facility has been added such that a keyword with a double underscore **__** is automatically translated into a dash **-** when the keyword/value pair is put into the body of the call. An example follows (notice the double underscores in the keyword items, these will be translated to dashes when the call is made):

```
fmg_instance.add('pm/config/adom/{adom}/obj/firewall/address'.format(adom="root"), allow__routing=0, associated__interface='any', name='add_obj_name', subnet=["192.168.1.0", "255.255.255.0"], type=0, comment='API address obj addition')
```
This facility is helpful, but a more obvious way to make these kind of calls with a little more clarity is shown below in the **Tests** section where a standard dictionary is utilized effectively. In that case, the double underscore translations are not needed and dashes will work perfectly fine (see below).

####Exceptions
Exceptions are allowed to propogate up to the caller and are only caught in certain cases where they will be needed in case verbose mode is asked for and the caller wants a print out of the exception. After the print is accomplished that same exception will be raised and propogated so it can be either caught and handled by the caller or used as a debug tool.

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
