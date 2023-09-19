## Synopsis

Represents the base components of the Fortinet FortiManager JSON-RPC interface. Written and maintained by the Fortinet North America CSE Team. This code is based on the fmg_jsonapi.py code provided in the ftntlib package as provided on the Fortinet Developer Network (FNDN). That code has since been modified by JP Forcioli as well as several others within Fortinet. This has now been streamlined and modified to utilize the standard **\**kwargs** functionality as well as has been modified extensively to be more scalable and provide context management and other aspects.
## Code Example

Standard format for a FortiManager JSON-RPC is utilized.

**Of Importance** is that this package uses context behavior for the FortiManager instance, so the **with** keyword 
can be utilized. This ensures that the FortiManager instance is logged into upon instantiation and is logged out of 
once the scope of the **with** statement is completed. For instance, to instantiate a FortiManager instance with the 
IP address of 10.1.1.1, with the user name admin and a password of <blank>, the user would simply type:

```
with FortiManager('10.1.1.1', 'admin', '') as fmg_instance:
```

The context manager does not HAVE to be utilized obviously. However, if it is not utilized, the *login* and *logout* 
functionality is not handled for the caller. It is expected that these methods will be called if the context manager 
is not utilized. An example would be:

```
fmg_instance = FortiManager('10.1.1.1', 'admin', '')
fmg_instance.login()
*something of importance accomplished here*
fmg_instance.logout()
```

Continuing, when a FortiManager instance is instantiated, the following attributes are configured (or can be 
configured by the user). The list provided lists the defaults.

```
- debug (default False),
- use_ssl (default True),
- verify_ssl (default False),
- timeout (default 300),
- check_adom_workspace (default True)
```

For instance, to instantiate a FortiManager instance with the IP address of 10.1.1.1, with the username admin and a 
password of <blank>, that uses http instead of https, is in debug mode, and warns after the verification of the SSL 
certificate upon each request, has a timeout of 100 and doesn't perform the automated checks for ADOM use and 
Workspace mode the user would simply type:

```
with FortiManager('10.1.1.1', 'admin', '', debug=True, use_ssl=False, disable_request_warnings=False, timeout=100, check_adom_workspace=False) as fmg_instance:
```

The *check_adom_workspace* option was added to speed up login for those users that don't care about Workspace Mode 
or having a notification and tracking if ADOMs are used. A clear example of when to set *check_adom_workspace* to 
False would be a FMG with only the root ADOM or something like the Cloud FMG which at the time of this writing 
didn't support the use of ADOMs. The login process is significantly faster when *check_adom_workspace* is False

Obviously these same parameters would be used in the standard call if the context manager is not utilized so:

```
fmg_instance = FortiManager('10.1.1.1', 'admin', '', debug=True, use_ssl=False, disable_request_warnings=False, timeout=100, check_adom_workspace=False)
```

With the release of FMG 7.2.2 an API User can be created with an API Key (THANK ALL THINGS GOOD!)
The feature works very much like it does in FOS and is very helpful. However, it clearly calls for a different way 
to login. We have modified pyFMG so the interface stays very close to the "standard" way you've done things. 
Basically you will do the following if you're using an API Key. Let's assume that you want to put the API Key in a 
variable and use that in your login. For a context manager setup you would do the following:

```
api_key = "reallylongfakeapikeyireceivedfromfmg"
fmg_instance = FortiManager('10.1.1.1', apikey=api_key) as fmg_instance:
```

pyFMG takes this information and creates a "session" key just as if you are logging in the old way. That session 
information is randomly generated and then appended to a dash and the last 4 digits of your API Key. This is for 
those people who need to track session information (particularly those of you who are threading/multiprocessing etc.)

For instance, if you're in debug mode and watching your output you'll see something like

```
"session": "8862b4d9-256b-43a5-bc2a-71d330978a6b-mfmg"
```

Notice the "mfmg" there. Again, this will make it where you can track things if needed. If you're not tracking by 
session, this really doesn't matter to you. However, it's there for those that need it.

If you don't use a context manager, then you do the same basic thing as before...except clearly this time you will 
use your API Key and not the user, password combo. For instance:

```
api_key = "reallylongfakeapikeyireceivedfromfmg"
fmg_instance = FortiManager('10.1.1.1', apikey=api_key)
fmg_instance.login()
*something of importance accomplished here*
fmg_instance.logout()
```

Notice that login() is still called and still must be used, despite that there really is no initial login. This is 
so the session can be created and maintained and ensures a consistent interface. The attributes of debug, use_ssl, 
verify_ssl, timeout and check_adom_workspace remain and can be called in the login area itself or set the same as 
before. Nothing has changed in this area.


The ability to login to FMG Cloud instances has been added to pyFMG. 
These instances have a URL of {numbers}.{location}.fortimanager.forticloud.com. When pyFMG sees the "fortimanager.
forticloud.com" moniker it maintains a value to ensure proper login functionality for FortiCloud portal and assets. 
Information can be found here: https://docs.fortinet.com/document/forticloud/23.3.0/identity-access-management-iam/703535/introduction  

In summary the value is kept and login is sent initially with the username and password as discussed above. However, 
an access token is given back after initial login and then a session is established with that token. Once the 
session is provided back to pyFMG the session identifier is set as discussed above and the process continues. pyFMG 
does not currently work with 2FA in this setup but that will be added if the requirement is levied by multiple users 
of the tool. To login to the FortiCloud instance the process looks very much the same as above. This example will 
utilize the context manager, but without the context manager the login() and logout() function is used as already 
explained.

```
with FortiManager('{numbers}.{location}.fortimanager.forticloud.com', 'admin', '', debug=True, check_adom_workspace=False) as fmg_instance:
```

The OAuth process, to include getting the token and passing it to the portal for a session, is transparent to the pyFMG 
user. pyFMG sends a call to revoke the OAuth token once a session is established with the FMG so that the token 
cannot be abused between its creation and timeout.

**As a note for those of you that have helped me with this project, If more logins become necessary pyFMG may change 
this concept to a decorator type so many more login functions can be added as required.**

A solution has been provided to ensure workspace mode can be handled. (See above on the *check_adom_workspace* 
option to turn this off).

When a FMG instance is created, either using the **with** statement as shown above or in a standard scenario (also 
shown above), the instance checks the FMG for status. At login a call is made to check for status and if 
*workspace-mode* is returned as anything other than a **0** then workspace capabilities are provided.  Standard calls 
to *lock*, *commit*, and *unlock* are required and are passed through to the workspace manager object for ease of 
use. If a caller is using the context manager, the workspace manager will now ensure an errant exception does not 
leave an ADOM stranded in a locked state. The workspace manager functionality will **NOT** call an automatic 
*commit*, it will simply ensure the *unlock_adom* function is called on any locked ADOM and then will logout. This 
happens in *logout*, thus a caller could lock an ADOM (or multiple ADOMs), do his work, call *commit* on any ADOM he 
wants to commit, and then simply call *logout* and then the workspace manager will take care of the unlocks. A 
common example (using an explicit call to *unlock_adom*) to add an address object might be:

```
fmg_instance.lock_adom("root")
fmg_instance.add('pm/config/adom/{adom}/obj/firewall/address'.format(adom="root"), allow__routing=0, associated__interface='any', name='add_obj_name', subnet=["192.168.1.0", "255.255.255.0"], type=0, comment='API address obj addition')
fmg_instance.commit_changes("root")
fmg_instance.unlock_adom("root")
fmg_instance.logout()
```
The following would perform the same and would also unlock the *root* ADOM on the way out (notice no call to 
*unlock_adom* is required here):

```
fmg_instance.lock_adom("root")
fmg_instance.add('pm/config/adom/{adom}/obj/firewall/address'.format(adom="root"), allow__routing=0, associated__interface='any', name='add_obj_name', subnet=["192.168.1.0", "255.255.255.0"], type=0, comment='API address obj addition')
fmg_instance.commit_changes("root")
fmg_instance.logout()
```

While this module is meant to be utilized with another caller-written abstraction, there is no reason that this 
module could not be utilized by itself to make detailed, multi-parameter calls. To that end, a capability has been 
provided that enables keyword/value arguments to be passed into any of the *get*, *add*, *update* ,*delete* ,*set* ,
*replace* ,*clone* ,*execute* , or *move* helper methods. Since there are many keywords in the FortiManager body 
that require a dash (and since the dash character is not allowed as a keyword argument handled by the **\**kwargs** 
pointer), a facility has been added such that a keyword with a double underscore **__** is automatically translated 
into a dash **-** when the keyword/value pair is put into the body of the call. An example follows (notice the 
double underscores in the keyword items, these will be translated to dashes when the call is made):

```
fmg_instance.add('pm/config/adom/{adom}/obj/firewall/address'.format(adom="root"), allow__routing=0, associated__interface='any', name='add_obj_name', subnet=["192.168.1.0", "255.255.255.0"], type=0, comment='API address obj addition')
```

Another addition to this concept has been added which is when FortiManager requires an attribute with a space between two words. Since this is not allowed, a facility has been added such that a keyword with a triple underscore **___** is automatically translated into a blank space when the keyword/value pair is put into the body of the call. An example follows (notice the triple underscores in the keyword items, these will be translated to spaces when the call is made):

```
fmg_instance.add('pm/config/adom/{adom}/obj/firewall/address'.format(adom="root"), fake___attribute='any', name='add_obj_name', subnet=["192.168.1.0", "255.255.255.0"], type=0, comment='API address obj addition')
```

These facilities are helpful, but a more obvious way to make these kind of calls with a little more clarity is shown below in the **Tests** section where a standard dictionary is utilized effectively. In that case, the double underscore translations are not needed and dashes will work perfectly fine (see below). The same holds true for spaces within an attribute when using the free-form method.

## Exceptions

The module provides the following exceptions for use:

1. FMGBaseException(Exception)
2. FMGValidSessionException(FMGBaseException)
3. FMGValueError(ValueError)
4. FMGResponseNotFormedCorrect(KeyError)
5. FMGConnectionError(ReqConnError)
6. FMGConnectTimeout(ReqConnTimeout)
7. FMGRequestNotFormedCorrect(FMGBaseException)
8. FMGOAuthTokenError(FMGBaseException)

**FMGBaseException** is the Base exception for the module and can be used to catch all things outside of the ValueError and Keyerror issues.

a caller could then write the following and have the equivalent of a standard *except* call with no exception mentioned. This ensures scalability:
```
try:
    Doing Something Here
except FMGBaseException:
    Do something with Exception
```

**FMGValidSessionException** has been added and is raised if any call is attempted without a valid connection being made to a FMG. In the past, other than to check the \_\_str()\_\_ value of the object after the login return, the code would continue to try to make calls despite having no valid session. Any call attempted now on an invalid session will have this error thrown.

**FMGValueError** is a standard ValueError and is caught in special cases where a connection attempt is made or a call is made with an invalid value. An example of this would be a connection to a FMG instance with a *timeout* value of <= 0.

**FMGResponseNotFormedCorrect** will be raised when response received back from the FMG instance does not have a *result*, *status*, or *code* attribute. FMG responses without these attributes are ill-formed and will raise this error. The only exception to this is the response from a valid *login()* call. This exception is suppressed for this, and a valid response is crafted for login to ensure a stable, standard, and constant response back from the module.

**FMGConnectionError** and **FMGConnectTimeout** are raised when a *requests.exception.ConnectionError* or *requests.exceptions.ConnectTimeout* exception is caught. This ensures calling code does not need to import/depend on the requests module to handle requests connection exceptions. *FMGConnectionError* will most likely be thrown at *login()* and are likely due to an incorrect hostname, or IP Address of the FMG appliance.

**FMGRequestNotFormedCorrect** will be raised when a request for free form capability is issued and the request format is not correct. Specifically a *data* keyword is required to be passed in and the value must be a dictionary. See the ```free_form()``` method explanation below

**FMGOAuthTokenError** is raised when a *json.JSONDecodeError* exception is caught during a login attempt which currently will only happen during the OAuth action.

Exceptions are allowed to propogate up to the caller and are only caught in certain cases where they will be needed in case verbose mode is asked for and the caller wants a print out of the exception. After the print is accomplished that same exception will be raised and propogated so it can be either caught and handled by the caller or used as a debug tool.

## Special Keywords

This section outlines special keywords that will be used within \*\*kwargs that will mean something significant to pyFMG. These keywords, when used by the caller will be checked and will provided special circumstances to the pyFMG calls as there are quite a few special reqiurements when dealing with the FortiManager.

The *data* keyword - utilizing arrays instead of JSON objects in the params section of the request object.

This case is required when an array of objects is needed vice a JSON object with possibly arrays or other objects inside it. An example of this would be a request that needs to look like the following:
```
{
  "id": 1, 
  "method": "add", 
  "params": [
    {
      "data": [
        "membername1", 
        "membername2"
      ], 
      "url": "pm/config/adom/root/obj/firewall/addrgrp/test_addr_group/member"
    }
  ], 
  "session": "BLAH"
}
```

Notice that the params attribute is holding a data attribute that is an array of items vice the standard JSON object as normally required. To utilize this functionality, the caller will provide a keyword of *data* in the call with the array of information as its value. The call would look like:

```
fmg_instance.add("pm/config/adom/root/obj/firewall/addrgrp/test_addr_group/member", data=["membername1", "membername2"])
```

Any and all keywords past the data keyword will be disregarded.

## Responses

A standard, response mechanism is provided from this module so calling objects know what to expect back. Unless an exception is thrown, this module will return a 2 object tuple consisting of the code of the response back, followed by the information in the *"data"* attribute within the response. If there's no data attribute in the response, the text of the response is provided. Since login does not provide a constant response from a FMG appliance, one is provided by this module to ensure a caller knows what will be returned and in what format. An example response of a login, get call, and then logout process is below:

```
(0, {'status': {'message': 'OK', 'code': 0}, 'url': 'sys/login/user'})
(0, [{u'faz.quota': 0, u'foslic_ram': 0, u'foslic_type': 0, u'sn': u'FGVM020000098115', u'mr': 6, u'conf_status': 1, u'os_type': 0, u'node_flags': 0, u'os_ver': 5, ...(truncated)}])
(0, {u'status': {u'message': u'OK', u'code': 0}, u'url': u'sys/logout'})
``` 

Notice the the login response (the first response above) is NOT unicode. Other than that it matches exactly with other call responses.

## Special Functions

When an operation is sent to the FMG that in return kicks off a task on the sytem (i.e. device config installation, policy package push, etc...) the return value is as discussed where a tuple with the return code and the return json value is provided. In this case, the JSON value will have a task identifier attribute and can be used to track that task. This module provides a simple track tasking functionality called ```track_task()``` that takes in a *task_id* integer and then optional values for *sleep_time* (default is 5 seconds) between requests, *retrieval_fail_gate* (default is 10) and a *timeout* (default is 120). This provides a looped response for that task that with the defaults allows for the system to take approx a minute to respond - this value is a very long time, so we are certain that if the system does not respond by then something is wrong. The loop requests information from the system about the task every 5 seconds and give the system over 2 minutes to complete prior to giving a response that the task is taking too long. This function allows the capability of getting a task and then watching the values - as well as pivoting off of the rich data the FMG responds with to include number of lines that were completed, any errors or warnings, completion time and more. The system also adds in an attribute to the response data on the completion cycle named **total_task_time** which is the time it took for the task to complete its actions. A way to call and use this function is as follows:

```
code, task_obj = fmg_instance.execute("securityconsole/install/package", flags=["preview"], adom="root", pkg=pp_name)
if 'task' in task_obj:
    taskid = task_obj.get('task')
    fmg_instance.track_task(taskid)
```

An execution function outside of the standard *get*, *add*, *update*, *delete*, *set*, *replace*, *clone*, *execute*, or *move* has been added. This function is called ```free_form(method, **kwargs)```. The arguments are the string method that must be called such as *add* or *get*, etc... and a key word argument list. The kw argument must be a dictionary that has the key **data** or a *FMGRequestNotFormedCorrect* exception will be raised. This data keyword must have the exact value you want to send to the FMG. This function is used for when either the FMG Request object is slightly different than standard OR you are trying to call the FMG with multiple operations. For instance, you want to add 3 address objects with one call. In order to do something like this, the ```free_form()``` function is used and called as below where we are requesting all data from policy id's 1, 3, 4, 5, and 7 with one call:

```
multi_data = []
for pol_id in [1, 3, 4, 5, 7]:
    multi_data.append({
            "url": f"/pm/config/adom/root/pkg/default/firewall/policy/{pol_id}",
            "fields": ["policyid", "name"],
          })

if len(multi_data) > 0:
    code, res = fmg_instance.free_form("get", data=multi_data)
``` 

## Logging

A logging functionality has been provided to enable logging to different handlers as required by the caller using the standard python logging facility. The capability to start logging is simply by calling the *getLog* function. This function returns the internal logging reference held by the FortiGate instance. To add or remove a handler use the associated *addHandler()* or *removeHandler()* functions providing a FileHandler or StreamHandler etc... object. The signature for the *getLog()* function is:

```
def getLog(self, loggername="fortinet", lvl=logging.INFO)
``` 

Once a logger is created by calling the *getLog* function, the logger will log the debug information to whatever handler was provided to the *addHandler()* function. If more than one handler is added, more than one log will occur. To stop logging simply use the *resetLog()* function and the Logging object will be set to None. An example of how to log all debug output to a file would be:

```
fmg.getLog(loggername="fmg")
fh = logging.FileHandler("/location/to/log/fil.log")
fh.setLevel(logging.INFO)
fh.setFormatter(logging.Formatter("%(asctime)s - %(name)s: %(message)s ", "%m/%d/%Y %I:%M:%S %p"))
fgt.addHandler(fh)
```

An external module can utilize standard logging functionality to provide a subordinate type logging function using the same handlers as provided to the pyFGT module. For instance, to log to the same location as the pyFGT module logs Handler is set, you would simply have to do the following:

```
fmg_logger = logging.getLogger("fmg.drvr")

# somewhere in the module
fmg_logger.log(logging.INFO, "This is a log message)
```

The log output in this case would have the fgt.drvr moniker in the format header due to the use of the *%(name)s* format string shown above.

## Motivation

This package is being established to support Ansible requirements and proper mod_utils utilization, however, it can be utilized for contact with any Fortinet FortiManager appliance or VM asset. 

## Installation

Installation of this package will be via the pip interface

## Tests

Utilizing the library is relatively simple.

Assuming you are within the with context and still using **fmg_instance** as before, to get all managed devices in 
the **root** adom, the following would be used:

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

Notice how the **data** dictionary is created and then sent in as **\**data**. This is because there are dashes in 
the keys of the dictionary that is required and dashes are not allowed in a keyword argument setup. For instance, 
let's assume that **allow-routing** and **associated-interface** are not required for this call. In that case, the 
call could have been:

```
fmg_instance.add(URL to add address object for FortiManager version, name='test_addr_object', subnet=['10.1.1.0', '255.255.255.255'],type=0)
```

Notice that all you have to do is send in the data that needs to be sent to the FortiManager appliance in the **\**kwargs** field - this makes calls extremely simple - send in a URL and the keyword arguments and the rest is taken care of.