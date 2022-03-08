# wmic.py drop-in replacement for check_wmi_plus.pl

As some of you may have noticed, the good old wmic command line utility on Linux does no longer meet the required security level from MS.

This leads to annoying eventlog error messages:
```
The server-side authentication level policy does not allow the user DOMAIN\user from address 127.0.0.1 to activate DCOM server. 
Please raise the activation authentication level at least to RPC_C_AUTHN_LEVEL_PKT_INTEGRITY in client application.
```

See also: 
* https://edcint.co.nz/checkwmiplus/forums/topic/wmic-rpc_c_authn_level_pkt_integrity/
* https://edcint.co.nz/checkwmiplus/long-term-fix-for-wmic-keeping-check-wmi-plus-alive/

Since client-less Windows monitoring using WMI/DCOM with Nagios or Icinga is quite cool, we decided to search for a solution for this problem.

As a result, here comes a little (kind of) drop-in replacement for the wmic binary, in order to get `check_wmi_plus.pl` working again.
The script is based on the example `wmiquery.py` from Alberto Solino.

Please note: This is a first try, it hasn't been fully tested yet and there may be still some features missing.

## How to use

* Download the `wmic.py` file
* Place it into `/bin/wmic.py` or wherever your current wmic binary is deployed
* Move your original `wmic` binary to a safe place, e.g. `mv /bin/wmic /bin/wmic-orig`
* Create a symlink to the `wmic.py`: e.g. `symlink -s /bin/wmic.py /bin/wmic`
* Happy dance!! 😎


# Licensing
This software is provided under a slightly modified version of the Apache Software License. 
See the accompanying LICENSE file for more information.

This product includes software developed by SecureAuth Corporation (https://www.secureauth.com/).

# Contribute
We love the Open Source community and are happy to review your pull requests.
