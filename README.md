# Zscaler Python SDK 

This is a Python SDK for Zscaler Internet Access.  This client library is designed to support the Zscaler Internet Access (ZIA) [API](https://help.zscaler.com/zia/about-api) and [SD-WAN API](https://help.zscaler.com/zia/sd-wan-api-integration) (aka "Partner API").  All API referecnes can be found here [[LINK](https://help.zscaler.com/zia/api)].  **PLEASE READ THE DOCUMENTATION BEFORE CONTACTING ZSCALER**

This SDK has been developed mainly using Python 3.8.5 on Ubuntu 20.04 LTS (Focal Fossa).

**NOTE:** This repository will experience frequent updates.  To minimize breakage, public method names will not change.  If you run into any defects, please open issues [[HERE.](https://github.com/eparra/zscaler-python-sdk/issues)]

## Quick Start 

1) If you have not verified your credentials, we suggest starting [[HERE](https://help.zscaler.com/zia/configuring-postman-rest-api-client)], unless you are already familar with this API.

2) Set profile
 
```
$ mkdir ~/.zscaler
$ cat > ~/.zscaler/profile.yaml <<EOF
default:
  url: https://admin.<ZIA-CLOUD>.net
  username: <ZIA-ADMIN-USER-ID>
  password: <ZIA-ADMIN-USER-PASSWORD>
  apikey: <ZIA-API-KEY>
partner:
  url: https://admin.<ZIA-CLOUD>.net
  username: <ZIA-PARTNER-ADMIN-USER-ID>
  password: <ZIA-PARTNER-ADMIN-USER-PASSWORD>
  apikey: <PARTNER-API-KEY>
EOF
```
        
3) Clone Repository (OS must have git installed)

```
$ git clone https://github.com/omitroom13/zscaler-python-sdk.git
$ cd zscaler-python-sdk/
```

4) Install SDK requirements (OS must have python3 installed)

```
$ pip install -r requirements.txt
```

5) Install SDK

```
$ python setup.py install
```

6) Check out examples

```
$ ls examples/
...
```

## API Support

### SD-WAN (Partner) API

* **VPN Credentials**
* **Locations**
* **Activate**

## Licensing

This work is released under the MIT license, forked from [eparra's zscaler-python-sdk v0.5](https://github.com/eparra/zscaler-python-sdk/). A copy of the license is provided in the [LICENSE](https://github.com/omitroom13/zscaler-python-sdk/blob/master/LICENSE) file.

## Reporting Issues

If you have bugs or other issues specifically pertaining to this library, file them [here](https://github.com/omitroom13/zscaler-python-sdk/issues).

## References

* https://help.zscaler.com/zia/api
* https://help.zscaler.com/zia/zscaler-api-developer-guide
* https://help.zscaler.com/zia/sd-wan-api-integration
