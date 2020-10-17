# Zscaler CLI

This is a Python CLI for Zscaler Internet Access.  This cli (or client library) is designed to support the Zscaler Internet Access (ZIA) [API](https://help.zscaler.com/zia/about-api) and [SD-WAN API](https://help.zscaler.com/zia/sd-wan-api-integration) (aka "Partner API").  All API referecnes can be found here [[LINK](https://help.zscaler.com/zia/api)].  **PLEASE READ THE DOCUMENTATION BEFORE CONTACTING ZSCALER**

This CLI has been developed mainly using Python 3.8.5 on Ubuntu 20.04 LTS (Focal Fossa).

**NOTE:** This repository will experience frequent updates.  To minimize breakage, public method names will not change.  If you run into any defects, please open issues [[HERE.](https://github.com/omitroom13/zia/issues)]

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
        
3) Install package

```
$ pip install zia
```

4) Check out examples

```
$ zia --help
$ zia policies --help
$ zia policies list
[
 {
  "id": 463593,
  "accessControl": "READ_WRITE",
  "name": "URL Filtering Rule-1",
  "order": 8,
  "protocols": [
   "ANY_RULE"
  ],
  "urlCategories": [
   "OTHER_ADULT_MATERIAL",
   "ADULT_THEMES",
   "LINGERIE_BIKINI",
   "NUDITY",
   "PORNOGRAPHY",
   "SEXUALITY",
   "ADULT_SEX_EDUCATION",
   "K_12_SEX_EDUCATION",
   "OTHER_DRUGS",
   "OTHER_ILLEGAL_OR_QUESTIONABLE",
   "COPYRIGHT_INFRINGEMENT",
   "COMPUTER_HACKING",
   "QUESTIONABLE",
   "PROFANITY",
   "MATURE_HUMOR",
   "ANONYMIZER"
  ],
...
```

## API Support

### SD-WAN (Partner) API

* **VPN Credentials**
* **Locations**
* **Activate**

## Licensing

This work is released under the MIT license, forked from [eparra's zscaler-python-sdk v0.5](https://github.com/eparra/zscaler-python-sdk/). A copy of the license is provided in the [LICENSE](https://github.com/omitroom13/zia/blob/master/LICENSE) file.

## Reporting Issues

If you have bugs or other issues specifically pertaining to this library, file them [here](https://github.com/omitroom13/zia/issues).

## References

* https://help.zscaler.com/zia/api
* https://help.zscaler.com/zia/zscaler-api-developer-guide
* https://help.zscaler.com/zia/sd-wan-api-integration
