## intorobot_smartconfig_devel
NONE

## Test Smartconfig in IntoRobot-Atom
- log in you atom, and run the script smartconfig_get_ap_info. this script is used for decoding the smartconfig encoded messages as well as configing the wifi with the decoded info
```
  atom# smartconfig_get_ap_info
```
- at the same time, run the test python for atom-yun configuration
```
  atom# python sockets_udp2.py
```
- and then, run intorobot-App and add a new device. (Your smart phone should be connected to a ap which is already connected to the Internet
