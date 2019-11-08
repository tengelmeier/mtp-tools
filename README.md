Readme for MTP tools
====================

The project contains an Wireshark plugin to deal with PTP / MTP / PTP-IP / Fuji PTP over IP in various flavors.
One of the goals was to to create an easy to extend Wireshark dissector for PTP.

The toolchain implements: 

- extract the descriptions of PTP types and constants to JSON from other sources: *ptp_descriptions*
- generate code for dealing with PTP data based on JSON API descriptions *code\_generation*
- an example of such generated code: *wireshark*, an wireshark dissector lua plugin that extracts much more of PTP data that the original C-based dissector plugin

The code-generation approach is influenced by 

- [go-mtpfs][1] , esp. [munge.py][2]
 
- [NikonHacker PTP-over-usb support][3]
  
[1]: https://github.com/hanwen/go-mtpfs
[2]: https://raw.githubusercontent.com/hanwen/go-mtpfs/master/mtp/munge.py
[3]: https://nikonhacker.com/wiki/Wireshark\_PTP\_Support

Licensing:
----------

I hope I can explain it as simple as possible. And: IANAL. In my understanding, extracting constants from some source code produces 'derivate work'. So using one of the scripts in ptp_descriptions creates a JSON file that has the same license as the original source code.
This gives the following matrix:

- my code is under the BSD license
- the MTP constants in mtp_description.json are based on wpdmtp is under the BSD license
- the vendor specific ptp\_*.json descriptions are based libgphoto ptp.h and under the LGPL license
- any code using wireshark APIs is under the GPL license. See https://ask.wireshark.org/questions/12371/wireshark-plugin-and-gpl-license

This means: 
- using the code-generator with your own templates to create some source based on descriptions in ptp-bsd-license will generate BSD-licensed code. 
- using the code-generator with your own templates to create some source based on descriptions in ptp-lgpl-license will generate LGPL-licensed code. 
- using the code-generator to generate an Wireshark dissector will build GPL code, regardless of the descriptions used. 
 
 
