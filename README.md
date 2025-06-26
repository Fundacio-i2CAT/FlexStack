# FlexStack(R) Community Edition

<!--<img src="doc/img/logo.png" alt="V2X Flex Stack" width="200"/>--> <img src="https://raw.githubusercontent.com/Fundacio-i2CAT/FlexStack/refs/heads/master/doc/img/i2cat_logo.png" alt="i2CAT Logo" width="200"/>

# Short description

FlexStack(R) is a software library implementing the ETSI C-ITS protocol stack. Its aim is to facilitate and accelerate the development and integration of software applications on vehicles, vulnerable road users (VRU), and roadside infrastructure that requires the exchange of V2X messages (compliant with ETSI standards) with other actors of the V2X ecosystem.

# Documentation

Extensive documentation is available at [https://flexstack.eu](https://flexstack.eu).

# Pre-requisites

## Supported Operating Systems

This library can run on any system that supports Python 3.8 or higher.

It's important to remark that depending on the Access and Physical layer used, the library may requires additional dependencies.
As an example, it comes with a precompiled version of the C-V2X Link Layer tested on current Cohda Mk6 and other Qualcomm based solutions, which is used to enable the usage of C-V2X directly by this message library. However, if you want to use it with other hardware or software solutions, you may need to cross-compile the C-V2X Link Layer for your specific platform.

## Dependencies

All dependecies can be found in the `requirements.txt` file. To install them, run the following command:

```
pip install -r requirements.txt
```

On the Access Layer, the dependencies depends on the Access Technology used. Specific tutorials and examples can be found elsewhere.

## Build tools

The library is built using Python. To build the library, run the following command:

```
python -m build
```

It requires the `setuptools` and `wheel` packages. If they are not installed, they can be installed using the following command:

```
pip install build setuptools wheel
```

## Known Limitations

- The ASN.1 compiler used in this library is `asn1tools`, which has some limitations. For example, it does not support the `ANY` type, which is used in some ETSI C-ITS messages. This means that some messages may have undergone some adaptations to be compatible with the library. Although this simplifications have been tested with existing commercial implementations, and everything works as expected, it is important to be aware of this limitation.

# Installation

Library can be easily installed using the following command:

```
pip install v2xflexstack
```

## Developers

- Jordi Marias-i-Parella (jordi.marias@i2cat.net)
- Daniel Ulied Guevara (daniel.ulied@i2cat.net)
- Adrià Pons Serra (adria.pons@i2cat.net)
- Marc Codina Bartumeus (marc.codina@i2cat.net)
- Lluc Feixa Morancho (lluc.feixa@i2cat.net)

# Source

This code has been developed within the following research and innovation projects:

- **CARAMEL** (Grant Agreement No. 833611) – Funded under the Horizon 2020 programme, focusing on cybersecurity for connected and autonomous vehicles.
- **PLEDGER** (Grant Agreement No. 871536) – A Horizon 2020 project aimed at edge computing solutions to improve performance and security.
- **CODECO** (Grant Agreement No. 101092696) – A Horizon Europe initiative addressing cooperative and connected mobility.
- **SAVE-V2X** (Grant Agreement No. ACE05322000044) – Focused on V2X communication for vulnerable road user safety, and funded by ACCIO.
- **PoDIUM** (Grant Agreement No. 101069547) – Funded under the Horizon 2021 programme, this project focuses on accelerating the implementation of connected, cooperative and automated mobility technology.
- **SPRINGTIME** (PID2023-146378NB-I00) funded by the Spanish government (MCIU/AEI/10.13039/501100011033/FEDER/UE), this project focuses in techniques to get IP-based interconnection on multiple environments.
- **ONOFRE-3** (PID2020-112675RB-C43) funded by the Spanish government (MCIN/ AEI /10.13039/501100011033), this project focuses on the adaptation of network and compute resources from the cloud to the far-edge.

# Copyright

This code has been developed by Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT).

FlexStack is a registered trademark of i2CAT. Unauthorized use is strictly prohibited.

i2CAT is a **non-profit research and innovation centre that** promotes mission-driven knowledge to solve business challenges, co-create solutions with a transformative impact, empower citizens through open and participative digital social innovation with territorial capillarity, and promote pioneering and strategic initiatives. i2CAT **aims to transfer** research project results to private companies in order to create social and economic impact via the out-licensing of intellectual property and the creation of spin-offs. Find more information of i2CAT projects and IP rights at https://i2cat.net/tech-transfer/

# License

This code is licensed under the terms of the AGPL. Information about the license can be located at https://www.gnu.org/licenses/agpl-3.0.html.

Please, refer to FlexStack Community Edition as a dependence of your works.

If you find that this license doesn't fit with your requirements regarding the use, distribution or redistribution of our code for your specific work, please, don’t hesitate to contact the intellectual property managers in i2CAT at the following address: techtransfer@i2cat.net Also, in the following page you’ll find more information about the current commercialization status or other licensees: Under Development.

# Attributions

Attributions of Third Party Components of this work:

- `asn1tools` Version 0.165.0 - Imported python library - https://asn1tools.readthedocs.io/en/latest/ - MIT license
- `python-dateutil` Version 2.8.2 - Imported python library - https://pypi.org/project/python-dateutil/ - dual license - either Apache 2.0 License or the BSD 3-Clause License.
- `tinydb` Version 4.7.1- Imported python library - https://tinydb.readthedocs.io/en/latest/ - MIT license
- `ecdsa` Version 0.18.0 - Imported python library - https://pypi.org/project/ecdsa/ - MIT license
