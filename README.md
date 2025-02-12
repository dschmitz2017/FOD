[![Documentation Status](https://readthedocs.org/projects/flowspy/badge/?version=latest)](https://readthedocs.org/projects/flowspy/?badge=latest)

# Firewall on Demand

## Description

Firewall on Demand (hereafter FoD) is based on the [flowspy](https://github.com/grnet/flowspy) project developed by [GRNET](http://www.grnet.gr/).

The FOD server applies flow rules - via [NETCONF](https://www.rfc-editor.org/rfc/rfc6241) - to a flowspec-capable network device which then propagates the rules via eBGP to other devices in the network.

Users are authenticated against Shibboleth. Authorization is performed via a combination of a Shibboleth attribute and the peer network address range that the user originates from. FoD is meant to operate using the following architecture:


       +-----------+          +------------+        +------------+
       |   FoD     | NETCONF  | flowspec   | ebgp   |   router   |
       | web app   +----------> device     +-------->            |
       +-----------+          +------+-----+        +------------+
                                     | ebgp
                                     |
                              +------v-----+
                              |   router   |
                              |            |
                              +------------+

## Currently supported devices

Fod currently supports updating of router(s) via NETCONF 
(for more information see doc/prerequisites/generic.md)
FoD currently does not support updating directly routers via BGP.

### Example of inbound firewall rules required on your flowspec device


|Name     |Protocol | Port |
|:--------|:-------:|:----:|
| NETCONF | tcp     | 830  |
| ssh     | tcp     | 22   |

## Documentation

Please visit the documentation directory above (`doc`) to see FoD's documentation.

GRnet's original [flowspy documentation](http://flowspy.readthedocs.org) is also available online.

## Installation Considerations

If you are upgrading from a previous version bear in mind the changes
introduced in Django 1.4.

## Rest Api
FoD provides a rest api. It uses token as authentication method. For usage instructions & examples check the documentation.

## Limitations

A user can belong to more than one `Peer` without any limitations.

The FoD UI polls the FoD server to dynamically update the dashboard and the

"Live Status" about the `Route`s they are aware of. In addition, the polling
implementation fetches information for every `Peer` the user is associated
with. Thus, if a user belongs to many `Peer`s too many AJAX calls will be sent
to the backend - which may result in a non responsive state. It is recommended to
keep the peers associated with any user under 5.


## Contact 

You can contact us directly at fod{at}lists[dot]geant(.)org

## Copyright and license

Copyright © 2017-2023 GÈANT GN4-2/GN4-3/GN5-1 Project

Copyright © 2010-2017 Greek Research and Technology Network (GRNET S.A.)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
