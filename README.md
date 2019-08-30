# syslog_parse

## Installation
```shell
 pip install syslog-parse
```
## Usage
Single parsing:
```
>>> from syslog_parse import parse
>>> a = "<189>Jan 20 2019 06:31:16.173 US-LAX-2-CR-2-new %%01OPS/5/OPS_LOGIN(s):CID=0x80b40445;Succeeded in establishing the OPS connection.(ServiceType=embedding-script, UserName=_soc_l3loop.py, Ip=0.0.0.0, VpnName=_public_)"
>>> parse(a)
<generator object Parser.cycle_parse at 0x10342cb10>
>>> parse(a)
Message(facility=<Facility.local7: 23>, severity=<Severity.notice: 5>, timestamp=datetime.datetime(2019, 1, 20, 6, 31, 16), hostname='US-LAX-2-CR-2-new', module='OPS', digest='OPS_LOGIN', content='CID=0x80b40445;Succeeded in establishing the OPS connection.(ServiceType=embedding-script, UserName=_soc_l3loop.py, Ip=0.0.0.0, VpnName=_public_)')
```
   
multiple parsing:
```
>>> from syslog_parse import cycle_parse
>>> aa = "<189>Jan 20 2019 06:31:17.60.1 US-DFW-1-CR-1 %%01INFO/5/SUPPRESS_LOG(l)[8480539]:Last message repeated 20 times.(InfoID=1079656494, ModuleName=VTY, InfoAlias=ACL_DENY)<7>Jan 20 14:30:56 AP-HKG-2-CR-1-RE0 kernel: rts_commit_proposalmput op: 2, peer_type:17, peer_index:3, vskid:0, seqno:14447884, flag:9,<7>Jan 20 14:30:56 AP-HKG-2-CR-1-RE0 kernel: rts_commit_proposalmput op: 2, peer_type:17, peer_index:1, vskid:0, seqno:14447884, flag:9,<7>Jan 20 14:30:56 AP-HKG-2-CR-1-RE0 kernel: rts_commit_proposalmput op: 2, peer_type:17, peer_index:5, vskid:0, seqno:14447884, flag:9,<37>Jan 20 14:30:56 AP-HKG-2-CR-1-RE0 snmpd[15576]: SNMPD_AUTH_RESTRICTED_ADDRESS: nsa_initial_callback: request from address 103.36.133.244 not allowed<7>Jan 20 14:30:57 AP-HKG-2-CR-1-RE0 kernel: rts_commit_proposalmput op: 2, peer_type:17, peer_index:3, vskid:0, seqno:14447886, flag:9,<7>Jan 20 06:25:22 AP-SGN-1-CR-1-RE0 kernel: rts_commit_proposalmput op: 2, peer_type:17, peer_index:1, vskid:0, seqno:1158657, flag:9,<7>Jan 20 14:30:57 AP-HKG-2-CR-1-RE0 kernel: rts_commit_proposalmput op: 2, peer_type:17, peer_index:5, vskid:0, seqno:14447886, flag:9,<7>Jan 20 14:30:57 AP-HKG-2-CR-1-RE0 kernel: rts_commit_proposalmput op: 2, peer_type:17, peer_index:1, vskid:0, seqno:14447886, flag:9,<188>Jan 20 2019 06:31:14.967 SA-SAO-2-CR-1 %%01SOC/4/hwBaseArpVlanCarEnhanceTrap_clear(l):VS=Admin-VS-CID=0x80c4046e-alarmID=0x09e62006-clearType=service_resume;ARP VLAN CAR became ineffective on an interface.(Logical Interface = Eth-Trunk4, Physical Interface = GigabitEthernet3/0/6, Pe-Vlan = 0, Ce-Vlan = 0, Sample Rate = 499)"
>>> cycle_parse(aa)
<generator object Parser.cycle_parse at 0x10342cb10>
>>> next(cycle_parse(aa))
Message(facility=<Facility.local7: 23>, severity=<Severity.notice: 5>, timestamp=datetime.datetime(2019, 1, 20, 6, 31, 17), hostname='US-DFW-1-CR-1', module='INFO', digest='SUPPRESS_LOG', content='Last message repeated 20 times.(InfoID=1079656494, ModuleName=VTY, InfoAlias=ACL_DENY)')
>>> for msg in cycle_parse(bb):
 print(msg)

Message(facility=<Facility.local7: 23>, severity=<Severity.notice: 5>, timestamp=datetime.datetime(2019, 1, 20, 6, 31, 17), hostname='US-DFW-1-CR-1', module='INFO', digest='SUPPRESS_LOG', content='Last message repeated 20 times.(InfoID=1079656494, ModuleName=VTY, InfoAlias=ACL_DENY)')
Message(facility=<Facility.kernel: 0>, severity=<Severity.debug: 7>, timestamp=datetime.datetime(2019, 1, 20, 14, 30, 56), hostname='AP-HKG-2-CR-1-RE0', module='kernel', digest='rts_commit_proposalmput op', content='2, peer_type:17, peer_index:3, vskid:0, seqno:14447884, flag:9,')
```