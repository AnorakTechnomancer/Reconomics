from ai_pentest.scanners.nmap import NmapScanner


SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="test.example"/>
    </hostnames>

    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service
          name="ssh"
          product="OpenSSH"
          version="8.7"
        />
      </port>

      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_nmap_xml():
    result = NmapScanner.parse_xml(
        "192.0.2.10",
        SAMPLE_XML,
    )

    assert result.scanner == "nmap"
    assert result.target == "192.0.2.10"

    assert len(result.hosts) == 1

    host = result.hosts[0]

    assert host.address == "192.0.2.10"
    assert host.hostname == "test.example"
    assert host.status == "up"

    assert len(host.services) == 2

    ssh = host.services[0]

    assert ssh.port == 22
    assert ssh.protocol == "tcp"
    assert ssh.state == "open"
    assert ssh.service == "ssh"
    assert ssh.product == "OpenSSH"
    assert ssh.version == "8.7"
