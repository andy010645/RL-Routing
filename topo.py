from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import Link, Intf, TCLink


def Test_topo():
    net = Mininet(controller=RemoteController,link=TCLink)

    info("*** Add Controller ***\n")
    net.addController("c0",controller=RemoteController)

    info("*** Add Switch ***\n")
    s1 = net.addSwitch("s1")
    s2 = net.addSwitch("s2")
    s3 = net.addSwitch("s3")
    s4 = net.addSwitch("s4")

    info("*** Add Host ***\n")
    h1 = net.addHost("h1",mac="00:00:00:00:00:01")
    h2 = net.addHost("h2",mac="00:00:00:00:00:02")
    h3 = net.addHost("h3",mac="00:00:00:00:00:03")
    h4 = net.addHost("h4",mac="00:00:00:00:00:04")

    info("*** Add Link ***\n")
    net.addLink(s1,h1,bw=0.01)
    net.addLink(s2,h2,bw=0.01)
    net.addLink(s3,h3,bw=0.01)
    net.addLink(s4,h4,bw=0.01)

    net.addLink(s1,s2,bw=0.01)
    net.addLink(s2,s3,bw=0.01)
    net.addLink(s3,s4,bw=0.01)

    info("*** Network Start ***\n")
    net.start()
    CLI(net)
    net.stop()

if __name__ == "__main__":
    setLogLevel("debug")
    Test_topo()