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
    s5 = net.addSwitch("s5")
    s6 = net.addSwitch("s6")
    s7 = net.addSwitch("s7")
    s8 = net.addSwitch("s8")
    s9 = net.addSwitch("s9")
    s10 = net.addSwitch("s10")
    s11 = net.addSwitch("s11")
    s12 = net.addSwitch("s12")
    s13 = net.addSwitch("s13")
    s14 = net.addSwitch("s14")

    info("*** Add Host ***\n")
    h1 = net.addHost("h1",mac="00:00:00:00:00:01")
    h2 = net.addHost("h2",mac="00:00:00:00:00:02")
    h3 = net.addHost("h3",mac="00:00:00:00:00:03")
    h4 = net.addHost("h4",mac="00:00:00:00:00:04")
    h5 = net.addHost("h5",mac="00:00:00:00:00:05")
    h6 = net.addHost("h6",mac="00:00:00:00:00:06")
    h7 = net.addHost("h7",mac="00:00:00:00:00:07")
    h8 = net.addHost("h8",mac="00:00:00:00:00:08")
    h9 = net.addHost("h9",mac="00:00:00:00:00:09")
    h10 = net.addHost("h10",mac="00:00:00:00:00:10")
    h11 = net.addHost("h11",mac="00:00:00:00:00:11")
    h12 = net.addHost("h12",mac="00:00:00:00:00:12")
    h13 = net.addHost("h13",mac="00:00:00:00:00:13")
    h14 = net.addHost("h14",mac="00:00:00:00:00:14")

    info("*** Add Link ***\n")
    net.addLink(s1,h1,bw=0.01)
    net.addLink(s2,h2,bw=0.01)
    net.addLink(s3,h3,bw=0.01)
    net.addLink(s4,h4,bw=0.01)
    net.addLink(s5,h5,bw=0.01)
    net.addLink(s6,h6,bw=0.01)
    net.addLink(s7,h7,bw=0.01)
    net.addLink(s8,h8,bw=0.01)
    net.addLink(s9,h9,bw=0.01)
    net.addLink(s10,h10,bw=0.01)
    net.addLink(s11,h11,bw=0.01)
    net.addLink(s12,h12,bw=0.01)
    net.addLink(s13,h13,bw=0.01)
    net.addLink(s14,h14,bw=0.01)

    net.addLink(s1,s2,bw=0.01)
    net.addLink(s1,s3,bw=0.01)
    net.addLink(s1,s4,bw=0.01)
    net.addLink(s2,s3,bw=0.01)
    net.addLink(s2,s8,bw=0.01)
    net.addLink(s3,s6,bw=0.01)
    net.addLink(s4,s5,bw=0.01)
    net.addLink(s4,s11,bw=0.01)
    net.addLink(s5,s6,bw=0.01)
    net.addLink(s5,s7,bw=0.01)
    net.addLink(s6,s10,bw=0.01)
    net.addLink(s6,s14,bw=0.01)
    net.addLink(s7,s8,bw=0.01)
    net.addLink(s8,s9,bw=0.01)
    net.addLink(s9,s10,bw=0.01)
    net.addLink(s9,s12,bw=0.01)
    net.addLink(s9,s13,bw=0.01)
    net.addLink(s11,s12,bw=0.01)
    net.addLink(s11,s13,bw=0.01)
    net.addLink(s12,s14,bw=0.01)
    net.addLink(s13,s14,bw=0.01)

    info("*** Network Start ***\n")
    net.start()
    # CLI(net)
    # net.stop()
    return net
def generate(net):
    h1 = net.get('h1')
    print(h1.cmd('ping 10.0.0.2 -s 1000 -c 1'))
    

if __name__ == "__main__":
    setLogLevel("info")
    net = Test_topo()

    while 1:
        input = raw_input('CLI/GEN/QUIT')
        if input.upper() == 'CLI':
            CLI(net)
        elif input.upper() == 'GEN':
            generate(net)
        elif input.upper() == 'QUIT':
            net.stop()
            break
    