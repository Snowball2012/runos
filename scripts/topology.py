from mininet.topo import Topo

class AccessTopology (Topo):

    def __init__(self):
        # Initialize topology
        Topo.__init__(self)

        # Add hosts and switches
        
        left_host = self.addHost("lh")
        left_switch = self.addSwitch("ls")

        up_host_1 = self.addHost("uh1")
        up_host_2 = self.addHost("uh2")
        up_switch = self.addSwitch("us")

        right_host = self.addHost("rh")
        right_switch = self.addSwitch("rs")

        down_host_1 = self.addHost("dh1")
        down_host_2 = self.addHost("dh2")
        down_switch = self.addSwitch("ds")

        # Add links
        self.addLink(left_host, left_switch)

        self.addLink(up_host_1, up_switch)
        self.addLink(up_host_2, up_switch)

        self.addLink(down_host_1, down_switch)
        self.addLink(down_host_2, down_switch)

        self.addLink(right_host, right_switch)

        self.addLink(left_switch, up_switch)
        self.addLink(left_switch, down_switch)

        self.addLink(right_switch, up_switch)
        self.addLink(right_switch, down_switch)

        self.addLink(down_switch, up_switch)
