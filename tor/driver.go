package tor

import (
	"fmt"
	"net"
	"sync"

	"github.com/Sirupsen/logrus"
	"github.com/docker/engine-api/client"
	"github.com/docker/go-plugins-helpers/network"
	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/portmapper"
	"github.com/docker/libnetwork/types"
	"github.com/vishvananda/netlink"
)

const (
	defaultRoute     = "0.0.0.0/0"
	torPortPrefix    = "tor-veth0-"
	bridgePrefix     = "torbr-"
	containerEthName = "eth"

	mtuOption        = "net.jessfraz.tor.bridge.mtu"
	bridgeNameOption = "net.jessfraz.tor.bridge.name"

	defaultMTU          = 1500
	defaultTorContainer = "tor-router"

	ipv4ForwardConf     = "/proc/sys/net/ipv4/ip_forward"
	ipv4ForwardConfPerm = 0644
)

// endpointConfiguration represents the user specified configuration for the sandbox endpoint.
type endpointConfiguration struct {
	PortBindings []types.PortBinding
	ExposedPorts []types.TransportPort
}

// containerConfiguration represents the user specified configuration for a container.
type containerConfiguration struct {
	ParentEndpoints []string
	ChildEndpoints  []string
}

// torEndpoint represents an endpoint in the tor network for a container.
type torEndpoint struct {
	id              string
	srcName         string
	addr            *net.IPNet
	addrv6          *net.IPNet
	macAddress      net.HardwareAddr
	config          *endpointConfiguration // User specified parameters
	containerConfig *containerConfiguration
	portMapping     []types.PortBinding // Operation port bindings
}

// Driver represents the interface for the network plugin driver.
type Driver struct {
	network.Driver
	dcli     *client.Client
	networks map[string]*NetworkState
	sync.Mutex
}

// GetCapabilities gets the scope for the network.
func (d *Driver) GetCapabilities() (*network.CapabilitiesResponse, error) {
	return &network.CapabilitiesResponse{Scope: network.LocalScope}, nil
}

// CreateNetwork creates a new tor network.
func (d *Driver) CreateNetwork(r *network.CreateNetworkRequest) error {
	logrus.Debugf("Create network request: %+v", r)

	bridgeName, err := getBridgeName(r.NetworkID, r.Options)
	if err != nil {
		return err
	}

	mtu, err := getBridgeMTU(r.Options)
	if err != nil {
		return err
	}

	gateway, mask, err := getGatewayIP(r)
	if err != nil {
		return err
	}

	// we need to have ip forwarding setup for this to work w routing
	if err = setupIPForwarding(ipv4ForwardConf, ipv4ForwardConfPerm); err != nil {
		return err
	}

	// get tor router ip
	torIP, err := d.getTorRouterIP()
	if err != nil {
		return err
	}

	logrus.Debugf("tor router ip is: %s", torIP)

	ns := &NetworkState{
		BridgeName:  bridgeName,
		MTU:         mtu,
		Gateway:     gateway,
		GatewayMask: mask,
		endpoints:   map[string]*torEndpoint{},
		portMapper:  portmapper.New(),
		blockUDP:    true, // TODO: this should be configurable
	}
	d.networks[r.NetworkID] = ns

	// setup iptables chains
	ns.natChain, ns.filterChain, err = setupIPChains()
	if err != nil {
		return fmt.Errorf("Setup iptables chains failed: %v", err)
	}

	logrus.Debugf("Initializing bridge for network %s", r.NetworkID)
	if err := ns.initBridge(torIP); err != nil {
		delete(d.networks, r.NetworkID)
		return fmt.Errorf("Init bridge %s failed: %v", bridgeName, err)
	}

	return nil
}

func (d *Driver) getNetworkState(id string) (*NetworkState, error) {
	d.Lock()
	defer d.Unlock()
	ns, ok := d.networks[id]
	if !ok {
		return ns, types.InternalMaskableErrorf("network %s does not exist", id)
	}
	return ns, nil
}

// DeleteNetwork deletes a given tor network.
func (d *Driver) DeleteNetwork(r *network.DeleteNetworkRequest) error {
	logrus.Debugf("Delete network request: %+v", r)

	// Get the network handler and make sure it exists
	ns, err := d.getNetworkState(r.NetworkID)
	if err != nil {
		return err
	}

	if ns == nil {
		return driverapi.ErrNoNetwork(r.NetworkID)
	}

	err = ns.deleteBridge(r.NetworkID)
	if err != nil {
		return fmt.Errorf("Deleting bridge for network %s failed: %s", r.NetworkID, err)
	}
	delete(d.networks, r.NetworkID)

	return nil
}

// CreateEndpoint creates new endpoints for a container.
func (d *Driver) CreateEndpoint(r *network.CreateEndpointRequest) (*network.CreateEndpointResponse, error) {
	logrus.Debugf("Create endpoint request: %+v", r)

	// Get the network handler and make sure it exists
	ns, err := d.getNetworkState(r.NetworkID)
	if err != nil {
		return nil, err
	}

	if ns == nil {
		return nil, driverapi.ErrNoNetwork(r.NetworkID)
	}

	// Check if endpoint id is good and retrieve correspondent endpoint
	ep, err := ns.getEndpoint(r.EndpointID)
	if err != nil {
		return nil, err
	}

	// Endpoint with that id exists either on desired or other sandbox
	if ep != nil {
		return nil, driverapi.ErrEndpointExists(r.EndpointID)
	}

	// Try to convert the options to endpoint configuration
	epConfig, err := parseEndpointOptions(r.Options)
	if err != nil {
		return nil, err
	}
	logrus.Infof("epConfig: %#v", epConfig)

	// Create and add the endpoint
	ns.Lock()
	endpoint := &torEndpoint{id: r.EndpointID, config: epConfig}
	ns.endpoints[r.EndpointID] = endpoint
	ns.Unlock()

	// On failure make sure to remove the endpoint
	defer func() {
		if err != nil {
			ns.Lock()
			delete(ns.endpoints, r.EndpointID)
			ns.Unlock()
		}
	}()

	if r.Interface.MacAddress != "" {
		endpoint.macAddress, err = net.ParseMAC(r.Interface.MacAddress)
		if err != nil {
			return nil, fmt.Errorf("Parsing %s as Mac failed: %v", r.Interface.MacAddress, err)
		}
	}
	if r.Interface.Address != "" {
		_, endpoint.addr, err = net.ParseCIDR(r.Interface.Address)
		if err != nil {
			return nil, fmt.Errorf("Parsing %s as CIDR failed: %v", r.Interface.Address, err)
		}
	}
	if r.Interface.AddressIPv6 != "" {
		_, endpoint.addrv6, err = net.ParseCIDR(r.Interface.AddressIPv6)
		if err != nil {
			return nil, fmt.Errorf("Parsing %s as CIDR failed: %v", r.Interface.AddressIPv6, err)
		}
	}

	// Program any required port mapping and store them in the endpoint
	endpoint.portMapping, err = ns.allocatePorts(epConfig, endpoint, defaultBindingIP, false)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

// DeleteEndpoint deletes the given endpoints.
func (d *Driver) DeleteEndpoint(r *network.DeleteEndpointRequest) error {
	logrus.Debugf("Delete endpoint request: %+v", r)

	// Get the network handler and make sure it exists
	ns, err := d.getNetworkState(r.NetworkID)
	if err != nil {
		return err
	}

	if ns == nil {
		return driverapi.ErrNoNetwork(r.NetworkID)
	}

	// Check if endpoint id is good and retrieve correspondent endpoint
	ep, err := ns.getEndpoint(r.EndpointID)
	if err != nil {
		return err
	}

	if ep == nil {
		return EndpointNotFoundError(r.EndpointID)
	}

	// Remove it
	ns.Lock()
	delete(ns.endpoints, r.EndpointID)
	ns.Unlock()

	// On failure make sure to set back ep in n.endpoints, but only
	// if it hasn't been taken over already by some other thread.
	defer func() {
		if err != nil {
			ns.Lock()
			if _, ok := ns.endpoints[r.EndpointID]; !ok {
				ns.endpoints[r.EndpointID] = ep
			}
			ns.Unlock()
		}
	}()

	// Remove port mappings. Do not stop endpoint delete on unmap failure
	if err := ns.releasePorts(ep); err != nil {
		return err
	}

	return nil
}

// EndpointInfo returns information about an endpoint.
func (d *Driver) EndpointInfo(r *network.InfoRequest) (*network.InfoResponse, error) {
	logrus.Debugf("Endpoint info request: %+v", r)

	res := &network.InfoResponse{
		Value: make(map[string]string),
	}
	// TODO(shanel): If this only ever returns nil, should it return an error at all?
	return res, nil
}

// Join creates a veth pair connected to the requested network.
func (d *Driver) Join(r *network.JoinRequest) (*network.JoinResponse, error) {
	logrus.Debugf("Join request: %+v", r)

	// Get the network handler and make sure it exists
	ns, err := d.getNetworkState(r.NetworkID)
	if err != nil {
		return nil, err
	}

	if ns == nil {
		return nil, driverapi.ErrNoNetwork(r.NetworkID)
	}

	bridgeName := ns.BridgeName

	// create and attach local name to the bridge
	localVethPair, err := vethPair(truncateID(r.EndpointID), bridgeName)
	if err != nil {
		return nil, fmt.Errorf("getting vethpair failed: %v", err)
	}

	if err := netlink.LinkAdd(localVethPair); err != nil {
		return nil, fmt.Errorf("failed to create the veth pair named: [ %v ] error: [ %s ] ", localVethPair, err)
	}

	// Bring the veth pair up
	if err := netlink.LinkSetUp(localVethPair); err != nil {
		return nil, fmt.Errorf("Error enabling Veth local iface: [ %v ]: %v", localVethPair, err)
	}
	logrus.Infof("Attached veth [ %s ] to bridge [ %s ]", localVethPair.Name, bridgeName)

	// SrcName gets renamed to DstPrefix + ID on the container iface
	res := &network.JoinResponse{
		InterfaceName: network.InterfaceName{
			SrcName:   localVethPair.PeerName,
			DstPrefix: containerEthName,
		},
		Gateway: d.networks[r.NetworkID].Gateway,
	}
	logrus.Debugf("Join endpoint %s:%s to %s", r.NetworkID, r.EndpointID, r.SandboxKey)
	return res, nil
}

// Leave deletes and cleans up a veth pair in the given network.
func (d *Driver) Leave(r *network.LeaveRequest) error {
	logrus.Debugf("Leave request: %+v", r)

	// Get the network handler and make sure it exists
	ns, err := d.getNetworkState(r.NetworkID)
	if err != nil {
		return err
	}

	if ns == nil {
		return driverapi.ErrNoNetwork(r.NetworkID)
	}

	bridgeName := ns.BridgeName

	localVethPair, err := vethPair(truncateID(r.EndpointID), bridgeName)
	if err != nil {
		return fmt.Errorf("getting vethpair failed: %v", err)
	}

	if err := netlink.LinkDel(localVethPair); err != nil {
		return fmt.Errorf("unable to delete veth on leave: %s", err)
	}

	logrus.Debugf("Leave %s:%s", r.NetworkID, r.EndpointID)
	return nil
}

// NewDriver creates a new Driver pointer.
func NewDriver() (*Driver, error) {
	defaultHeaders := map[string]string{"User-Agent": "engine-api-cli-1.0"}
	dcli, err := client.NewClient("unix:///var/run/docker.sock", "", nil, defaultHeaders)
	if err != nil {
		return nil, fmt.Errorf("could not connect to docker: %s", err)
	}

	d := &Driver{
		dcli:     dcli,
		networks: make(map[string]*NetworkState),
	}
	return d, nil
}
