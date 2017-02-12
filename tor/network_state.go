package tor

import (
	"bytes"
	"fmt"
	"net"
	"sync"

	"github.com/Sirupsen/logrus"
	"github.com/docker/libnetwork/iptables"
	"github.com/docker/libnetwork/netutils"
	"github.com/docker/libnetwork/portmapper"
	"github.com/docker/libnetwork/types"
)

var (
	defaultBindingIP        = net.IPv4(0, 0, 0, 0)
	maxAllocatePortAttempts = 10
)

// NetworkState is filled in at network creation time.
// It contains state that we wish to keep for each network.
type NetworkState struct {
	BridgeName            string
	MTU                   int
	Gateway               string
	GatewayMask           string
	endpoints             map[string]*torEndpoint // key: endpoint id
	portMapper            *portmapper.PortMapper
	natChain, filterChain *iptables.ChainInfo
	iptCleanFuncs         iptablesCleanFuncs
	blockUDP              bool
	sync.Mutex
}

func (n *NetworkState) getEndpoint(eid string) (*torEndpoint, error) {
	n.Lock()
	defer n.Unlock()

	if eid == "" {
		return nil, InvalidEndpointIDError(eid)
	}

	if ep, ok := n.endpoints[eid]; ok {
		return ep, nil
	}

	return nil, nil
}

func (n *NetworkState) allocatePorts(epConfig *endpointConfiguration, ep *torEndpoint, reqDefBindIP net.IP, ulPxyEnabled bool) ([]types.PortBinding, error) {
	if epConfig == nil || epConfig.PortBindings == nil {
		return nil, nil
	}

	defHostIP := defaultBindingIP
	if reqDefBindIP != nil {
		defHostIP = reqDefBindIP
	}

	return n.allocatePortsInternal(epConfig.PortBindings, ep.addr.IP, defHostIP, ulPxyEnabled)
}

func (n *NetworkState) allocatePortsInternal(bindings []types.PortBinding, containerIP, defHostIP net.IP, ulPxyEnabled bool) ([]types.PortBinding, error) {
	bs := make([]types.PortBinding, 0, len(bindings))
	for _, c := range bindings {
		b := c.GetCopy()
		if err := n.allocatePort(&b, containerIP, defHostIP, ulPxyEnabled); err != nil {
			// On allocation failure, release previously allocated ports. On cleanup error, just log a warning message
			if cuErr := n.releasePortsInternal(bs); cuErr != nil {
				logrus.Warnf("Upon allocation failure for %v, failed to clear previously allocated port bindings: %v", b, cuErr)
			}
			return nil, err
		}
		bs = append(bs, b)
	}
	return bs, nil
}

func (n *NetworkState) allocatePort(bnd *types.PortBinding, containerIP, defHostIP net.IP, ulPxyEnabled bool) error {
	var (
		host net.Addr
		err  error
	)

	// Store the container interface address in the operational binding
	bnd.IP = containerIP

	// Adjust the host address in the operational binding
	if len(bnd.HostIP) == 0 {
		bnd.HostIP = defHostIP
	}

	// Adjust HostPortEnd if this is not a range.
	if bnd.HostPortEnd == 0 {
		bnd.HostPortEnd = bnd.HostPort
	}

	// Construct the container side transport address
	container, err := bnd.ContainerAddr()
	if err != nil {
		return err
	}

	// Try up to maxAllocatePortAttempts times to get a port that's not already allocated.
	for i := 0; i < maxAllocatePortAttempts; i++ {
		if host, err = n.portMapper.MapRange(container, bnd.HostIP, int(bnd.HostPort), int(bnd.HostPortEnd), ulPxyEnabled); err == nil {
			break
		}
		// There is no point in immediately retrying to map an explicitly chosen port.
		if bnd.HostPort != 0 {
			logrus.Warnf("Failed to allocate and map port %d-%d: %s", bnd.HostPort, bnd.HostPortEnd, err)
			break
		}
		logrus.Warnf("Failed to allocate and map port: %s, retry: %d", err, i+1)
	}
	if err != nil {
		return err
	}

	// Save the host port (regardless it was or not specified in the binding)
	switch netAddr := host.(type) {
	case *net.TCPAddr:
		bnd.HostPort = uint16(host.(*net.TCPAddr).Port)
		return nil
	case *net.UDPAddr:
		bnd.HostPort = uint16(host.(*net.UDPAddr).Port)
		return nil
	default:
		// For completeness
		return ErrUnsupportedAddressType(fmt.Sprintf("%T", netAddr))
	}
}

func (n *NetworkState) releasePorts(ep *torEndpoint) error {
	return n.releasePortsInternal(ep.portMapping)
}

func (n *NetworkState) releasePortsInternal(bindings []types.PortBinding) error {
	var errorBuf bytes.Buffer

	// Attempt to release all port bindings, do not stop on failure
	for _, m := range bindings {
		if err := n.releasePort(m); err != nil {
			errorBuf.WriteString(fmt.Sprintf("\ncould not release %v because of %v", m, err))
		}
	}

	if errorBuf.Len() != 0 {
		return fmt.Errorf(errorBuf.String())
	}
	return nil
}

func (n *NetworkState) releasePort(bnd types.PortBinding) error {
	// Construct the host side transport address
	host, err := bnd.HostAddr()
	if err != nil {
		return err
	}
	return n.portMapper.Unmap(host)
}

func (n *NetworkState) setupIPTables(torIP string) error {
	addrv4, _, err := netutils.GetIfaceAddr(n.BridgeName)
	if err != nil {
		return fmt.Errorf("Failed to setup IP tables, cannot acquire interface address for bridge %s: %v", n.BridgeName, err)
	}

	ipnet := addrv4.(*net.IPNet)
	ic := &iptablesConfig{
		addr: &net.IPNet{
			IP:   ipnet.IP.Mask(ipnet.Mask),
			Mask: ipnet.Mask,
		},
		bridgeName:  n.BridgeName,
		torIP:       torIP,
		hairpinMode: hairpinMode,
		iccMode:     true,
		ipMasqMode:  true,
		blockUDP:    n.blockUDP,
	}

	if err = ic.setupIPTablesInternal(true); err != nil {
		return fmt.Errorf("setup iptables failed for bridge %s: %v", n.BridgeName, err)
	}
	n.registerIptCleanFunc(func() error {
		return ic.setupIPTablesInternal(false)
	})

	err = iptables.ProgramChain(n.natChain, n.BridgeName, ic.hairpinMode, true)
	if err != nil {
		return fmt.Errorf("Failed to program NAT chain: %s", err.Error())
	}
	n.registerIptCleanFunc(func() error {
		return iptables.ProgramChain(n.natChain, n.BridgeName, ic.hairpinMode, false)
	})

	err = iptables.ProgramChain(n.filterChain, n.BridgeName, ic.hairpinMode, true)
	if err != nil {
		return fmt.Errorf("Failed to program FILTER chain: %s", err.Error())
	}
	n.registerIptCleanFunc(func() error {
		return iptables.ProgramChain(n.filterChain, n.BridgeName, ic.hairpinMode, false)
	})

	n.portMapper.SetIptablesChain(n.filterChain, n.BridgeName)

	// forward to tor
	if err := ic.forwardToTor(iptables.Insert); err != nil {
		return fmt.Errorf("Redirecting traffic from bridge (%s) to torIP (%s) via iptables failed: %v", n.BridgeName, torIP, err)
	}
	n.registerIptCleanFunc(func() error {
		return ic.forwardToTor(iptables.Delete)
	})

	return nil
}

type iptableCleanFunc func() error
type iptablesCleanFuncs []iptableCleanFunc

func (n *NetworkState) registerIptCleanFunc(clean iptableCleanFunc) {
	n.iptCleanFuncs = append(n.iptCleanFuncs, clean)
}
