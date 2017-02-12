package tor

import (
	"fmt"
	"net"

	"github.com/docker/libnetwork/iptables"
)

type iptRule struct {
	table   iptables.Table
	chain   string
	preArgs []string
	args    []string
}

type iptablesConfig struct {
	bridgeName  string
	torIP       string
	addr        *net.IPNet
	hairpinMode bool
	iccMode     bool
	ipMasqMode  bool
	blockUDP    bool
}

func programChainRule(rule iptRule, ruleDescr string, enable bool) error {
	var (
		prefix    []string
		condition bool
		doesExist = iptables.Exists(rule.table, rule.chain, rule.args...)
	)

	action := iptables.Insert
	condition = !doesExist
	if !enable {
		action = iptables.Delete
		condition = doesExist
	}
	prefix = []string{string(action), rule.chain}

	if rule.preArgs != nil {
		prefix = append(rule.preArgs, prefix...)
	}

	if condition {
		if output, err := iptables.Raw(append(prefix, rule.args...)...); err != nil {
			return fmt.Errorf("Unable to %s %s rule: %v", action, ruleDescr, err)
		} else if len(output) != 0 {
			return &iptables.ChainError{Chain: rule.chain, Output: output}
		}
	}

	return nil
}

func (ic *iptablesConfig) setupIPTablesInternal(enable bool) error {

	// TODO(shanel): Format this to look prettier.
	var (
		address = ic.addr.String()
		natRule = iptRule{
			table:   iptables.Nat,
			chain:   "POSTROUTING",
			preArgs: []string{"-t", "nat"},
			args:    []string{"-s", address, "!", "-o", ic.bridgeName, "-j", "MASQUERADE"},
		}
		hpNatRule = iptRule{
			table:   iptables.Nat,
			chain:   "POSTROUTING",
			preArgs: []string{"-t", "nat"},
			args: []string{
				"-m", "addrtype",
				"--src-type", "LOCAL",
				"-o", ic.bridgeName,
				"-j", "MASQUERADE",
			},
		}
		outRule = iptRule{
			table: iptables.Filter,
			chain: "FORWARD",
			args:  []string{"-i", ic.bridgeName, "!", "-o", ic.bridgeName, "-j", "ACCEPT"},
		}
		inRule = iptRule{
			table: iptables.Filter,
			chain: "FORWARD",
			args: []string{
				"-o", ic.bridgeName,
				"-m", "conntrack",
				"--ctstate", "RELATED,ESTABLISHED",
				"-j", "ACCEPT",
			},
		}
	)

	// Set NAT.
	if ic.ipMasqMode {
		if err := programChainRule(natRule, "NAT", enable); err != nil {
			return err
		}
	}

	// In hairpin mode, masquerade traffic from localhost
	if ic.hairpinMode {
		if err := programChainRule(hpNatRule, "MASQ LOCAL HOST", enable); err != nil {
			return err
		}
	}

	// Set Inter Container Communication.
	if err := setIcc(ic.bridgeName, ic.iccMode, enable); err != nil {
		return err
	}

	// Set Accept on all non-intercontainer outgoing packets.
	if err := programChainRule(outRule, "ACCEPT NON_ICC OUTGOING", enable); err != nil {
		return err
	}

	// Set Accept on incoming packets for existing connections.
	if err := programChainRule(inRule, "ACCEPT INCOMING", enable); err != nil {
		return err
	}

	return nil
}

func (ic *iptablesConfig) forwardToTor(action iptables.Action) error {
	// route dns requests and tcp requests
	lines := [][]string{
		[]string{
			"-t", string(iptables.Nat),
			string(action), "PREROUTING",
			"-i", ic.bridgeName,
			"-p", "udp",
			"--dport", "53",
			"-j", "REDIRECT",
			"--to-ports", torDNSPort,
		},
		[]string{
			"-t", string(iptables.Nat),
			string(action), "PREROUTING",
			"-i", ic.bridgeName,
			"-p", "tcp",
			"--syn",
			"-j", "REDIRECT",
			"--to-ports", torTransparentProxyPort,
		},
	}
	for _, args := range lines {
		if output, err := iptables.Raw(args...); err != nil {
			return err
		} else if len(output) != 0 {
			return iptables.ChainError{Chain: "PREROUTING", Output: output}
		}
	}

	// block udp traffic
	if ic.blockUDP {
		lines := [][]string{
			[]string{
				"-t", string(iptables.Filter),
				string(action), "FORWARD",
				"-i", ic.bridgeName,
				"-p", "udp",
				"-j", "DROP",
			},
			[]string{
				"-t", string(iptables.Filter),
				string(action), "FORWARD",
				"-o", ic.bridgeName,
				"-p", "udp",
				"-j", "DROP",
			},
			[]string{
				"-t", string(iptables.Filter),
				string(action), "TOR",
				"-p", "udp",
				"-j", "DROP",
			},
		}
		for _, args := range lines {
			if output, err := iptables.Raw(args...); err != nil {
				return err
			} else if len(output) != 0 {
				return iptables.ChainError{Chain: "FORWARD", Output: output}
			}
		}
	}

	return nil
}
