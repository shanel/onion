package tor

import (
	"fmt"

	"github.com/Sirupsen/logrus"
	"github.com/docker/libnetwork/iptables"
)

const (
	// TorChain is the TOR iptable chain name.
	TorChain                = "TOR"
	hairpinMode             = false
	torTransparentProxyPort = "22340"
	torDNSPort              = "22353"
)

func setupIPChains() (*iptables.ChainInfo, *iptables.ChainInfo, error) {
	natChain, err := iptables.NewChain(TorChain, iptables.Nat, hairpinMode)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create NAT chain: %s", err.Error())
	}
	defer func() {
		if err != nil {
			if err := iptables.RemoveExistingChain(TorChain, iptables.Nat); err != nil {
				logrus.Warnf("Failed on removing iptables NAT chain on cleanup: %v", err)
			}
		}
	}()

	filterChain, err := iptables.NewChain(TorChain, iptables.Filter, hairpinMode)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create FILTER chain: %s", err.Error())
	}

	return natChain, filterChain, nil
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

func setIcc(bridgeIface string, iccEnable, insert bool) error {
	var (
		table      = iptables.Filter
		chain      = "FORWARD"
		args       = []string{"-i", bridgeIface, "-o", bridgeIface, "-p", "tcp", "-j"}
		acceptArgs = append(args, "ACCEPT")
		dropArgs   = append(args, "DROP")
	)

	if insert {
		if !iccEnable {
			iptables.Raw(append([]string{"-D", chain}, acceptArgs...)...)

			if !iptables.Exists(table, chain, dropArgs...) {
				if output, err := iptables.Raw(append([]string{"-A", chain}, dropArgs...)...); err != nil {
					return fmt.Errorf("Unable to prevent intercontainer communication: %v", err)
				} else if len(output) != 0 {
					return fmt.Errorf("Error disabling intercontainer communication: %s", output)
				}
			}
		} else {
			iptables.Raw(append([]string{"-D", chain}, dropArgs...)...)

			if !iptables.Exists(table, chain, acceptArgs...) {
				if output, err := iptables.Raw(append([]string{"-I", chain}, acceptArgs...)...); err != nil {
					return fmt.Errorf("Unable to allow intercontainer communication: %v", err)
				} else if len(output) != 0 {
					return fmt.Errorf("Error enabling intercontainer communication: %s", output)
				}
			}
		}
	} else {
		// Remove any ICC rule.
		if !iccEnable {
			if iptables.Exists(table, chain, dropArgs...) {
				iptables.Raw(append([]string{"-D", chain}, dropArgs...)...)
			}
		} else {
			if iptables.Exists(table, chain, acceptArgs...) {
				iptables.Raw(append([]string{"-D", chain}, acceptArgs...)...)
			}
		}
	}

	return nil
}
