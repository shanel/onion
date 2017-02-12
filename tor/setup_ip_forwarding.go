package tor

import (
	"fmt"
	"io/ioutil"
	"os"
)

func setupIPForwarding(path string, perms os.FileMode) error {
	// Get current IPv4 forward setup
	ipv4ForwardData, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("Cannot read IP forwarding setup: %v", err)
	}

	// Enable IPv4 forwarding only if it is not already enabled
	if ipv4ForwardData[0] != '1' {
		// Enable IPv4 forwarding
		if err := ioutil.WriteFile(path, []byte{'1', '\n'}, perms); err != nil {
			return fmt.Errorf("Setup IP forwarding failed: %v", err)
		}
	}

	return nil
}
