package tor

import (
	"encoding/json"
	"fmt"

	"github.com/docker/libnetwork/netlabel"
)

// TODO: The implementation of this bullshit with marshal and unmarshal sucks. Fix it.
func parseEndpointOptions(epOptions map[string]interface{}) (*endpointConfiguration, error) {
	if epOptions == nil {
		return nil, nil
	}

	ec := &endpointConfiguration{}

	if opts, ok := epOptions[netlabel.PortMap]; ok {
		o, err := json.Marshal(opts)
		if err != nil {
			return nil, fmt.Errorf("PortMap marshal error: %v", err)
		}
		if err := json.Unmarshal(o, &ec.PortBindings); err != nil {
			return nil, fmt.Errorf("PortMap umarshal error: %v", err)
		}
	}

	if opts, ok := epOptions[netlabel.ExposedPorts]; ok {
		o, err := json.Marshal(opts)
		if err != nil {
			return nil, fmt.Errorf("ExposedPorts marshal error: %v", err)
		}
		if err := json.Unmarshal(o, &ec.ExposedPorts); err != nil {
			return nil, fmt.Errorf("ExposedPorts umarshal error: %v", err)
		}
	}

	return ec, nil
}
