package tor

import (
	"reflect"
	"testing"

	"github.com/docker/go-plugins-helpers/network"
)

func TestEndpointInfo(t *testing.T) {

	want := &network.InfoResponse{
		Value: make(map[string]string),
	}

	ir := &network.InfoRequest{}
	d := tor.Driver{}
	got, err := d.EndpointInfo(ir)
	if !reflect.DeepEqual(want, got) || err != nil {
		t.Fatalf("EndpointInfo(%v) == %v, %v; want %v, nil", ir, got, err, want)
	}
}
