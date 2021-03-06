package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/docker/engine-api/client/transport"
	"github.com/docker/engine-api/types"
)

func TestVolumeInspectError(t *testing.T) {
	client := &Client{
		transport: transport.NewMockClient(nil, transport.ErrorMock(http.StatusInternalServerError, "Server error")),
	}

	_, err := client.VolumeInspect("nothing")
	if err == nil || err.Error() != "Error response from daemon: Server error" {
		t.Fatalf("expected a Server Error, got %v", err)
	}
}

func TestVolumeInspectNotFound(t *testing.T) {
	client := &Client{
		transport: transport.NewMockClient(nil, transport.ErrorMock(http.StatusNotFound, "Server error")),
	}

	_, err := client.VolumeInspect("unknown")
	if err == nil || !IsErrVolumeNotFound(err) {
		t.Fatalf("expected a volumeNotFound error, got %v", err)
	}
}

func TestVolumeInspect(t *testing.T) {
	expectedURL := "/volumes/volume_id"
	client := &Client{
		transport: transport.NewMockClient(nil, func(req *http.Request) (*http.Response, error) {
			if !strings.HasPrefix(req.URL.Path, expectedURL) {
				return nil, fmt.Errorf("Expected URL '%s', got '%s'", expectedURL, req.URL)
			}
			if req.Method != "GET" {
				return nil, fmt.Errorf("expected GET method, got %s", req.Method)
			}
			content, err := json.Marshal(types.Volume{
				Name:       "name",
				Driver:     "driver",
				Mountpoint: "mountpoint",
			})
			if err != nil {
				return nil, err
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       ioutil.NopCloser(bytes.NewReader(content)),
			}, nil
		}),
	}

	v, err := client.VolumeInspect("volume_id")
	if err != nil {
		t.Fatal(err)
	}
	if v.Name != "name" {
		t.Fatalf("expected `name`, got %s", v.Name)
	}
	if v.Driver != "driver" {
		t.Fatalf("expected `driver`, got %s", v.Driver)
	}
	if v.Mountpoint != "mountpoint" {
		t.Fatalf("expected `mountpoint`, got %s", v.Mountpoint)
	}
}
