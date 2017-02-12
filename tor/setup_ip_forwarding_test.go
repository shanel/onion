package tor

import (
	"bytes"
	"io/ioutil"
	"testing"
)

// TODO(shanel): Need to fix up these test to deal with passed in path and perms
func TestSetupIPForwarding(t *testing.T) {
	f, err := ioutil.TempFile("", "ipforwarding-test")
	if err != nil {
		t.Fatal(err)
	}
	filename := f.Name()
	data := "1\n"

	if err := ioutil.WriteFile(filename, []byte(data), 0644); err != nil {
		t.Fatalf("WriteFile %s: %v", filename, err)
	}

	// Disable IP Forwarding if enabled
	procSetting := readCurrentIPForwardingSetting(t, filename)
	if bytes.Compare(procSetting, []byte("1\n")) == 0 {
		writeIPForwardingSetting(t, filename, []byte{'0', '\n'})
	}

	// Set IP Forwarding
	if err := setupIPForwarding(filename, 0644); err != nil {
		t.Fatalf("Failed to setup IP forwarding: %v", err)
	}

	// Read new setting
	procSetting = readCurrentIPForwardingSetting(t, filename)
	if bytes.Compare(procSetting, []byte("1\n")) != 0 {
		t.Fatalf("Failed to effectively setup IP forwarding")
	}
}

func readCurrentIPForwardingSetting(t *testing.T, path string) []byte {
	procSetting, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatalf("Can't execute test: Failed to read current IP forwarding setting: %v", err)
	}
	return procSetting
}

func writeIPForwardingSetting(t *testing.T, path string, chars []byte) {
	err := ioutil.WriteFile(path, chars, 0644)
	if err != nil {
		t.Fatalf("Can't execute or cleanup after test: Failed to reset IP forwarding: %v", err)
	}
}
