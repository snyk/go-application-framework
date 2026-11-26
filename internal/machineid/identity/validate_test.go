package identity

import "testing"

func TestSerialFromBIOS(t *testing.T) {
	t.Parallel()

	serial := "C02Q7KHTGFWF"
	empty := ""

	tests := []struct {
		name string
		raw  *string
		want string
	}{
		{
			name: "null serial yields empty",
			raw:  nil,
			want: "",
		},
		{
			name: "empty serial yields empty",
			raw:  &empty,
			want: "",
		},
		{
			name: "present serial returned",
			raw:  &serial,
			want: "C02Q7KHTGFWF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := serialFromBIOS(tt.raw); got != tt.want {
				t.Errorf("serialFromBIOS() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeSerial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "valid serial",
			raw:  "C02Q7KHTGFWF",
			want: "C02Q7KHTGFWF",
		},
		{
			name: "valid serial with surrounding whitespace",
			raw:  "  C02Q7KHTGFWF  \n",
			want: "C02Q7KHTGFWF",
		},
		{
			name: "vmware serial kept",
			raw:  "VMware-42 1a2b3c4d5e6f",
			want: "VMware-42 1a2b3c4d5e6f",
		},
		{
			name: "empty",
			raw:  "",
			want: "",
		},
		{
			name: "whitespace only",
			raw:  "   ",
			want: "",
		},
		{
			name: "placeholder oem",
			raw:  "To be filled by O.E.M.",
			want: "",
		},
		{
			name: "placeholder none",
			raw:  "None",
			want: "",
		},
		{
			name: "placeholder zero",
			raw:  "0",
			want: "",
		},
		{
			name: "placeholder system serial number",
			raw:  "System Serial Number",
			want: "",
		},
		{
			name: "placeholder default string",
			raw:  "Default string",
			want: "",
		},
		{
			name: "placeholder none upper case",
			raw:  "NONE",
			want: "",
		},
		{
			name: "placeholder to be filled by oem without dots",
			raw:  "To Be Filled By OEM",
			want: "",
		},
		{
			name: "placeholder not specified",
			raw:  "Not Specified",
			want: "",
		},
		{
			name: "placeholder not applicable",
			raw:  "Not Applicable",
			want: "",
		},
		{
			name: "placeholder chassis serial number",
			raw:  "Chassis Serial Number",
			want: "",
		},
		{
			name: "placeholder invalid",
			raw:  "INVALID",
			want: "",
		},
		{
			name: "placeholder n/a",
			raw:  "n/a",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := NormalizeSerial(tt.raw); got != tt.want {
				t.Errorf("NormalizeSerial(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}
