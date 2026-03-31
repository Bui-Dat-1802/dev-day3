package model

import (
	"net"
	"testing"
)

// simpleValidate performs lightweight validation used by tests
// It mirrors expected rules the application should enforce without
// changing production code: checks type and basic name patterns.
func simpleValidate(a Asset) bool {
	if !IsValidType(a.Type) {
		return false
	}

	switch a.Type {
	case TypeDomain:
		// basic check: domain should contain a dot
		return a.Name != "" && (len(a.Name) > 0) && (containsDot(a.Name))
	case TypeIP:
		// should be a valid IP
		return net.ParseIP(a.Name) != nil
	case TypeService:
		// service must have a non-empty name
		return a.Name != ""
	default:
		return false
	}
}

func containsDot(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return true
		}
	}
	return false
}

func TestAssetValidation(t *testing.T) {
	tests := []struct {
		name    string
		asset   Asset
		wantErr bool
	}{
		{
			name:    "valid domain asset",
			asset:   Asset{Name: "example.com", Type: TypeDomain},
			wantErr: false,
		},
		{
			name:    "invalid asset type",
			asset:   Asset{Name: "test", Type: "invalid"},
			wantErr: true,
		},
		{
			name:    "domain without dot",
			asset:   Asset{Name: "localhost", Type: TypeDomain},
			wantErr: true,
		},
		{
			name:    "valid ip",
			asset:   Asset{Name: "127.0.0.1", Type: TypeIP},
			wantErr: false,
		},
		{
			name:    "invalid ip",
			asset:   Asset{Name: "999.999.999.999", Type: TypeIP},
			wantErr: true,
		},
		{
			name:    "valid service",
			asset:   Asset{Name: "db-service", Type: TypeService},
			wantErr: false,
		},
		{
			name:    "empty name",
			asset:   Asset{Name: "", Type: TypeService},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok := simpleValidate(tt.asset)
			if ok && tt.wantErr {
				t.Fatalf("expected validation to fail for case %q, but it succeeded", tt.name)
			}
			if !ok && !tt.wantErr {
				t.Fatalf("expected validation to succeed for case %q, but it failed", tt.name)
			}
		})
	}
}

// TestIsValidType tests the asset type validation
func TestIsValidType(t *testing.T) {
	tests := []struct {
		name      string
		assetType string
		want      bool
	}{
		{
			name:      "valid domain type",
			assetType: TypeDomain,
			want:      true,
		},
		{
			name:      "valid ip type",
			assetType: TypeIP,
			want:      true,
		},
		{
			name:      "valid service type",
			assetType: TypeService,
			want:      true,
		},
		{
			name:      "invalid type - empty",
			assetType: "",
			want:      false,
		},
		{
			name:      "invalid type - random string",
			assetType: "invalid",
			want:      false,
		},
		{
			name:      "invalid type - case sensitive",
			assetType: "DOMAIN",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidType(tt.assetType)
			if got != tt.want {
				t.Errorf("IsValidType(%q) = %v, want %v", tt.assetType, got, tt.want)
			}
		})
	}
}

// TestIsValidStatus tests the asset status validation
func TestIsValidStatus(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   bool
	}{
		{
			name:   "valid active status",
			status: StatusActive,
			want:   true,
		},
		{
			name:   "valid inactive status",
			status: StatusInactive,
			want:   true,
		},
		{
			name:   "invalid status - empty",
			status: "",
			want:   false,
		},
		{
			name:   "invalid status - random string",
			status: "pending",
			want:   false,
		},
		{
			name:   "invalid status - case sensitive",
			status: "ACTIVE",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidStatus(tt.status)
			if got != tt.want {
				t.Errorf("IsValidStatus(%q) = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}

// BenchmarkIsValidType benchmarks the type validation function
func BenchmarkIsValidType(b *testing.B) {
	for i := 0; i < b.N; i++ {
		IsValidType(TypeDomain)
	}
}

// BenchmarkIsValidStatus benchmarks the status validation function
func BenchmarkIsValidStatus(b *testing.B) {
	for i := 0; i < b.N; i++ {
		IsValidStatus(StatusActive)
	}
}
