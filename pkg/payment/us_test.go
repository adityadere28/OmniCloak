package payment

import "testing"

func TestUSRoutingAndMICR(t *testing.T) {
	tests := []struct {
		given   string
		run     func() (Result, error)
		want    Reason
		wantErr bool
	}{
		{"ACH routing", func() (Result, error) { return ValidateABARoutingForRail("021000021", RoutingACH) }, ReasonValid, false},
		{"wire routing", func() (Result, error) { return ValidateABARoutingForRail("021000021", RoutingWire) }, ReasonValid, false},
		{"check routing", func() (Result, error) { return ValidateABARoutingForRail("021000021", RoutingCheck) }, ReasonValid, false},
		{"invalid routing prefix", func() (Result, error) { return ValidateABARoutingForRail("991000025", RoutingACH) }, ReasonRuleMismatch, false},
		{"unsupported rail", func() (Result, error) { return ValidateABARoutingForRail("021000021", "unknown") }, ReasonInvalidFormat, true},
		{"MICR components", func() (Result, error) { return ValidateUSCheckMICR("021000021", "123456789", "1234") }, ReasonValid, false},
		{"MICR invalid account", func() (Result, error) { return ValidateUSCheckMICR("021000021", "12A", "1234") }, ReasonInvalidCharacter, false},
	}
	for _, tt := range tests {
		t.Run("Given_"+tt.given+"_When_validating_Then_"+string(tt.want), func(t *testing.T) {
			got, err := tt.run()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an invalid-configuration error")
				}
				return
			}
			if err != nil || got.Reason != tt.want {
				t.Fatalf("validation = %+v, %v; want reason %q", got, err, tt.want)
			}
		})
	}
}

func TestNACHAFields(t *testing.T) {
	tests := []struct {
		given string
		run   func() (Result, error)
		want  Reason
	}{
		{"company ID", func() (Result, error) { return ValidateACHCompanyID("1234567890") }, ReasonValid},
		{"trace number", func() (Result, error) { return ValidateACHTraceNumber("123456780000001") }, ReasonValid},
		{"return code", func() (Result, error) { return ValidateACHReturnCode("R01") }, ReasonValid},
		{"unknown return code", func() (Result, error) { return ValidateACHReturnCode("R99") }, ReasonRuleMismatch},
		{"NOC code", func() (Result, error) { return ValidateNOCCode("C01") }, ReasonValid},
		{"invalid NOC code", func() (Result, error) { return ValidateNOCCode("C99") }, ReasonRuleMismatch},
	}
	for _, tt := range tests {
		t.Run("Given_"+tt.given+"_When_validating_Then_"+string(tt.want), func(t *testing.T) {
			got, err := tt.run()
			if err != nil || got.Reason != tt.want {
				t.Fatalf("validation = %+v, %v; want reason %q", got, err, tt.want)
			}
		})
	}
}

func TestUSIdentifiersAndAVS(t *testing.T) {
	tests := []struct {
		given string
		run   func() (Result, error)
		want  Reason
	}{
		{"EIN format", func() (Result, error) { return ValidateEIN("12-3456789") }, ReasonValid},
		{"EIN invalid prefix", func() (Result, error) { return ValidateEIN("00-3456789") }, ReasonRuleMismatch},
		{"ITIN structure", func() (Result, error) { return ValidateITIN("912-70-1234") }, ReasonValid},
		{"ITIN invalid middle", func() (Result, error) { return ValidateITIN("912-66-1234") }, ReasonRuleMismatch},
		{"SSN structure", func() (Result, error) { return ValidateSSN("123-45-6789") }, ReasonValid},
		{"SSN invalid area", func() (Result, error) { return ValidateSSN("000-45-6789") }, ReasonRuleMismatch},
		{"ZIP five digits", func() (Result, error) { return ValidateUSZIP("12345") }, ReasonValid},
		{"ZIP plus four", func() (Result, error) { return ValidateUSZIP("12345-6789") }, ReasonValid},
		{"ZIP bad separator", func() (Result, error) { return ValidateUSZIP("1234567890") }, ReasonInvalidCharacter},
		{"AVS address and ZIP", func() (Result, error) { return ValidateAVSAddress("123 TEST WAY", "12345") }, ReasonValid},
		{"AVS invalid ZIP", func() (Result, error) { return ValidateAVSAddress("123 TEST WAY", "ABCDE") }, ReasonInvalidCharacter},
		{"consumer account type", func() (Result, error) { return ValidateAccountKind("consumer") }, ReasonValid},
		{"commercial account type", func() (Result, error) { return ValidateAccountKind("commercial") }, ReasonValid},
		{"unknown account type", func() (Result, error) { return ValidateAccountKind("other") }, ReasonRuleMismatch},
	}
	for _, tt := range tests {
		t.Run("Given_"+tt.given+"_When_validating_Then_"+string(tt.want), func(t *testing.T) {
			got, err := tt.run()
			if err != nil || got.Reason != tt.want {
				t.Fatalf("validation = %+v, %v; want reason %q", got, err, tt.want)
			}
		})
	}
}
