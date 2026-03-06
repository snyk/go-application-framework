package testapi

// GetDefaultFindingTypes returns the FindingTypes based on which scan configuration fields are set.
// Returns nil if no configuration is set or if the configuration cannot be determined.
// This method provides a way to determine the expected finding types even when no findings exist.
func (s *ScanConfiguration) GetDefaultFindingTypes() []FindingType {
	if s == nil {
		return nil
	}

	var types []FindingType

	if s.Sca != nil {
		types = append(types, FindingTypeSca)
	}
	if s.Sast != nil {
		types = append(types, FindingTypeSast)
	}
	if s.Iac != nil {
		types = append(types, FindingTypeConfig)
	}
	if s.Container != nil {
		types = append(types, FindingTypeSca)
	}
	if s.Secrets != nil {
		types = append(types, FindingTypeSecret)
	}

	return types
}
