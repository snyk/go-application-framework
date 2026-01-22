package configuration

import "errors"

// ErrNoUserPreferredOrganization is returned when the user has no preferred organization configured.
var ErrNoUserPreferredOrganization = errors.New("no user preferred organization configured")

// GetUserPreferredOrganization returns the user's preferred organization UUID.
// This is intended for internal GAF use when determining organization fallback.
func GetUserPreferredOrganization(config Configuration) (string, error) {
	preferredOrg, err := config.GetStringWithError(userPreferredOrganization)
	if err != nil {
		return "", err
	}
	if preferredOrg == "" {
		return "", ErrNoUserPreferredOrganization
	}
	return preferredOrg, nil
}

// IsUserPreferredOrganization checks if the given orgUUID matches the user's
// preferred organization as configured in the Snyk web UI.
func IsUserPreferredOrganization(config Configuration, orgUUID string) (bool, error) {
	preferredOrg, err := GetUserPreferredOrganization(config)
	if err != nil {
		return false, err
	}
	return preferredOrg == orgUUID, nil
}

// RegisterUserPreferredOrganizationDefault registers the default value function
// for the user's preferred organization and sets up cache invalidation key dependencies.
// keyDependencies are the configuration keys that the defaultFunc depends on;
// when any of these keys change, the cached user preferred organization value is cleared.
func RegisterUserPreferredOrganizationDefault(config Configuration, defaultFunc DefaultValueFunction, keyDependencies []string) error {
	for _, dep := range keyDependencies {
		if err := config.AddKeyDependency(userPreferredOrganization, dep); err != nil {
			return err
		}
	}
	config.AddDefaultValue(userPreferredOrganization, defaultFunc)
	return nil
}
