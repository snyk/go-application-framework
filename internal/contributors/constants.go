package contributors

import "github.com/snyk/go-application-framework/internal/apiclients/contributors_ingest"

// EntityType identifies the kind of Snyk entity a captured ID refers to.
type EntityType = contributors_ingest.EntityType

// EntityTypeProject identifies a captured ID as a Snyk project ID.
const EntityTypeProject = contributors_ingest.EntityTypeProject

// EntityTypeRevision identifies a captured ID as a Snyk revision ID.
const EntityTypeRevision = contributors_ingest.EntityTypeRevision
