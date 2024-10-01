package sarif

import "list"

// Static Analysis Results Format (SARIF) Version 2.1.0 JSON
// Schema
//
// Static Analysis Results Format (SARIF) Version 2.1.0 JSON
// Schema: a standard format for the output of static analysis
// tools.
@jsonschema(schema="http://json-schema.org/draft-04/schema#")
@jsonschema(id="https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json")

// The URI of the JSON schema corresponding to the version.
$schema?: string

// The SARIF format version of this log file.
version!: "2.1.0"

// The set of runs contained in this log file.
runs!: [...] & [...#run]

// References to external property files that share data between
// runs.
inlineExternalProperties?: list.UniqueItems() & [...] & [...#externalProperties]

// Key/value pairs that provide additional information about the
// log file.
properties?: #propertyBag

#address: {
	// The address expressed as a byte offset from the start of the
	// addressable region.
	absoluteAddress?: int & >=-1 | *-1

	// The address expressed as a byte offset from the absolute
	// address of the top-most parent object.
	relativeAddress?: int

	// The number of bytes in this range of addresses.
	length?: int

	// An open-ended string that identifies the address kind. 'data',
	// 'function', 'header','instruction', 'module', 'page',
	// 'section', 'segment', 'stack', 'stackFrame', 'table' are
	// well-known values.
	kind?: string

	// A name that is associated with the address, e.g., '.text'.
	name?: string

	// A human-readable fully qualified name that is associated with
	// the address.
	fullyQualifiedName?: string

	// The byte offset of this address from the absolute or relative
	// address of the parent object.
	offsetFromParent?: int

	// The index within run.addresses of the cached object for this
	// address.
	index?: int & >=-1 | *-1

	// The index within run.addresses of the parent object.
	parentIndex?: int & >=-1 | *-1

	// Key/value pairs that provide additional information about the
	// address.
	properties?: #propertyBag
}

#artifact: {
	// A short description of the artifact.
	description?: #message

	// The location of the artifact.
	location?: #artifactLocation

	// Identifies the index of the immediate parent of the artifact,
	// if this artifact is nested.
	parentIndex?: int & >=-1 | *-1

	// The offset in bytes of the artifact within its containing
	// artifact.
	offset?: int & >=0

	// The length of the artifact in bytes.
	length?: int & >=-1 | *-1

	// The role or roles played by the artifact in the analysis.
	roles?: list.UniqueItems() & [...] & [..."analysisTarget" | "attachment" | "responseFile" | "resultFile" | "standardStream" | "tracedFile" | "unmodified" | "modified" | "added" | "deleted" | "renamed" | "uncontrolled" | "driver" | "extension" | "translation" | "taxonomy" | "policy" | "referencedOnCommandLine" | "memoryContents" | "directory" | "userSpecifiedConfiguration" | "toolSpecifiedConfiguration" | "debugOutputFile"]

	// The MIME type (RFC 2045) of the artifact.
	mimeType?: =~"[^/]+/.+"

	// The contents of the artifact.
	contents?: #artifactContent

	// Specifies the encoding for an artifact object that refers to a
	// text file.
	encoding?: string

	// Specifies the source language for any artifact object that
	// refers to a text file that contains source code.
	sourceLanguage?: string

	// A dictionary, each of whose keys is the name of a hash function
	// and each of whose values is the hashed value of the artifact
	// produced by the specified hash function.
	hashes?: {
		[string]: string
	}

	// The Coordinated Universal Time (UTC) date and time at which the
	// artifact was most recently modified. See "Date/time
	// properties" in the SARIF spec for the required format.
	lastModifiedTimeUtc?: string

	// Key/value pairs that provide additional information about the
	// artifact.
	properties?: #propertyBag
}

#artifactChange: {
	// The location of the artifact to change.
	artifactLocation!: #artifactLocation

	// An array of replacement objects, each of which represents the
	// replacement of a single region in a single artifact specified
	// by 'artifactLocation'.
	replacements!: [_, ...] & [...#replacement]

	// Key/value pairs that provide additional information about the
	// change.
	properties?: #propertyBag
}

#artifactContent: {
	// UTF-8-encoded content from a text artifact.
	text?: string

	// MIME Base64-encoded content from a binary artifact, or from a
	// text artifact in its original encoding.
	binary?: string

	// An alternate rendered representation of the artifact (e.g., a
	// decompiled representation of a binary region).
	rendered?: #multiformatMessageString

	// Key/value pairs that provide additional information about the
	// artifact content.
	properties?: #propertyBag
}

#artifactLocation: {
	// A string containing a valid relative or absolute URI.
	uri?: string

	// A string which indirectly specifies the absolute URI with
	// respect to which a relative URI in the "uri" property is
	// interpreted.
	uriBaseId?: string

	// The index within the run artifacts array of the artifact object
	// associated with the artifact location.
	index?: int & >=-1 | *-1

	// A short description of the artifact location.
	description?: #message

	// Key/value pairs that provide additional information about the
	// artifact location.
	properties?: #propertyBag
}

#attachment: {
	// A message describing the role played by the attachment.
	description?: #message

	// The location of the attachment.
	artifactLocation!: #artifactLocation

	// An array of regions of interest within the attachment.
	regions?: list.UniqueItems() & [...] & [...#region]

	// An array of rectangles specifying areas of interest within the
	// image.
	rectangles?: list.UniqueItems() & [...] & [...#rectangle]

	// Key/value pairs that provide additional information about the
	// attachment.
	properties?: #propertyBag
}

#codeFlow: {
	// A message relevant to the code flow.
	message?: #message

	// An array of one or more unique threadFlow objects, each of
	// which describes the progress of a program through a thread of
	// execution.
	threadFlows!: [_, ...] & [...#threadFlow]

	// Key/value pairs that provide additional information about the
	// code flow.
	properties?: #propertyBag
}

#configurationOverride: {
	// Specifies how the rule or notification was configured during
	// the scan.
	configuration!: #reportingConfiguration

	// A reference used to locate the descriptor whose configuration
	// was overridden.
	descriptor!: #reportingDescriptorReference

	// Key/value pairs that provide additional information about the
	// configuration override.
	properties?: #propertyBag
}

#conversion: {
	// A tool object that describes the converter.
	tool!: #tool

	// An invocation object that describes the invocation of the
	// converter.
	invocation?: #invocation

	// The locations of the analysis tool's per-run log files.
	analysisToolLogFiles?: list.UniqueItems() & [...] & [...#artifactLocation]

	// Key/value pairs that provide additional information about the
	// conversion.
	properties?: #propertyBag
}

#edge: {
	// A string that uniquely identifies the edge within its graph.
	id!: string

	// A short description of the edge.
	label?: #message

	// Identifies the source node (the node at which the edge starts).
	sourceNodeId!: string

	// Identifies the target node (the node at which the edge ends).
	targetNodeId!: string

	// Key/value pairs that provide additional information about the
	// edge.
	properties?: #propertyBag
}

#edgeTraversal: {
	// Identifies the edge being traversed.
	edgeId!: string

	// A message to display to the user as the edge is traversed.
	message?: #message

	// The values of relevant expressions after the edge has been
	// traversed.
	finalState?: {
		[string]: #multiformatMessageString
	}

	// The number of edge traversals necessary to return from a nested
	// graph.
	stepOverEdgeCount?: int & >=0

	// Key/value pairs that provide additional information about the
	// edge traversal.
	properties?: #propertyBag
}

#exception: {
	// A string that identifies the kind of exception, for example,
	// the fully qualified type name of an object that was thrown, or
	// the symbolic name of a signal.
	kind?: string

	// A message that describes the exception.
	message?: string

	// The sequence of function calls leading to the exception.
	stack?: #stack

	// An array of exception objects each of which is considered a
	// cause of this exception.
	innerExceptions?: [...] & [...#exception]

	// Key/value pairs that provide additional information about the
	// exception.
	properties?: #propertyBag
	...
}

#externalProperties: {
	// The URI of the JSON schema corresponding to the version of the
	// external property file format.
	schema?: string

	// The SARIF format version of this external properties object.
	version?: "2.1.0"

	// A stable, unique identifer for this external properties object,
	// in the form of a GUID.
	guid?: =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// A stable, unique identifer for the run associated with this
	// external properties object, in the form of a GUID.
	runGuid?: =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// A conversion object that will be merged with a separate run.
	conversion?: #conversion

	// An array of graph objects that will be merged with a separate
	// run.
	graphs?: list.UniqueItems() & [...] & [...#graph]

	// Key/value pairs that provide additional information that will
	// be merged with a separate run.
	externalizedProperties?: #propertyBag

	// An array of artifact objects that will be merged with a
	// separate run.
	artifacts?: list.UniqueItems() & [...] & [...#artifact]

	// Describes the invocation of the analysis tool that will be
	// merged with a separate run.
	invocations?: [...] & [...#invocation]

	// An array of logical locations such as namespaces, types or
	// functions that will be merged with a separate run.
	logicalLocations?: list.UniqueItems() & [...] & [...#logicalLocation]

	// An array of threadFlowLocation objects that will be merged with
	// a separate run.
	threadFlowLocations?: list.UniqueItems() & [...] & [...#threadFlowLocation]

	// An array of result objects that will be merged with a separate
	// run.
	results?: [...] & [...#result]

	// Tool taxonomies that will be merged with a separate run.
	taxonomies?: list.UniqueItems() & [...] & [...#toolComponent]

	// The analysis tool object that will be merged with a separate
	// run.
	driver?: #toolComponent

	// Tool extensions that will be merged with a separate run.
	extensions?: list.UniqueItems() & [...] & [...#toolComponent]

	// Tool policies that will be merged with a separate run.
	policies?: list.UniqueItems() & [...] & [...#toolComponent]

	// Tool translations that will be merged with a separate run.
	translations?: list.UniqueItems() & [...] & [...#toolComponent]

	// Addresses that will be merged with a separate run.
	addresses?: [...] & [...#address]

	// Requests that will be merged with a separate run.
	webRequests?: list.UniqueItems() & [...] & [...#webRequest]

	// Responses that will be merged with a separate run.
	webResponses?: list.UniqueItems() & [...] & [...#webResponse]

	// Key/value pairs that provide additional information about the
	// external properties.
	properties?: #propertyBag
	...
}

#externalPropertyFileReference: ({
	location!: _
	...
} | {
	guid!: _
	...
}) & {
	// The location of the external property file.
	location?: #artifactLocation

	// A stable, unique identifer for the external property file in
	// the form of a GUID.
	guid?: =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// A non-negative integer specifying the number of items contained
	// in the external property file.
	itemCount?: int & >=-1 | *-1

	// Key/value pairs that provide additional information about the
	// external property file.
	properties?: #propertyBag
	...
}

#externalPropertyFileReferences: {
	// An external property file containing a run.conversion object to
	// be merged with the root log file.
	conversion?: #externalPropertyFileReference

	// An array of external property files containing a run.graphs
	// object to be merged with the root log file.
	graphs?: list.UniqueItems() & [...] & [...#externalPropertyFileReference]

	// An external property file containing a run.properties object to
	// be merged with the root log file.
	externalizedProperties?: #externalPropertyFileReference

	// An array of external property files containing run.artifacts
	// arrays to be merged with the root log file.
	artifacts?: list.UniqueItems() & [...] & [...#externalPropertyFileReference]

	// An array of external property files containing run.invocations
	// arrays to be merged with the root log file.
	invocations?: list.UniqueItems() & [...] & [...#externalPropertyFileReference]

	// An array of external property files containing
	// run.logicalLocations arrays to be merged with the root log
	// file.
	logicalLocations?: list.UniqueItems() & [...] & [...#externalPropertyFileReference]

	// An array of external property files containing
	// run.threadFlowLocations arrays to be merged with the root log
	// file.
	threadFlowLocations?: list.UniqueItems() & [...] & [...#externalPropertyFileReference]

	// An array of external property files containing run.results
	// arrays to be merged with the root log file.
	results?: list.UniqueItems() & [...] & [...#externalPropertyFileReference]

	// An array of external property files containing run.taxonomies
	// arrays to be merged with the root log file.
	taxonomies?: list.UniqueItems() & [...] & [...#externalPropertyFileReference]

	// An array of external property files containing run.addresses
	// arrays to be merged with the root log file.
	addresses?: list.UniqueItems() & [...] & [...#externalPropertyFileReference]

	// An external property file containing a run.driver object to be
	// merged with the root log file.
	driver?: #externalPropertyFileReference

	// An array of external property files containing run.extensions
	// arrays to be merged with the root log file.
	extensions?: list.UniqueItems() & [...] & [...#externalPropertyFileReference]

	// An array of external property files containing run.policies
	// arrays to be merged with the root log file.
	policies?: list.UniqueItems() & [...] & [...#externalPropertyFileReference]

	// An array of external property files containing run.translations
	// arrays to be merged with the root log file.
	translations?: list.UniqueItems() & [...] & [...#externalPropertyFileReference]

	// An array of external property files containing run.requests
	// arrays to be merged with the root log file.
	webRequests?: list.UniqueItems() & [...] & [...#externalPropertyFileReference]

	// An array of external property files containing run.responses
	// arrays to be merged with the root log file.
	webResponses?: list.UniqueItems() & [...] & [...#externalPropertyFileReference]

	// Key/value pairs that provide additional information about the
	// external property files.
	properties?: #propertyBag
}

#fix: {
	// A message that describes the proposed fix, enabling viewers to
	// present the proposed change to an end user.
	description?: #message

	// One or more artifact changes that comprise a fix for a result.
	artifactChanges!: list.UniqueItems() & [_, ...] & [...#artifactChange]

	// Key/value pairs that provide additional information about the
	// fix.
	properties?: #propertyBag
}

#graph: {
	// A description of the graph.
	description?: #message

	// An array of node objects representing the nodes of the graph.
	nodes?: list.UniqueItems() & [...] & [...#node]

	// An array of edge objects representing the edges of the graph.
	edges?: list.UniqueItems() & [...] & [...#edge]

	// Key/value pairs that provide additional information about the
	// graph.
	properties?: #propertyBag
}

#graphTraversal: ({
	runGraphIndex!: _
	...
} | {
	resultGraphIndex!: _
	...
}) & {
	// The index within the run.graphs to be associated with the
	// result.
	runGraphIndex?: int & >=-1 | *-1

	// The index within the result.graphs to be associated with the
	// result.
	resultGraphIndex?: int & >=-1 | *-1

	// A description of this graph traversal.
	description?: #message

	// Values of relevant expressions at the start of the graph
	// traversal that may change during graph traversal.
	initialState?: {
		[string]: #multiformatMessageString
	}

	// Values of relevant expressions at the start of the graph
	// traversal that remain constant for the graph traversal.
	immutableState?: {
		[string]: #multiformatMessageString
	}

	// The sequences of edges traversed by this graph traversal.
	edgeTraversals?: [...] & [...#edgeTraversal]

	// Key/value pairs that provide additional information about the
	// graph traversal.
	properties?: #propertyBag
}

#invocation: {
	// The command line used to invoke the tool.
	commandLine?: string

	// An array of strings, containing in order the command line
	// arguments passed to the tool from the operating system.
	arguments?: [...] & [...string]

	// The locations of any response files specified on the tool's
	// command line.
	responseFiles?: list.UniqueItems() & [...] & [...#artifactLocation]

	// The Coordinated Universal Time (UTC) date and time at which the
	// run started. See "Date/time properties" in the SARIF spec for
	// the required format.
	startTimeUtc?: string

	// The Coordinated Universal Time (UTC) date and time at which the
	// run ended. See "Date/time properties" in the SARIF spec for
	// the required format.
	endTimeUtc?: string

	// The process exit code.
	exitCode?: int

	// An array of configurationOverride objects that describe rules
	// related runtime overrides.
	ruleConfigurationOverrides?: list.UniqueItems() & [...] & [...#configurationOverride]

	// An array of configurationOverride objects that describe
	// notifications related runtime overrides.
	notificationConfigurationOverrides?: list.UniqueItems() & [...] & [...#configurationOverride]

	// A list of runtime conditions detected by the tool during the
	// analysis.
	toolExecutionNotifications?: [...] & [...#notification]

	// A list of conditions detected by the tool that are relevant to
	// the tool's configuration.
	toolConfigurationNotifications?: [...] & [...#notification]

	// The reason for the process exit.
	exitCodeDescription?: string

	// The name of the signal that caused the process to exit.
	exitSignalName?: string

	// The numeric value of the signal that caused the process to
	// exit.
	exitSignalNumber?: int

	// The reason given by the operating system that the process
	// failed to start.
	processStartFailureMessage?: string

	// Specifies whether the tool's execution completed successfully.
	executionSuccessful!: bool

	// The machine that hosted the analysis tool run.
	machine?: string

	// The account that ran the analysis tool.
	account?: string

	// The process id for the analysis tool run.
	processId?: int

	// An absolute URI specifying the location of the analysis tool's
	// executable.
	executableLocation?: #artifactLocation

	// The working directory for the analysis tool run.
	workingDirectory?: #artifactLocation

	// The environment variables associated with the analysis tool
	// process, expressed as key/value pairs.
	environmentVariables?: {
		[string]: string
	}

	// A file containing the standard input stream to the process that
	// was invoked.
	stdin?: #artifactLocation

	// A file containing the standard output stream from the process
	// that was invoked.
	stdout?: #artifactLocation

	// A file containing the standard error stream from the process
	// that was invoked.
	stderr?: #artifactLocation

	// A file containing the interleaved standard output and standard
	// error stream from the process that was invoked.
	stdoutStderr?: #artifactLocation

	// Key/value pairs that provide additional information about the
	// invocation.
	properties?: #propertyBag
}

#location: {
	// Value that distinguishes this location from all other locations
	// within a single result object.
	id?: int & >=-1 | *-1

	// Identifies the artifact and region.
	physicalLocation?: #physicalLocation

	// The logical locations associated with the result.
	logicalLocations?: list.UniqueItems() & [...] & [...#logicalLocation]

	// A message relevant to the location.
	message?: #message

	// A set of regions relevant to the location.
	annotations?: list.UniqueItems() & [...] & [...#region]

	// An array of objects that describe relationships between this
	// location and others.
	relationships?: list.UniqueItems() & [...] & [...#locationRelationship]

	// Key/value pairs that provide additional information about the
	// location.
	properties?: #propertyBag
}

#locationRelationship: {
	// A reference to the related location.
	target!: int & >=0

	// A set of distinct strings that categorize the relationship.
	// Well-known kinds include 'includes', 'isIncludedBy' and
	// 'relevant'.
	kinds?: list.UniqueItems() & [...string] | *["relevant"]

	// A description of the location relationship.
	description?: #message

	// Key/value pairs that provide additional information about the
	// location relationship.
	properties?: #propertyBag
}

#logicalLocation: {
	// Identifies the construct in which the result occurred. For
	// example, this property might contain the name of a class or a
	// method.
	name?: string

	// The index within the logical locations array.
	index?: int & >=-1 | *-1

	// The human-readable fully qualified name of the logical
	// location.
	fullyQualifiedName?: string

	// The machine-readable name for the logical location, such as a
	// mangled function name provided by a C++ compiler that encodes
	// calling convention, return type and other details along with
	// the function name.
	decoratedName?: string

	// Identifies the index of the immediate parent of the construct
	// in which the result was detected. For example, this property
	// might point to a logical location that represents the
	// namespace that holds a type.
	parentIndex?: int & >=-1 | *-1

	// The type of construct this logical location component refers
	// to. Should be one of 'function', 'member', 'module',
	// 'namespace', 'parameter', 'resource', 'returnType', 'type',
	// 'variable', 'object', 'array', 'property', 'value', 'element',
	// 'text', 'attribute', 'comment', 'declaration', 'dtd' or
	// 'processingInstruction', if any of those accurately describe
	// the construct.
	kind?: string

	// Key/value pairs that provide additional information about the
	// logical location.
	properties?: #propertyBag
}

#message: {
	text!: _
	...
} & {
	// A plain text message string.
	text?: string

	// A Markdown message string.
	markdown?: string

	// The identifier for this message.
	id?: string

	// An array of strings to substitute into the message string.
	arguments?: [...] & [...string]

	// Key/value pairs that provide additional information about the
	// message.
	properties?: #propertyBag
}

#multiformatMessageString: {
	// A plain text message string or format string.
	text!: string

	// A Markdown message string or format string.
	markdown?: string

	// Key/value pairs that provide additional information about the
	// message.
	properties?: #propertyBag
}

#node: {
	// A string that uniquely identifies the node within its graph.
	id!: string

	// A short description of the node.
	label?: #message

	// A code location associated with the node.
	location?: #location

	// Array of child nodes.
	children?: list.UniqueItems() & [...] & [...#node]

	// Key/value pairs that provide additional information about the
	// node.
	properties?: #propertyBag
}

#notification: {
	// The locations relevant to this notification.
	locations?: list.UniqueItems() & [...] & [...#location]

	// A message that describes the condition that was encountered.
	message!: #message

	// A value specifying the severity level of the notification.
	level?: "none" | "note" | "warning" | "error" | *"warning"

	// The thread identifier of the code that generated the
	// notification.
	threadId?: int

	// The Coordinated Universal Time (UTC) date and time at which the
	// analysis tool generated the notification.
	timeUtc?: string

	// The runtime exception, if any, relevant to this notification.
	exception?: #exception

	// A reference used to locate the descriptor relevant to this
	// notification.
	descriptor?: #reportingDescriptorReference

	// A reference used to locate the rule descriptor associated with
	// this notification.
	associatedRule?: #reportingDescriptorReference

	// Key/value pairs that provide additional information about the
	// notification.
	properties?: #propertyBag
}

#physicalLocation: {
	artifactLocation!: _
	...
} & {
	// The address of the location.
	address?: #address

	// The location of the artifact.
	artifactLocation?: #artifactLocation

	// Specifies a portion of the artifact.
	region?: #region

	// Specifies a portion of the artifact that encloses the region.
	// Allows a viewer to display additional context around the
	// region.
	contextRegion?: #region

	// Key/value pairs that provide additional information about the
	// physical location.
	properties?: #propertyBag
}

#propertyBag: {
	// A set of distinct strings that provide additional information.
	tags?: list.UniqueItems() & [...] & [...string]
	...
}

#rectangle: {
	// The Y coordinate of the top edge of the rectangle, measured in
	// the image's natural units.
	top?: number

	// The X coordinate of the left edge of the rectangle, measured in
	// the image's natural units.
	left?: number

	// The Y coordinate of the bottom edge of the rectangle, measured
	// in the image's natural units.
	bottom?: number

	// The X coordinate of the right edge of the rectangle, measured
	// in the image's natural units.
	right?: number

	// A message relevant to the rectangle.
	message?: #message

	// Key/value pairs that provide additional information about the
	// rectangle.
	properties?: #propertyBag
}

#region: {
	// The line number of the first character in the region.
	startLine?: int & >=1

	// The column number of the first character in the region.
	startColumn?: int & >=1

	// The line number of the last character in the region.
	endLine?: int & >=1

	// The column number of the character following the end of the
	// region.
	endColumn?: int & >=1

	// The zero-based offset from the beginning of the artifact of the
	// first character in the region.
	charOffset?: int & >=-1 | *-1

	// The length of the region in characters.
	charLength?: int & >=0

	// The zero-based offset from the beginning of the artifact of the
	// first byte in the region.
	byteOffset?: int & >=-1 | *-1

	// The length of the region in bytes.
	byteLength?: int & >=0

	// The portion of the artifact contents within the specified
	// region.
	snippet?: #artifactContent

	// A message relevant to the region.
	message?: #message

	// Specifies the source language, if any, of the portion of the
	// artifact specified by the region object.
	sourceLanguage?: string

	// Key/value pairs that provide additional information about the
	// region.
	properties?: #propertyBag
}

#replacement: {
	// The region of the artifact to delete.
	deletedRegion!: #region

	// The content to insert at the location specified by the
	// 'deletedRegion' property.
	insertedContent?: #artifactContent

	// Key/value pairs that provide additional information about the
	// replacement.
	properties?: #propertyBag
}

#reportingDescriptor: {
	// A stable, opaque identifier for the report.
	id!: string

	// An array of stable, opaque identifiers by which this report was
	// known in some previous version of the analysis tool.
	deprecatedIds?: list.UniqueItems() & [...] & [...string]

	// A unique identifer for the reporting descriptor in the form of
	// a GUID.
	guid?: =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// An array of unique identifies in the form of a GUID by which
	// this report was known in some previous version of the analysis
	// tool.
	deprecatedGuids?: list.UniqueItems() & [...] & [...=~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"]

	// A report identifier that is understandable to an end user.
	name?: string

	// An array of readable identifiers by which this report was known
	// in some previous version of the analysis tool.
	deprecatedNames?: list.UniqueItems() & [...] & [...string]

	// A concise description of the report. Should be a single
	// sentence that is understandable when visible space is limited
	// to a single line of text.
	shortDescription?: #multiformatMessageString

	// A description of the report. Should, as far as possible,
	// provide details sufficient to enable resolution of any problem
	// indicated by the result.
	fullDescription?: #multiformatMessageString

	// A set of name/value pairs with arbitrary names. Each value is a
	// multiformatMessageString object, which holds message strings
	// in plain text and (optionally) Markdown format. The strings
	// can include placeholders, which can be used to construct a
	// message in combination with an arbitrary number of additional
	// string arguments.
	messageStrings?: {
		[string]: #multiformatMessageString
	}

	// Default reporting configuration information.
	defaultConfiguration?: #reportingConfiguration

	// A URI where the primary documentation for the report can be
	// found.
	helpUri?: string

	// Provides the primary documentation for the report, useful when
	// there is no online documentation.
	help?: #multiformatMessageString

	// An array of objects that describe relationships between this
	// reporting descriptor and others.
	relationships?: list.UniqueItems() & [...] & [...#reportingDescriptorRelationship]

	// Key/value pairs that provide additional information about the
	// report.
	properties?: #propertyBag
}

#reportingConfiguration: {
	// Specifies whether the report may be produced during the scan.
	enabled?: bool | *true

	// Specifies the failure level for the report.
	level?: "none" | "note" | "warning" | "error" | *"warning"

	// Specifies the relative priority of the report. Used for
	// analysis output only.
	rank?: >=-1.0 & <=100.0 | *-1.0

	// Contains configuration information specific to a report.
	parameters?: #propertyBag

	// Key/value pairs that provide additional information about the
	// reporting configuration.
	properties?: #propertyBag
}

#reportingDescriptorReference: ({
	index!: _
	...
} | {
	guid!: _
	...
} | {
	id!: _
	...
}) & {
	// The id of the descriptor.
	id?: string

	// The index into an array of descriptors in
	// toolComponent.ruleDescriptors,
	// toolComponent.notificationDescriptors, or
	// toolComponent.taxonomyDescriptors, depending on context.
	index?: int & >=-1 | *-1

	// A guid that uniquely identifies the descriptor.
	guid?: =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// A reference used to locate the toolComponent associated with
	// the descriptor.
	toolComponent?: #toolComponentReference

	// Key/value pairs that provide additional information about the
	// reporting descriptor reference.
	properties?: #propertyBag
}

#reportingDescriptorRelationship: {
	// A reference to the related reporting descriptor.
	target!: #reportingDescriptorReference

	// A set of distinct strings that categorize the relationship.
	// Well-known kinds include 'canPrecede', 'canFollow',
	// 'willPrecede', 'willFollow', 'superset', 'subset', 'equal',
	// 'disjoint', 'relevant', and 'incomparable'.
	kinds?: list.UniqueItems() & [...string] | *["relevant"]

	// A description of the reporting descriptor relationship.
	description?: #message

	// Key/value pairs that provide additional information about the
	// reporting descriptor reference.
	properties?: #propertyBag
}

#result: {
	// The stable, unique identifier of the rule, if any, to which
	// this notification is relevant. This member can be used to
	// retrieve rule metadata from the rules dictionary, if it
	// exists.
	ruleId?: string

	// The index within the tool component rules array of the rule
	// object associated with this result.
	ruleIndex?: int & >=-1 | *-1

	// A reference used to locate the rule descriptor relevant to this
	// result.
	rule?: #reportingDescriptorReference

	// A value that categorizes results by evaluation state.
	kind?: "notApplicable" | "pass" | "fail" | "review" | "open" | "informational" | *"fail"

	// A value specifying the severity level of the result.
	level?: "none" | "note" | "warning" | "error" | *"warning"

	// A message that describes the result. The first sentence of the
	// message only will be displayed when visible space is limited.
	message!: #message

	// Identifies the artifact that the analysis tool was instructed
	// to scan. This need not be the same as the artifact where the
	// result actually occurred.
	analysisTarget?: #artifactLocation

	// The set of locations where the result was detected. Specify
	// only one location unless the problem indicated by the result
	// can only be corrected by making a change at every specified
	// location.
	locations?: [...] & [...#location]

	// A stable, unique identifer for the result in the form of a
	// GUID.
	guid?: =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// A stable, unique identifier for the equivalence class of
	// logically identical results to which this result belongs, in
	// the form of a GUID.
	correlationGuid?: =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// A positive integer specifying the number of times this
	// logically unique result was observed in this run.
	occurrenceCount?: int & >=1

	// A set of strings that contribute to the stable, unique identity
	// of the result.
	partialFingerprints?: {
		[string]: string
	}

	// A set of strings each of which individually defines a stable,
	// unique identity for the result.
	fingerprints?: {
		[string]: string
	}

	// An array of 'stack' objects relevant to the result.
	stacks?: list.UniqueItems() & [...] & [...#stack]

	// An array of 'codeFlow' objects relevant to the result.
	codeFlows?: [...] & [...#codeFlow]

	// An array of zero or more unique graph objects associated with
	// the result.
	graphs?: list.UniqueItems() & [...] & [...#graph]

	// An array of one or more unique 'graphTraversal' objects.
	graphTraversals?: list.UniqueItems() & [...] & [...#graphTraversal]

	// A set of locations relevant to this result.
	relatedLocations?: list.UniqueItems() & [...] & [...#location]

	// A set of suppressions relevant to this result.
	suppressions?: list.UniqueItems() & [...] & [...#suppression] | null

	// The state of a result relative to a baseline of a previous run.
	baselineState?: "new" | "unchanged" | "updated" | "absent"

	// A number representing the priority or importance of the result.
	rank?: >=-1.0 & <=100.0 | *-1.0

	// A set of artifacts relevant to the result.
	attachments?: list.UniqueItems() & [...] & [...#attachment]

	// An absolute URI at which the result can be viewed.
	hostedViewerUri?: string

	// The URIs of the work items associated with this result.
	workItemUris?: list.UniqueItems() & [...] & [...string]

	// Information about how and when the result was detected.
	provenance?: #resultProvenance

	// An array of 'fix' objects, each of which represents a proposed
	// fix to the problem indicated by the result.
	fixes?: list.UniqueItems() & [...] & [...#fix]

	// An array of references to taxonomy reporting descriptors that
	// are applicable to the result.
	taxa?: list.UniqueItems() & [...] & [...#reportingDescriptorReference]

	// A web request associated with this result.
	webRequest?: #webRequest

	// A web response associated with this result.
	webResponse?: #webResponse

	// Key/value pairs that provide additional information about the
	// result.
	properties?: #propertyBag
}

#resultProvenance: {
	// The Coordinated Universal Time (UTC) date and time at which the
	// result was first detected. See "Date/time properties" in the
	// SARIF spec for the required format.
	firstDetectionTimeUtc?: string

	// The Coordinated Universal Time (UTC) date and time at which the
	// result was most recently detected. See "Date/time properties"
	// in the SARIF spec for the required format.
	lastDetectionTimeUtc?: string

	// A GUID-valued string equal to the automationDetails.guid
	// property of the run in which the result was first detected.
	firstDetectionRunGuid?: =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// A GUID-valued string equal to the automationDetails.guid
	// property of the run in which the result was most recently
	// detected.
	lastDetectionRunGuid?: =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// The index within the run.invocations array of the invocation
	// object which describes the tool invocation that detected the
	// result.
	invocationIndex?: int & >=-1 | *-1

	// An array of physicalLocation objects which specify the portions
	// of an analysis tool's output that a converter transformed into
	// the result.
	conversionSources?: list.UniqueItems() & [...] & [...#physicalLocation]

	// Key/value pairs that provide additional information about the
	// result.
	properties?: #propertyBag
}

#run: {
	// Information about the tool or tool pipeline that generated the
	// results in this run. A run can only contain results produced
	// by a single tool or tool pipeline. A run can aggregate results
	// from multiple log files, as long as context around the tool
	// run (tool command-line arguments and the like) is identical
	// for all aggregated files.
	tool!: #tool

	// Describes the invocation of the analysis tool.
	invocations?: [...] & [...#invocation]

	// A conversion object that describes how a converter transformed
	// an analysis tool's native reporting format into the SARIF
	// format.
	conversion?: #conversion

	// The language of the messages emitted into the log file during
	// this run (expressed as an ISO 639-1 two-letter lowercase
	// culture code) and an optional region (expressed as an ISO
	// 3166-1 two-letter uppercase subculture code associated with a
	// country or region). The casing is recommended but not required
	// (in order for this data to conform to RFC5646).
	language?: =~"^[a-zA-Z]{2}|^[a-zA-Z]{2}-[a-zA-Z]{2}]?$" | *"en-US"

	// Specifies the revision in version control of the artifacts that
	// were scanned.
	versionControlProvenance?: list.UniqueItems() & [...] & [...#versionControlDetails]

	// The artifact location specified by each uriBaseId symbol on the
	// machine where the tool originally ran.
	originalUriBaseIds?: {
		[string]: #artifactLocation
	}

	// An array of artifact objects relevant to the run.
	artifacts?: list.UniqueItems() & [...] & [...#artifact]

	// An array of logical locations such as namespaces, types or
	// functions.
	logicalLocations?: list.UniqueItems() & [...] & [...#logicalLocation]

	// An array of zero or more unique graph objects associated with
	// the run.
	graphs?: list.UniqueItems() & [...] & [...#graph]

	// The set of results contained in an SARIF log. The results array
	// can be omitted when a run is solely exporting rules metadata.
	// It must be present (but may be empty) if a log file represents
	// an actual scan.
	results?: [...] & [...#result]

	// Automation details that describe this run.
	automationDetails?: #runAutomationDetails

	// Automation details that describe the aggregate of runs to which
	// this run belongs.
	runAggregates?: list.UniqueItems() & [...] & [...#runAutomationDetails]

	// The 'guid' property of a previous SARIF 'run' that comprises
	// the baseline that was used to compute result 'baselineState'
	// properties for the run.
	baselineGuid?: =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// An array of strings used to replace sensitive information in a
	// redaction-aware property.
	redactionTokens?: list.UniqueItems() & [...] & [...string]

	// Specifies the default encoding for any artifact object that
	// refers to a text file.
	defaultEncoding?: string

	// Specifies the default source language for any artifact object
	// that refers to a text file that contains source code.
	defaultSourceLanguage?: string

	// An ordered list of character sequences that were treated as
	// line breaks when computing region information for the run.
	newlineSequences?: list.UniqueItems() & [_, ...] & [...string] | *["\r\n", "\n"]

	// Specifies the unit in which the tool measures columns.
	columnKind?: "utf16CodeUnits" | "unicodeCodePoints"

	// References to external property files that should be inlined
	// with the content of a root log file.
	externalPropertyFileReferences?: #externalPropertyFileReferences

	// An array of threadFlowLocation objects cached at run level.
	threadFlowLocations?: list.UniqueItems() & [...] & [...#threadFlowLocation]

	// An array of toolComponent objects relevant to a taxonomy in
	// which results are categorized.
	taxonomies?: list.UniqueItems() & [...] & [...#toolComponent]

	// Addresses associated with this run instance, if any.
	addresses?: [...] & [...#address]

	// The set of available translations of the localized data
	// provided by the tool.
	translations?: list.UniqueItems() & [...] & [...#toolComponent]

	// Contains configurations that may potentially override both
	// reportingDescriptor.defaultConfiguration (the tool's default
	// severities) and invocation.configurationOverrides (severities
	// established at run-time from the command line).
	policies?: list.UniqueItems() & [...] & [...#toolComponent]

	// An array of request objects cached at run level.
	webRequests?: list.UniqueItems() & [...] & [...#webRequest]

	// An array of response objects cached at run level.
	webResponses?: list.UniqueItems() & [...] & [...#webResponse]

	// A specialLocations object that defines locations of special
	// significance to SARIF consumers.
	specialLocations?: #specialLocations

	// Key/value pairs that provide additional information about the
	// run.
	properties?: #propertyBag
}

#runAutomationDetails: {
	// A description of the identity and role played within the
	// engineering system by this object's containing run object.
	description?: #message

	// A hierarchical string that uniquely identifies this object's
	// containing run object.
	id?: string

	// A stable, unique identifer for this object's containing run
	// object in the form of a GUID.
	guid?: =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// A stable, unique identifier for the equivalence class of runs
	// to which this object's containing run object belongs in the
	// form of a GUID.
	correlationGuid?: =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// Key/value pairs that provide additional information about the
	// run automation details.
	properties?: #propertyBag
}

#specialLocations: {
	// Provides a suggestion to SARIF consumers to display file paths
	// relative to the specified location.
	displayBase?: #artifactLocation

	// Key/value pairs that provide additional information about the
	// special locations.
	properties?: #propertyBag
	...
}

#stack: {
	// A message relevant to this call stack.
	message?: #message

	// An array of stack frames that represents a sequence of calls,
	// rendered in reverse chronological order, that comprise the
	// call stack.
	frames!: [...] & [...#stackFrame]

	// Key/value pairs that provide additional information about the
	// stack.
	properties?: #propertyBag
}

#stackFrame: {
	// The location to which this stack frame refers.
	location?: #location

	// The name of the module that contains the code of this stack
	// frame.
	module?: string

	// The thread identifier of the stack frame.
	threadId?: int

	// The parameters of the call that is executing.
	parameters?: [...] & [...string | *[]]

	// Key/value pairs that provide additional information about the
	// stack frame.
	properties?: #propertyBag
}

#suppression: {
	// A stable, unique identifer for the suprression in the form of a
	// GUID.
	guid?: =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// A string that indicates where the suppression is persisted.
	kind!: "inSource" | "external"

	// A string that indicates the state of the suppression.
	state?: "accepted" | "underReview" | "rejected"

	// A string representing the justification for the suppression.
	justification?: string

	// Identifies the location associated with the suppression.
	location?: #location

	// Key/value pairs that provide additional information about the
	// suppression.
	properties?: #propertyBag
}

#threadFlow: {
	// An string that uniquely identifies the threadFlow within the
	// codeFlow in which it occurs.
	id?: string

	// A message relevant to the thread flow.
	message?: #message

	// Values of relevant expressions at the start of the thread flow
	// that may change during thread flow execution.
	initialState?: {
		[string]: #multiformatMessageString
	}

	// Values of relevant expressions at the start of the thread flow
	// that remain constant.
	immutableState?: {
		[string]: #multiformatMessageString
	}

	// A temporally ordered array of 'threadFlowLocation' objects,
	// each of which describes a location visited by the tool while
	// producing the result.
	locations!: [_, ...] & [...#threadFlowLocation]

	// Key/value pairs that provide additional information about the
	// thread flow.
	properties?: #propertyBag
	...
}

#threadFlowLocation: {
	// The index within the run threadFlowLocations array.
	index?: int & >=-1 | *-1

	// The code location.
	location?: #location

	// The call stack leading to this location.
	stack?: #stack

	// A set of distinct strings that categorize the thread flow
	// location. Well-known kinds include 'acquire', 'release',
	// 'enter', 'exit', 'call', 'return', 'branch', 'implicit',
	// 'false', 'true', 'caution', 'danger', 'unknown',
	// 'unreachable', 'taint', 'function', 'handler', 'lock',
	// 'memory', 'resource', 'scope' and 'value'.
	kinds?: list.UniqueItems() & [...] & [...string]

	// An array of references to rule or taxonomy reporting
	// descriptors that are applicable to the thread flow location.
	taxa?: list.UniqueItems() & [...] & [...#reportingDescriptorReference]

	// The name of the module that contains the code that is
	// executing.
	module?: string

	// A dictionary, each of whose keys specifies a variable or
	// expression, the associated value of which represents the
	// variable or expression value. For an annotation of kind
	// 'continuation', for example, this dictionary might hold the
	// current assumed values of a set of global variables.
	state?: {
		[string]: #multiformatMessageString
	}

	// An integer representing a containment hierarchy within the
	// thread flow.
	nestingLevel?: int & >=0

	// An integer representing the temporal order in which execution
	// reached this location.
	executionOrder?: int & >=-1 | *-1

	// The Coordinated Universal Time (UTC) date and time at which
	// this location was executed.
	executionTimeUtc?: string

	// Specifies the importance of this location in understanding the
	// code flow in which it occurs. The order from most to least
	// important is "essential", "important", "unimportant". Default:
	// "important".
	importance?: "important" | "essential" | "unimportant" | *"important"

	// A web request associated with this thread flow location.
	webRequest?: #webRequest

	// A web response associated with this thread flow location.
	webResponse?: #webResponse

	// Key/value pairs that provide additional information about the
	// threadflow location.
	properties?: #propertyBag
}

#tool: {
	// The analysis tool that was run.
	driver!: #toolComponent

	// Tool extensions that contributed to or reconfigured the
	// analysis tool that was run.
	extensions?: list.UniqueItems() & [...] & [...#toolComponent]

	// Key/value pairs that provide additional information about the
	// tool.
	properties?: #propertyBag
}

#toolComponent: {
	// A unique identifer for the tool component in the form of a
	// GUID.
	guid?: =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// The name of the tool component.
	name!: string

	// The organization or company that produced the tool component.
	organization?: string

	// A product suite to which the tool component belongs.
	product?: string

	// A localizable string containing the name of the suite of
	// products to which the tool component belongs.
	productSuite?: string

	// A brief description of the tool component.
	shortDescription?: #multiformatMessageString

	// A comprehensive description of the tool component.
	fullDescription?: #multiformatMessageString

	// The name of the tool component along with its version and any
	// other useful identifying information, such as its locale.
	fullName?: string

	// The tool component version, in whatever format the component
	// natively provides.
	version?: string

	// The tool component version in the format specified by Semantic
	// Versioning 2.0.
	semanticVersion?: string

	// The binary version of the tool component's primary executable
	// file expressed as four non-negative integers separated by a
	// period (for operating systems that express file versions in
	// this way).
	dottedQuadFileVersion?: =~"[0-9]+(\\.[0-9]+){3}"

	// A string specifying the UTC date (and optionally, the time) of
	// the component's release.
	releaseDateUtc?: string

	// The absolute URI from which the tool component can be
	// downloaded.
	downloadUri?: string

	// The absolute URI at which information about this version of the
	// tool component can be found.
	informationUri?: string

	// A dictionary, each of whose keys is a resource identifier and
	// each of whose values is a multiformatMessageString object,
	// which holds message strings in plain text and (optionally)
	// Markdown format. The strings can include placeholders, which
	// can be used to construct a message in combination with an
	// arbitrary number of additional string arguments.
	globalMessageStrings?: {
		[string]: #multiformatMessageString
	}

	// An array of reportingDescriptor objects relevant to the
	// notifications related to the configuration and runtime
	// execution of the tool component.
	notifications?: list.UniqueItems() & [...] & [...#reportingDescriptor]

	// An array of reportingDescriptor objects relevant to the
	// analysis performed by the tool component.
	rules?: list.UniqueItems() & [...] & [...#reportingDescriptor]

	// An array of reportingDescriptor objects relevant to the
	// definitions of both standalone and tool-defined taxonomies.
	taxa?: list.UniqueItems() & [...] & [...#reportingDescriptor]

	// An array of the artifactLocation objects associated with the
	// tool component.
	locations?: [...] & [...#artifactLocation]

	// The language of the messages emitted into the log file during
	// this run (expressed as an ISO 639-1 two-letter lowercase
	// language code) and an optional region (expressed as an ISO
	// 3166-1 two-letter uppercase subculture code associated with a
	// country or region). The casing is recommended but not required
	// (in order for this data to conform to RFC5646).
	language?: =~"^[a-zA-Z]{2}|^[a-zA-Z]{2}-[a-zA-Z]{2}]?$" | *"en-US"

	// The kinds of data contained in this object.
	contents?: list.UniqueItems() & [..."localizedData" | "nonLocalizedData"] | *["localizedData", "nonLocalizedData"]

	// Specifies whether this object contains a complete definition of
	// the localizable and/or non-localizable data for this
	// component, as opposed to including only data that is relevant
	// to the results persisted to this log file.
	isComprehensive?: bool | *false

	// The semantic version of the localized strings defined in this
	// component; maintained by components that provide translations.
	localizedDataSemanticVersion?: string

	// The minimum value of localizedDataSemanticVersion required in
	// translations consumed by this component; used by components
	// that consume translations.
	minimumRequiredLocalizedDataSemanticVersion?: string

	// The component which is strongly associated with this component.
	// For a translation, this refers to the component which has been
	// translated. For an extension, this is the driver that provides
	// the extension's plugin model.
	associatedComponent?: #toolComponentReference

	// Translation metadata, required for a translation, not populated
	// by other component types.
	translationMetadata?: #translationMetadata

	// An array of toolComponentReference objects to declare the
	// taxonomies supported by the tool component.
	supportedTaxonomies?: list.UniqueItems() & [...] & [...#toolComponentReference]

	// Key/value pairs that provide additional information about the
	// tool component.
	properties?: #propertyBag
}

#toolComponentReference: {
	// The 'name' property of the referenced toolComponent.
	name?: string

	// An index into the referenced toolComponent in tool.extensions.
	index?: int & >=-1 | *-1

	// The 'guid' property of the referenced toolComponent.
	guid?: =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// Key/value pairs that provide additional information about the
	// toolComponentReference.
	properties?: #propertyBag
	...
}

#translationMetadata: {
	// The name associated with the translation metadata.
	name!: string

	// The full name associated with the translation metadata.
	fullName?: string

	// A brief description of the translation metadata.
	shortDescription?: #multiformatMessageString

	// A comprehensive description of the translation metadata.
	fullDescription?: #multiformatMessageString

	// The absolute URI from which the translation metadata can be
	// downloaded.
	downloadUri?: string

	// The absolute URI from which information related to the
	// translation metadata can be downloaded.
	informationUri?: string

	// Key/value pairs that provide additional information about the
	// translation metadata.
	properties?: #propertyBag
	...
}

#versionControlDetails: {
	// The absolute URI of the repository.
	repositoryUri!: string

	// A string that uniquely and permanently identifies the revision
	// within the repository.
	revisionId?: string

	// The name of a branch containing the revision.
	branch?: string

	// A tag that has been applied to the revision.
	revisionTag?: string

	// A Coordinated Universal Time (UTC) date and time that can be
	// used to synchronize an enlistment to the state of the
	// repository at that time.
	asOfTimeUtc?: string

	// The location in the local file system to which the root of the
	// repository was mapped at the time of the analysis.
	mappedTo?: #artifactLocation

	// Key/value pairs that provide additional information about the
	// version control details.
	properties?: #propertyBag
}

#webRequest: {
	// The index within the run.webRequests array of the request
	// object associated with this result.
	index?: int & >=-1 | *-1

	// The request protocol. Example: 'http'.
	protocol?: string

	// The request version. Example: '1.1'.
	version?: string

	// The target of the request.
	target?: string

	// The HTTP method. Well-known values are 'GET', 'PUT', 'POST',
	// 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT'.
	method?: string

	// The request headers.
	headers?: {
		[string]: string
	}

	// The request parameters.
	parameters?: {
		[string]: string
	}

	// The body of the request.
	body?: #artifactContent

	// Key/value pairs that provide additional information about the
	// request.
	properties?: #propertyBag
	...
}

#webResponse: {
	// The index within the run.webResponses array of the response
	// object associated with this result.
	index?: int & >=-1 | *-1

	// The response protocol. Example: 'http'.
	protocol?: string

	// The response version. Example: '1.1'.
	version?: string

	// The response status code. Example: 451.
	statusCode?: int

	// The response reason. Example: 'Not found'.
	reasonPhrase?: string

	// The response headers.
	headers?: {
		[string]: string
	}

	// The body of the response.
	body?: #artifactContent

	// Specifies whether a response was received from the server.
	noResponseReceived?: bool | *false

	// Key/value pairs that provide additional information about the
	// response.
	properties?: #propertyBag
	...
}
