package json_schemas

// TODO: this should be dynamically fetched if possible; it is owned by Analytics API not by GAF
const AnalyticsV2EventSchema = `{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "type": "object",
  "required": ["data"],
  "properties": {
    "data": {
      "$ref": "#/schemas/AnalyticsData"
    }
  },
  "schemas": {
    "AnalyticsData": {
      "type": "object",
      "required": [
        "type",
        "attributes"
      ],
      "properties": {
        "type": {
          "type": "string",
          "description": "The type of data ('analytics')."
        },
        "attributes": {
          "$ref": "#/schemas/AnalyticsAttributes"
        }
      }
    },
    "AnalyticsAttributes": {
      "type": "object",
      "required": [
        "interaction"
      ],
      "properties": {
        "interaction": {
          "$ref": "#/schemas/Interaction"
        },
        "runtime": {
          "$ref": "#/schemas/Runtime"
        }
      }
    },
    "Interaction": {
      "type": "object",
      "required": [
        "id",
        "timestamp_ms",
        "type",
        "status",
        "target"
      ],
      "properties": {
        "id": {
          "type": "string",
          "format": "uri",
          "description": "The client-generated ID of the interaction event in the form of  'urn:snyk:interaction:00000000-0000-0000-0000-000000000000'\n"
        },
        "timestamp_ms": {
          "type": "integer",
          "format": "int64",
          "description": "The timestamp in epoch milliseconds when the interaction was started in UTC (Zulu time)."
        },
        "stage": {
          "type": "string",
          "description": "The stage of the SDLC where the Interaction occurred, such as 'dev'|'cicd'|'prchecks'|'unknown'.",
          "enum": [
            "dev",
            "cicd",
            "prchecks",
            "unknown"
          ]
        },
        "type": {
          "type": "string",
          "description": "The type of interaction, could be 'Scan done'. Scan Done indicates that a test was run no  matter if the CLI or IDE ran it, other types can be freely chosen types.\n"
        },
        "categories": {
          "type": "array",
          "items": {
            "type": "string"
          },
          "description": "The category vector used to describe the interaction in detail, 'oss','test'."
        },
        "status": {
          "type": "string",
          "description": "Status would be 'success' or 'failure', where success means the action was executed,  while failure means it didn't run.\n"
        },
        "results": {
          "type": "array",
          "description": "The result of the interaction. Could be a something like this [{'name': 'critical', 'count': 0}].\nOnly strings, integers, and boolean values are allowed.\n",
          "items": {
            "type": "object",
            "additionalProperties": true
          }
        },
        "target": {
          "$ref": "#/schemas/Target"
        },
        "errors": {
          "type": "array",
          "items": {
            "$ref": "#/schemas/InteractionError"
          }
        },
        "extension": {
          "type": "object",
          "description": "Optional additional extension.\n\nOnly strings, integers, and boolean values are allowed.\n",
          "additionalProperties": true
        }
      }
    },
    "Runtime": {
      "type": "object",
      "properties": {
        "application": {
          "$ref": "#/schemas/Application"
        },
        "integration": {
          "$ref": "#/schemas/Integration"
        },
        "environment": {
          "$ref": "#/schemas/Environment"
        },
        "platform": {
          "$ref": "#/schemas/Platform"
        },
        "performance": {
          "$ref": "#/schemas/Performance"
        }
      }
    },
    "Target": {
      "type": "object",
      "required": [
        "id"
      ],
      "properties": {
        "id": {
          "type": "string",
          "format": "uri",
          "description": "A purl is a URL composed of seven components.\nscheme:type/namespace/name@version?qualifiers#subpath\n\nThe purl specification is available here:\n\n'https://github.com/package-url/purl-spec'\n\nSome purl examples\n\n'pkg:github/package-url/purl-spec@244fd47e07d1004f0aed9c'\n\n'pkg:npm/%40angular/animation@12.3.1'\n\n'pkg:pypi/django@1.11.1'\n"
        }
      }
    },
    "InteractionError": {
      "type": "object",
      "required": [
        "id"
      ],
      "properties": {
        "id": {
          "type": "string",
          "description": "Error identifier corresponding to the errors defined in the error catalog.\n\n'https://docs.snyk.io/scan-with-snyk/error-catalog'\n"
        },
        "code": {
          "type": "string",
          "description": "The HTTP specific error code."
        }
      }
    },
    "Application": {
      "type": "object",
      "required": [
        "name",
        "version"
      ],
      "description": "The application name, e.g. snyk-ls. The version of the integration.\n",
      "properties": {
        "name": {
          "type": "string"
        },
        "version": {
          "type": "string"
        }
      }
    },
    "Integration": {
      "type": "object",
      "required": [
        "name",
        "version"
      ],
      "description": "TODO UPDATE with correct samples of integration name. The name of the integration, could be a plugin or extension (e.g. Snyk Security plugin for intelliJ). The version of the integration (2.3.4).\n",
      "properties": {
        "name": {
          "type": "string"
        },
        "version": {
          "type": "string"
        }
      }
    },
    "Environment": {
      "type": "object",
      "required": [
        "name",
        "version"
      ],
      "description": "The environment for the integration (e.g., IntelliJ Ultimate, Pycharm). The version of the integration environment (e.g. 2023.3)\n",
      "properties": {
        "name": {
          "type": "string"
        },
        "version": {
          "type": "string"
        }
      }
    },
    "Platform": {
      "type": "object",
      "required": [
        "os",
        "arch"
      ],
      "description": "The operating system and the architecture (AMD64, ARM64, 386, ALPINE).",
      "properties": {
        "os": {
          "type": "string"
        },
        "arch": {
          "type": "string"
        }
      }
    },
    "Performance": {
      "type": "object",
      "required": [
        "duration_ms"
      ],
      "description": "The scan duration in milliseconds",
      "properties": {
        "duration_ms": {
          "type": "integer",
          "format": "int64"
        }
      }
    },
    "JsonApi": {
      "type": "object",
      "properties": {
        "version": {
          "type": "string",
          "pattern": "^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)$",
          "description": "Version of the JSON API specification this server supports.",
          "example": "1.0"
        }
      },
      "required": [
        "version"
      ],
      "additionalProperties": false,
      "example": {
        "version": "1.0"
      }
    },
    "ErrorLink": {
      "type": "object",
      "description": "A link that leads to further details about this particular occurrence of the problem.",
      "properties": {
        "about": {
          "$ref": "#/schemas/LinkProperty"
        }
      },
      "additionalProperties": false,
      "example": {
        "about": "https://example.com/about_this_error"
      }
    },
    "LinkProperty": {
      "oneOf": [
        {
          "type": "string",
          "description": "A string containing the link’s URL.",
          "example": "https://example.com/api/resource"
        },
        {
          "type": "object",
          "properties": {
            "href": {
              "type": "string",
              "description": "A string containing the link’s URL.",
              "example": "https://example.com/api/resource"
            },
            "meta": {
              "$ref": "#/schemas/Meta"
            }
          },
          "required": [
            "href"
          ],
          "additionalProperties": false,
          "example": {
            "href": "https://example.com/api/resource"
          }
        }
      ],
      "example": "https://example.com/api/resource"
    },
    "Meta": {
      "type": "object",
      "description": "Free-form object that may contain non-standard information.",
      "example": {
        "key1": "value1",
        "key2": {
          "sub_key": "sub_value"
        },
        "key3": [
          "array_value1",
          "array_value2"
        ]
      },
      "additionalProperties": true,
      "properties": {}
    },
    "ErrorDocument": {
      "type": "object",
      "properties": {
        "jsonapi": {
          "$ref": "#/schemas/JsonApi"
        },
        "errors": {
          "type": "array",
          "items": {
            "$ref": "#/schemas/Error"
          },
          "minItems": 1,
          "example": [
            {
              "status": "403",
              "detail": "Permission denied for this resource"
            }
          ]
        }
      },
      "additionalProperties": false,
      "required": [
        "jsonapi",
        "errors"
      ],
      "example": {
        "jsonapi": {
          "version": "1.0"
        },
        "errors": [
          {
            "status": "403",
            "detail": "Permission denied for this resource"
          }
        ]
      }
    },
    "Error": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string",
          "format": "uuid",
          "description": "A unique identifier for this particular occurrence of the problem.",
          "example": "f16c31b5-6129-4571-add8-d589da9be524"
        },
        "links": {
          "$ref": "#/schemas/ErrorLink"
        },
        "status": {
          "type": "string",
          "pattern": "^[45]\\d\\d$",
          "description": "The HTTP status code applicable to this problem, expressed as a string value.",
          "example": "400"
        },
        "detail": {
          "type": "string",
          "description": "A human-readable explanation specific to this occurrence of the problem.",
          "example": "The request was missing these required fields: ..."
        },
        "code": {
          "type": "string",
          "description": "An application-specific error code, expressed as a string value.",
          "example": "entity-not-found"
        },
        "title": {
          "type": "string",
          "description": "A short, human-readable summary of the problem that SHOULD NOT change from occurrence to occurrence of the problem, except for purposes of localization.",
          "example": "Bad request"
        },
        "source": {
          "type": "object",
          "properties": {
            "pointer": {
              "type": "string",
              "description": "A JSON Pointer [RFC6901] to the associated entity in the request document.",
              "example": "/data/attributes"
            },
            "parameter": {
              "type": "string",
              "description": "A string indicating which URI query parameter caused the error.",
              "example": "param1"
            }
          },
          "additionalProperties": false,
          "example": {
            "pointer": "/data/attributes"
          }
        },
        "meta": {
          "type": "object",
          "additionalProperties": true,
          "example": {
            "key": "value"
          },
          "properties": {}
        }
      },
      "required": [
        "status",
        "detail"
      ],
      "additionalProperties": false,
      "example": {
        "status": "404",
        "detail": "Not Found"
      }
    },
    "QueryVersion": {
      "type": "string",
      "description": "Requested API version",
      "pattern": "^(wip|work-in-progress|experimental|beta|((([0-9]{4})-([0-1][0-9]))-((3[01])|(0[1-9])|([12][0-9]))(~(wip|work-in-progress|experimental|beta))?))$"
    },
    "ActualVersion": {
      "type": "string",
      "description": "Resolved API version",
      "pattern": "^((([0-9]{4})-([0-1][0-9]))-((3[01])|(0[1-9])|([12][0-9]))(~(wip|work-in-progress|experimental|beta))?)$"
    }
  }
}
`
