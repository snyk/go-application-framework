package instrumentation

import "testing"

func Test_GetProjectIdAndMonitorIdFromMonitorUrl(t *testing.T) {
	text := `Testing /home/antoine/Documents/SnykSB/goof ...

Open Issues

 ✗ [LOW] Use of Hardcoded Credentials
   Finding ID: 56fdeb92-25b8-4e4a-a062-fd1b6a68e346
   Path: typeorm-db.js, line 11
   Info: Do not hardcode credentials in code. Found hardcoded credential used in typeorm.createConnection.

 ✗ [LOW] Use of Hardcoded Passwords
   Finding ID: 4d0edc8e-b007-4fbd-96ad-5f8439152c7a
   Path: tests/authentication.component.spec.js, line 48
   Info: Do not hardcode passwords in code. Found hardcoded password used in changePassword.

 ✗ [LOW] Use of Hardcoded Passwords
   Finding ID: 3d75a56b-9732-4d84-8348-1d5b8c3ebc2b
   Path: tests/authentication.component.spec.js, line 48
   Info: Do not hardcode passwords in code. Found hardcoded password used in changePassword.

 ✗ [LOW] Use of Hardcoded Passwords
   Finding ID: 3ff041bb-45bd-4f13-b08b-ed5fb56cdb4e
   Path: tests/authentication.component.spec.js, line 35
   Info: Do not hardcode passwords in code. Found hardcoded password used in changePassword.

 ✗ [LOW] Use of Hardcoded Passwords
   Finding ID: 0afb365f-5b54-4630-beea-b987bd8c7560
   Path: tests/authentication.component.spec.js, line 35
   Info: Do not hardcode passwords in code. Found hardcoded password used in changePassword.

 ✗ [LOW] Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
   Finding ID: 0862b4f4-2d1d-4014-934c-6175c8bc3115
   Path: app.js, line 45
   Info: Cookie misses the Secure attribute (it is false by default). Set it to true to protect the cookie from man-in-the-middle attacks.

 ✗ [LOW] Use of Hardcoded Passwords
   Finding ID: 1ba6abc7-31a1-4768-a6e4-84d76aa1aa1b
   Path: tests/authentication.component.spec.js, line 24
   Info: Do not hardcode passwords in code. Found hardcoded password used in changePassword.

 ✗ [LOW] Use of Hardcoded Passwords
   Finding ID: bbfea606-d013-42e3-b26c-07985f5eae6a
   Path: tests/authentication.component.spec.js, line 24
   Info: Do not hardcode passwords in code. Found hardcoded password used in changePassword.

 ✗ [MEDIUM] Allocation of Resources Without Limits or Throttling
   Finding ID: 6f5840f0-b4d1-41bf-9047-ba8698ad5314
   Path: routes/index.js, line 75
   Info: Expensive operation (a file system operation) is performed by an endpoint handler which does not use a rate-limiting mechanism. It may enable the attackers to perform Denial-of-service attacks. Consider using a rate-limiting middleware such as express-limit.

 ✗ [MEDIUM] Allocation of Resources Without Limits or Throttling
   Finding ID: df6bf797-fb70-4107-b9ff-aca8c30b7115
   Path: routes/index.js, line 241
   Info: Expensive operation (a file system operation) is performed by an endpoint handler which does not use a rate-limiting mechanism. It may enable the attackers to perform Denial-of-service attacks. Consider using a rate-limiting middleware such as express-limit.

 ✗ [MEDIUM] Use of Hardcoded Passwords
   Finding ID: 09fa8eb9-117f-42a6-90fb-24eaadd60fbf
   Path: typeorm-db.js, line 12
   Info: Do not hardcode passwords in code. Found hardcoded password used in typeorm.createConnection.

 ✗ [MEDIUM] Cleartext Transmission - HTTP Instead of HTTPS
   Finding ID: e5a806b4-30d1-47ec-8bd3-13d11e5e7f0b
   Path: app.js, line 86
   Info: http.createServer uses HTTP which is an insecure protocol and should not be used in code due to cleartext transmission of information. Data in cleartext in a communication channel can be sniffed by unauthorized actors. Consider using the https module instead.

 ✗ [MEDIUM] Use of Hardcoded Passwords
   Finding ID: 1cecd1d1-2097-4a3a-904f-baa188c00468
   Path: mongoose-db.js, line 52
   Info: Do not hardcode passwords in code. Found hardcoded password used in password.

 ✗ [MEDIUM] Cross-Site Request Forgery (CSRF)
   Finding ID: 25c696b5-6ab0-4cbb-ae06-44c3b696e7f0
   Path: app.js, line 28
   Info: CSRF protection is disabled for your Express app. This allows the attackers to execute requests on a user's behalf.

 ✗ [MEDIUM] Open Redirect
   Finding ID: 353708b0-064f-4af9-95f7-ea9c246f8ee2
   Path: routes/index.js, line 61
   Info: Unsanitized input from the HTTP request body flows into redirect, where it is used as input for request redirection. This may result in an Open Redirect vulnerability.

 ✗ [MEDIUM] Allocation of Resources Without Limits or Throttling
   Finding ID: 303714ee-79e3-4cfa-96e8-d1a237476701
   Path: routes/index.js, line 152
   Info: Expensive operation (a system command execution) is performed by an endpoint handler which does not use a rate-limiting mechanism. It may enable the attackers to perform Denial-of-service attacks. Consider using a rate-limiting middleware such as express-limit.

 ✗ [MEDIUM] Allocation of Resources Without Limits or Throttling
   Finding ID: d64d17f7-6441-43c9-82a1-c6d8dfa6f145
   Path: routes/index.js, line 298
   Info: Expensive operation (a file system operation) is performed by an endpoint handler which does not use a rate-limiting mechanism. It may enable the attackers to perform Denial-of-service attacks. Consider using a rate-limiting middleware such as express-limit.

 ✗ [MEDIUM] Allocation of Resources Without Limits or Throttling
   Finding ID: 6f75850c-a2fa-4550-baab-76b8b4cccb14
   Path: routes/index.js, line 67
   Info: Expensive operation (a file system operation) is performed by an endpoint handler which does not use a rate-limiting mechanism. It may enable the attackers to perform Denial-of-service attacks. Consider using a rate-limiting middleware such as express-limit.

 ✗ [MEDIUM] Information Exposure - X-Powered-By Header
   Finding ID: 02e7cd17-b381-46dd-9909-9722ffe036c2
   Path: app.js, line 28
   Info: Disable X-Powered-By header for your Express app (consider using Helmet middleware), because it exposes information about the used framework to potential attackers.

 ✗ [MEDIUM] Allocation of Resources Without Limits or Throttling
   Finding ID: e746b22c-83e0-489c-a1fa-8e60a0b19079
   Path: routes/index.js, line 82
   Info: Expensive operation (a file system operation) is performed by an endpoint handler which does not use a rate-limiting mechanism. It may enable the attackers to perform Denial-of-service attacks. Consider using a rate-limiting middleware such as express-limit.

 ✗ [MEDIUM] Allocation of Resources Without Limits or Throttling
   Finding ID: 477afacb-d530-4119-ad55-c9513f1ef49f
   Path: routes/index.js, line 89
   Info: Expensive operation (a file system operation) is performed by an endpoint handler which does not use a rate-limiting mechanism. It may enable the attackers to perform Denial-of-service attacks. Consider using a rate-limiting middleware such as express-limit.

 ✗ [HIGH] Hardcoded Non-Cryptographic Secret
   Finding ID: 746d0c10-032e-47f1-83d0-147d4d5107a7
   Path: app.js, line 83
   Info: Avoid hardcoding values that are meant to be secret. Found a hardcoded string used in here.

 ✗ [HIGH] Hardcoded Non-Cryptographic Secret
   Finding ID: 709d9187-8a5d-4109-836a-0951c4ec6b32
   Path: app.js, line 42
   Info: Avoid hardcoding values that are meant to be secret. Found a hardcoded string used in express-session.

 ✗ [HIGH] NoSQL Injection
   Finding ID: 24f3f971-1729-4201-98a3-79a736ca7f52
   Path: routes/index.js, line 39
   Info: Unsanitized input from the HTTP request body flows into find, where it is used in an NoSQL query. This may result in an NoSQL Injection vulnerability.



╭─────────────────────────────────────────────────────────────╮
│ Test Summary                                                │
│                                                             │
│   Organization:      antoine-playground                     │
│   Test type:         Static code analysis                   │
│   Project path:      /home/antoine/Documents/SnykSB/goof    │
│                                                             │
│   Total issues:   24                                        │
│   Ignored issues: 0 [ 0 HIGH  0 MEDIUM  0 LOW ]             │
│   Open issues:    24 [ 3 HIGH  13 MEDIUM  8 LOW ]           │
╰─────────────────────────────────────────────────────────────╯

Report

  Your test results are available at:
  https://app.snyk.io/org/antoine-playground/project/1f94159a-ba57-4447-a2e8-4611a9509794/history/36cca17a-44c0-496d-824b-091a641306c3
    
💡 Tip

   To view ignored issues, use the --include-ignores option.
`

	pairs, err := GetProjectIdAndMonitorIdFromText(text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pairs) == 0 {
		t.Fatalf("expected at least one project/monitor pair, got none")
	}

	projectID := pairs[0][0]
	monitorID := pairs[0][1]

	expectedProjectID := "1f94159a-ba57-4447-a2e8-4611a9509794"
	expectedMonitorID := "36cca17a-44c0-496d-824b-091a641306c3"

	if projectID != expectedProjectID {
		t.Errorf("projectID mismatch: got %q, want %q", projectID, expectedProjectID)
	}

	if monitorID != expectedMonitorID {
		t.Errorf("monitorID mismatch: got %q, want %q", monitorID, expectedMonitorID)
	}
}

const allProjectsText = `
Monitoring /home/antoine/Documents/SnykSB/java-goof (io.github.snyk:java-goof)...

Explore this snapshot at https://app.snyk.io/org/antoine-playground/project/d7413941-8667-4101-9fba-87861ed5a331/history/8bee3006-807e-489b-8ec5-092e1ae96a85

Notifications about newly disclosed issues related to these dependencies will be emailed to you.


-------------------------------------------------------

Monitoring /home/antoine/Documents/SnykSB/java-goof (io.snyk:log4shell-poc)...

Explore this snapshot at https://app.snyk.io/org/antoine-playground/project/7640820c-1d12-47aa-b042-f0e5de195165/history/6cbdb8ab-af7f-4375-b4f3-d2b6e92a9ace

Notifications about newly disclosed issues related to these dependencies will be emailed to you.


-------------------------------------------------------

Monitoring /home/antoine/Documents/SnykSB/java-goof (io.snyk:log4shell-client)...

Explore this snapshot at https://app.snyk.io/org/antoine-playground/project/809e430f-1437-4ea5-84f7-0d9a3362ba09/history/eb43feab-c0bc-4c82-aa18-0e8ce973183d

Notifications about newly disclosed issues related to these dependencies will be emailed to you.


-------------------------------------------------------

Monitoring /home/antoine/Documents/SnykSB/java-goof (io.snyk:log4shell-server)...

Explore this snapshot at https://app.snyk.io/org/antoine-playground/project/61f628c8-c956-4e1b-90e9-e02a089319e2/history/49e8bf80-83ae-425b-b5d5-f9b24fa5278c

Notifications about newly disclosed issues related to these dependencies will be emailed to you.


-------------------------------------------------------

Monitoring /home/antoine/Documents/SnykSB/java-goof (io.github.snyk:todolist-mvc)...

Explore this snapshot at https://app.snyk.io/org/antoine-playground/project/a8534641-6bfa-40fa-b042-b636d451462c/history/950c8471-89ff-4b00-84d3-7295d2a6115a

Notifications about newly disclosed issues related to these dependencies will be emailed to you.


-------------------------------------------------------

Monitoring /home/antoine/Documents/SnykSB/java-goof (io.github.snyk:todolist-core)...

Explore this snapshot at https://app.snyk.io/org/antoine-playground/project/fda353c0-1574-45db-a675-1aa0549ac6ba/history/bfbc00b5-809e-400d-9c65-341a3587b0c2

Notifications about newly disclosed issues related to these dependencies will be emailed to you.


-------------------------------------------------------

Monitoring /home/antoine/Documents/SnykSB/java-goof (io.github.snyk:todolist-web-common)...

Explore this snapshot at https://app.snyk.io/org/antoine-playground/project/23aa5dfa-9143-439d-8dad-30e165330e25/history/eb321372-77c9-4579-8e05-1fc227bbb7a9

Notifications about newly disclosed issues related to these dependencies will be emailed to you.


-------------------------------------------------------

Monitoring /home/antoine/Documents/SnykSB/java-goof (io.github.snyk:todolist-web-struts)...

Explore this snapshot at https://app.snyk.io/org/antoine-playground/project/dc44f303-ed78-4f54-a740-d83478b6a18f/history/cd2df5a3-e943-46da-9084-22ba8509ddf2

Notifications about newly disclosed issues related to these dependencies will be emailed to you.

`

func Test_GetProjectIdAndMonitorIdFromText_AllProjects(t *testing.T) {
	pairs, err := GetProjectIdAndMonitorIdFromText(allProjectsText)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// we expect 8 project/history pairs in allProjectsText
	if len(pairs) != 8 {
		t.Fatalf("expected 8 project/monitor pairs, got %d", len(pairs))
	}

	firstProjectID := pairs[0][0]
	firstMonitorID := pairs[0][1]
	lastProjectID := pairs[len(pairs)-1][0]
	lastMonitorID := pairs[len(pairs)-1][1]

	expectedFirstProjectID := "d7413941-8667-4101-9fba-87861ed5a331"
	expectedFirstMonitorID := "8bee3006-807e-489b-8ec5-092e1ae96a85"
	expectedLastProjectID := "dc44f303-ed78-4f54-a740-d83478b6a18f"
	expectedLastMonitorID := "cd2df5a3-e943-46da-9084-22ba8509ddf2"

	if firstProjectID != expectedFirstProjectID {
		t.Errorf("first projectID mismatch: got %q, want %q", firstProjectID, expectedFirstProjectID)
	}
	if firstMonitorID != expectedFirstMonitorID {
		t.Errorf("first monitorID mismatch: got %q, want %q", firstMonitorID, expectedFirstMonitorID)
	}
	if lastProjectID != expectedLastProjectID {
		t.Errorf("last projectID mismatch: got %q, want %q", lastProjectID, expectedLastProjectID)
	}
	if lastMonitorID != expectedLastMonitorID {
		t.Errorf("last monitorID mismatch: got %q, want %q", lastMonitorID, expectedLastMonitorID)
	}
}
