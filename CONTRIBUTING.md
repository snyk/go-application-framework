# Contributing
This repo is intended for internal (Snyk) contributions only at this time.

# Creating a new extension
Creating a new extension using the `go-application-framework` can be done in two steps

## Create the extension workflow
 Fristly, we define our new extension workflow. The extension workflow should contain:
  -  The workflow identifier; this is used by the framework's engine in order to identify the extension
  -  The workflow initialiser; the initialiser should be responsible initialising the extension parameters and registering the workflow with the engine
  -  The workflow entrypoint; this is the method the engine will call when invoking the extension, it should contain the business logic for your extension

## Initialise the extension when using the `go-application-framework`
The last step is to tell the `go-application-framework` to use your new extension, this can be done after creating a new app engine in your application.

## Building an extension
With the above steps outlined, we can work through the process of creating and using an extension for CLI. In this example, we'll implement a new CLI command which will return the currently authenticated user's username. We'll use the Snyk API's `/user/me` [endpoint](https://snyk.docs.apiary.io/#reference/users/my-user-details/get-my-details) to achieve this.

### Create a new extension workflow




<!-- 1. Create a new workflow
   1. Create a workflow identifier
   2. Create a workflow initialiser
      1. Register the workflow with the engine
   3. Create a workflow entrypoint
      1. Implement workflow business logic
2. Initialise the workflow when using the `go-application-framework` -->