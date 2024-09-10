# cueutils

`cueutils` provides a library for data transformation using the [Cue language](https://cuelang.org/). Cue is a powerful and expressive data description language well-suited for defining complex transformations on structured data formats.

## Why Use Cue for Data Transformation?

There are several advantages to using Cue for data transformations:

* **Declarative:** Cue scripts are declarative, meaning they focus on **what** needs to be transformed rather than **how**. This leads to more concise and easier-to-read code.
* **Expressive:** Cue supports a rich set of data types, expressions, and control flow constructs, allowing for complex transformations to be defined in a single location.
* **Type Safety:** Cue is statically typed, which helps to catch errors early in the development process and ensures data integrity during transformations.
* **Reusability:** Cue transformations can be packaged and reused across different parts of your application.

## Package Overview

`cueutils` provides a single key component:

- `Transformer`: This struct encapsulates a loaded Cue script that defines a data transformation. 

The provided functions allow you to:

*  `NewTransformer`: Creates a new `Transformer` instance from a provided Cue script name.
*  `Apply`: Applies the transformation defined in the script to an AST expression.
*  `ApplyValue`: Applies the transformation defined in the script to a Cue value.

This library provides a convenient way to integrate Cue-based data transformations within the Go Application Framework.