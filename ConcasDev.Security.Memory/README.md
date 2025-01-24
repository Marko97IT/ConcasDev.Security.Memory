# ConcasDev.Security.Memory

`ConcasDev.Security.Memory` is a utility library for securely handling sensitive data in memory. It provides methods to encrypt sensitive data using the `Microsoft.AspNetCore.DataProtection.Secret` API and ensures that sensitive data is cleaned from memory after use.

## Features

- Convert sensitive data (e.g., passwords, cryptographic keys) into a protected `Secret` object.
- Retrieve unprotected sensitive data from a `Secret` object safely.
- Automatically clears temporary buffers to minimize the risk of data exposure.
- Extension methods for clearing byte and character arrays.

## Installation

To install the library via NuGet:

```bash
dotnet add package ConcasDev.Security.Memory