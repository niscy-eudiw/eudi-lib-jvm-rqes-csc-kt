# Module EUDI rQES CSC library

`eudi-lib-jvm-rqes-csc-kt` is a Kotlin library, targeting JVM, that supports the [Cloud Signature Consortium API (version 2)](https://cloudsignatureconsortium.org/wp-content/uploads/2023/04/csc-api-v2.0.0.2.pdf) protocol.

In particular, the library focuses on the wallet's role in the protocol to:
- Resolve the remote signing service metadata
- Resolve metadata of the authorization server protecting the signing services
- Retrieve the list of credentials from the remote signing service
- Authorize the use of a specific credential for signing a specific document
- Request the remote signing service to sign a document

## eu.europa.ec.eudi.rqes

## rQES CSC features supported
