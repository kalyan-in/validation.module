# validation.module
essential 50+ validators 

This Python validation library provides a comprehensive set of over 50 field-specific validators for user inputs, payments, addresses, documents, security tokens, and more. 
In addition, it includes a universal JSON Schema validation engine that validates data against a provided JSON schema—supporting type validation, custom rules (such as length, pattern, min/max, and enum checks), and even nested objects and arrays.

Table of Contents
Features
Requirements


Features
50+ Essential Validators:
Validate common fields such as email, password strength, username, phone number, credit card, CVV, expiry date, transaction IDs, GSTIN, PAN, IFSC codes, UPI IDs, zip codes, city names, latitude, longitude, IP addresses, document numbers, and security tokens.

Universal JSON Schema Validator:
Validate entire objects using a JSON schema, including type checks (string, number, boolean, object, array) and custom rules (minLength, pattern, enum, minimum, maximum).

Nested Object & Array Support:
The engine handles nested objects and arrays, validating each sub-item as defined in schema.

Modular & Extensible:
Each validator is a separate function, and a VALIDATOR_MAP is used for dynamic lookup. Easily add or extend validations as needed.

Clear Output Format:
Returns an object with an "errors" array (empty if no errors) and a "status" flag indicating whether the data passed validation.

Requirements
Python 3.6+
No additional dependencies are required since this library uses built-in modules such as re, datetime, and typing.
