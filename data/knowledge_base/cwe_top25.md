# CWE Top 25 Most Dangerous Software Weaknesses

## CWE-79: Cross-site Scripting (XSS)
The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.

## CWE-89: SQL Injection
The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.

## CWE-20: Improper Input Validation
The product does not validate or incorrectly validates input that can affect the control flow or data flow of a program.

## CWE-352: Cross-Site Request Forgery (CSRF)
The web application does not, or can not, sufficiently verify that a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.

## CWE-78: OS Command Injection
The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command.

## CWE-434: Unrestricted Upload of File with Dangerous Type
The software allows the upload of a file with a dangerous type that can be automatically processed within the product's environment.

## CWE-862: Missing Authorization
The software does not perform an authorization check when an actor attempts to access a resource or perform an action.

## CWE-476: NULL Pointer Dereference
A NULL pointer dereference occurs when the application dereferences a pointer that it expects to be valid, but is NULL, typically causing a crash or exit.

## CWE-287: Improper Authentication
When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.

## CWE-190: Integer Overflow or Wraparound
The software performs a calculation that can produce an integer overflow or wraparound, when the logic assumes that the resulting value will always be larger than the original value.

