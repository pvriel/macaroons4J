# macaroons4J &nbsp; ![Java](https://img.shields.io/badge/java-%23ED8B00.svg?style=for-the-badge&logo=java&logoColor=white)

[![Project Status: Active](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)
[![Coverage](https://badgen.net/badge/coverage/86%25/green)](https://badgen.net/badge/coverage/86%25/green)

 A Java library for <a href="https://research.google/pubs/pub41892/">Macaroons</a>.
<br>The aim of this library is to provide an easy-to-use, yet versatile (e.g., support for structural caveats) library for developers.

***

## How to add this dependency to your project

We now use <a href="https://github.com/pvriel/macaroons4J/packages/">GitHub packages</a> instead of JitPack.

***

## Basic usage example
### Working with Macaroons in general
```java
String hintTargetLocation = "https://google.com";
byte[] macaroonIdentifier = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
String macaroonSecret = "A secret, only known to the target location";

Macaroon macaroon = new SimpleMacaroon(macaroonSecret, macaroonIdentifier, hintTargetLocation);
VerificationContext context = new VerificationContext();
macaroon.verify(macaroonSecret, context); // No exceptions thrown.
```
### Working with first-party caveats
```java
byte[] firstPartyCaveatIdentifier = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
// Create a custom FirstPartyCaveat subclass and define its verification process.
FirstPartyCaveat timeConstraint = new FirstPartyCaveat(firstPartyCaveatIdentifier) {
    @Override
    protected void verify(@NotNull Macaroon macaroon, @NotNull VerificationContext context) throws IllegalStateException {
        /*
            macaroon: the Macaroon instance that is being verified.
            context: the context in which the caveat should hold.
         */
        context.addRangeConstraint("time", Pair.of(5, 10));
    }
};
macaroon.addCaveat(timeConstraint);
macaroon.verify(macaroonSecret, context); // No exceptions thrown.

context = new VerificationContext();
context.addRangeConstraint("time", Pair.of(11, 15));
/*
    Exception thrown: context only valid in 'time' range 11 - 15, while the constraint is only valid between 5 - 10.
    There is no overlapping between the two ranges.
 */
macaroon.verify(macaroonSecret, context);
```
### Working with third-party caveats
```java
String thirdPartyCaveatRootKey = "Another secret, shared with the third-party";
byte[] thirdPartyCaveatIdentifier = "user is Alice";
String hintDischargeLocation = "https://oauthprovider.com";
ThirdPartyCaveat thirdPartyCaveat = new ThirdPartyCaveat(thirdPartyCaveatRootKey, thirdPartyCaveatIdentifier, hintDischargeLocation);
macaroon.addCaveat(thirdPartyCaveat);

macaroon.verify(macaroonSecret, new VerificationContext()); // Exception thrown: no discharge Macaroon bound.
        
// You can add additional caveats to the discharge Macaroons, but we are not doing that here.
Macaroon dischargeMacaroon = new SimpleMacaroon(thirdPartyCaveatRootKey, thirdPartyCaveatIdentifier, hintDischargeLocation);
macaroon.bindMacaroonForRequest(dischargeMacaroon);
macaroon.verify(macaroonSecret, new VerificationContext()); // No exceptions thrown.
```

***

## Contact

Found a bug, problem, ... or do you have a question about this library?
<br>Do not hesitate to contact me as soon as possible!
