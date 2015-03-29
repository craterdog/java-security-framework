![Java Security Framework](https://github.com/craterdog/java-security-framework/blob/master/docs/images/Security.jpg)

### A Simple to Use Java Security Framework
The Java security APIs define a very powerful framework for implementing common security related tasks
like key generation, signing and verifying documents, and encrypting and decrypting data. As with all
low level frameworks, it provides a great deal of flexibility in choosing the algorithms and key sizes
to be used for these tasks. However, this flexibility can cause a significant amount of confusion for
anyone who is not a security expert.

The _Crater Dog Technologies_™ Java Security Framework makes sensible choices for these algorithms based
on the latest research around potential vulnerabilities. It provides a high level framework that is easy
to use and very secure.

### Highlighted Features
The following highlights the main capabilities that this multi-module maven project provides:

 * symmetric (shared) key generation and formatting
 * asymmetric (public/private) key generation and formatting
 * signing (notarization) and validation of documents
 * encryption and decryption of keys and data
 * private certificate authority (CA) creation
 * client certificate generation and signing

### Quick Links
For more detail on this project click on the following links:

 * [javadocs](http://craterdog.github.io/java-security-framework/latest/index.html)
 * [wiki](https://github.com/craterdog/java-security-framework/wiki)
 * [release notes](https://github.com/craterdog/java-security-framework/wiki/releases)
 * [website](http://craterdog.com)

### Getting Started
To get started using these classes, include the following dependency in your maven pom.xml file:

```xml
    <dependency>
        <groupId>com.craterdog.java-security-framework</groupId>
        <artifactId>java-secure-messaging-api</artifactId>  <!-- or whichever submodule you need -->
        <version>x.y</version>
    </dependency>
```

The source code, javadocs and jar file artifacts for this project are available from the
*Maven Central Repository*. If your project doesn't currently use maven and you would like to,
click [here](https://github.com/craterdog/maven-parent-poms) to get started down that path quickly.

### Recognition
_Crater Dog Technologies™_ would like to recognize and thank the following
companies for their contributions to the development and testing of various
components within this project:

 * _Blackhawk Network_ (http://blackhawknetwork.com)

