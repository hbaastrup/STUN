# STUN
Simple Traversal of User Datagram Protocol (UDP) Through Network Address Translators (NATs) 
## Introduction
STUN https://en.wikipedia.org/wiki/STUN is a technique (protocol) there allow an application behind a Network Address Translators (NAT) Firewall to discover its public Internet address and the type of the NAT scenario used between the application and the Internet.
STUN is typically used in communication applications there need to inter connect. This is done by communicate the public Internet address to the other part, but before an application can communicate it's address, it need to discover it and can use STUN to do that.
STUN use a client/server scenario and the goal of this project is to implement a client API there are easy to use, plus the necessary classes to set-up a server.
The client can do SSL connection to implement the Shared Secret part of the standard (chapter 9.2). The client can also do DNS resolving to implement the Discovery part of the standard (chapter 9.1).
STUN is an Internet standard described in RFC 3489
