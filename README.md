# STUN
Simple Traversal of User Datagram Protocol (UDP) Through Network Address Translators (NATs) 

## Introduction
This project was originally a part of the Java incubator (javax), but disappeared when Oracle moved there repository from OpenJava.  
  
[STUN](https://en.wikipedia.org/wiki/STUN) is a technique (protocol) there allow an application behind a Network Address Translators ([NAT](https://en.wikipedia.org/wiki/Network_address_translation)) Firewall to discover its public Internet address and the type of the NAT scenario used between the application and the Internet.  
STUN is typically used in communication applications there need to inter connect. This is done by communicate the public Internet address to the other part, but before an application can communicate it's address, it need to discover it and can use STUN to do that.  
STUN use a client/server scenario and the goal of this project is to implement a client API there are easy to use, plus the necessary classes to set-up a server.  
The client can do SSL connection to implement the Shared Secret part of the standard (chapter 9.2). The client can also do DNS resolving to implement the Discovery part of the standard (chapter 9.1).  
STUN is an Internet standard described in [RFC 3489](https://www.ietf.org/rfc/rfc3489.txt)

## How to start
### How to build the Project
Download the latest source.  
The STUN project contains a Ant script file (build-ant.xml) and it should be enough to lunch "ant -f build-ant.xml" in the project's home directory. This will produce the directory "dist" there contains the library file "stun.jar". Include this file in your project there need to implement STUN. "stun.jar" does not depend on any other libraries.  
"stun.jar" will run as a STUN client if executed like ```java -jar stun.jar```. Use the ```-h``` option to see possible other options.

### Client examples
The below example shows a full client discovery scenario, using DNS Discovery and Shared Secret:  
```
String domain = "xten.net";
String dnsServerAddr = "64.69.76.5";

//Set key-store to use with Shared Secret service.
//Note: Shared Secret service use SSL so the client needs a key-store
//with a Certification Autherity Certificate for the services.
File keyStoreFile = new File("StunTest.jks"); //Key-store file
System.setProperty("javax.net.ssl.trustStore", keyStoreFile.getAbsolutePath());
System.setProperty("javax.net.ssl.trustStoreType", "JKS");

//First ask the domain for any STUN servers know to the DNS server for the domain
StunServerAddress stunServers[] = StunClient.discovery(domain, dnsServerAddr);
if (stunServers.length==0) return; //The DNS server does not have any _stun._udp SRV records for the given domain. 

//Try to bind to each server given by the DNS server
DiscoveryInfo info;
for (int i=0; i<stunServers.length; i++) {
	StunClient client = new StunClient(stunServers[i].address, stunServers[i].port);
	//Ask for a Shared Secret
	SharedSecret secret = client.getSharedSecret();
	//Do binding (discovering)
	info = client.binding(secret);
	if (info.getErrorCode()!=0) {
		//We got an error!Try the next server from the DNS.
		System.out.println("ERROR: "+info.getErrorMessage());
	}
	else break; //We have a full binding!
}

if (info.getErrorCode()==0) {
	//We have succeed the binding lets take a look at the result.
	String publicAddress = info.getPublicIpAddress();
	ConnectionScenario scenario = info.getScenarioState();
	if (info.isNodeNated()) {
		System.out.println("I'm NATted");
	}
	System.out.println(info);
}
```
Many time an application only needs it's public Internet address and the STUN server is know and does not use Shared Secret, such a client might look like this:
```
StunClient client = new StunClient("stun.l.google.com", 19302);
DiscoveryInfo info = client.binding(null);
if (info.getErrorCode()!=0) {
	System.out.println("ERROR: "+info.getErrorMessage());
}
else {
	String publicAddress = info.getPublicIpAddress();
}
```
**NOTE:** If the client need to work with a STUN server there support Shared Secret, the client needs a key-store containing the CA certificate for the server.

### Server example
**NOTE:** The server API is still under development and the interface might change over time.  
Below is a server there user Shared Secret but can only give the public Internet address to a client. it is not able to answer the client with a full NAT scenario as there is only used one IP address. To discover a full NAT scenario there need be two STUN servers with different IP addresses, each server listen on two different ports.  
As the project in this moment does not contain a method to change user and password with the Shared Secret service it is not jet possible to implement that.  
```
SharedSecretService ssService = new SharedSecretService();
File keyStoreFile = new File("StunTest.jks"); //Key-store file
ssService.setKeyStore(keyStoreFile, "henriksp".toCharArray(), "henrikkp".toCharArray());

InetAddress loclahost = Utils.getLocalAddr();
BindingService bService = new BindingService(loclahost, 0, null, 0, ssService);

try {
	ssService.startThread();
	bService.startThread();
	/*
	 Wait for request to stop server
	 .
	 .
	 .
	 */
}
finally {
	ssService.stop();
	bService.stop();
}
```
**NOTE:** If you plan to make a server there support Shared Secret, you need a key-store containg a certificate for your server. This certificate can either be signed by a CA or a self signed certificate. In any case all the clients there connect to your server needs the certificate of the signer. The reason for this is that the Shared Secret is obtained over SSL.  
You can use the Java [keytool](https://docs.oracle.com/javase/8/docs/technotes/tools/unix/keytool.html) program to create a key-store. If you only need a self signed certificate you can distribute this key-store with all you clients.  
The project comes with a self signed key-store file StunTest.jks with the key-store password "henrikkp" and the key password "henrikkp".  

