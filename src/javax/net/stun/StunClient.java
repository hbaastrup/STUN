/*
 * Copyrigth (C) 2010 Henrik Baastrup.
 *
 * Licensed under the GNU Lesser General Public License version 3;
 * you may not use this file except in compliance with the License.
 * You should have received a copy of the license together with this
 * file but can obtain a copy of the License at:
 *
 *       http://www.gnu.org/licenses/lgpl-3.0.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package javax.net.stun;

import javax.net.stun.dns.DClass;
import javax.net.stun.dns.DMessage;
import javax.net.stun.dns.DNSResolver;
import javax.net.stun.dns.DResource;
import javax.net.stun.dns.DResourceComparator;
import javax.net.stun.dns.DType;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * This class implement a STUN client as descriped in RFC 3489.
 *
 * @author Henrik Baastrup
 */
public class StunClient {
    /**
     * Values to discripe the test passed under the {@link StunClient#binding} method
     */
    public enum DoneBindingTest {
        NO_TEST,
        TEST1_FIRST_RUN,
        TEST2,
        TEST1_SECOND_RUN,
        TEST3
    }
    
    private String serverAddress = "";
    private int serverPort = 3478;

    private InetAddress localAddr = null;
    private int localPort = 0;

    private MessageAttribute mappedAddress = null;
    private MessageAttribute changedAddress = null;

    private DoneBindingTest bindingTestDone = DoneBindingTest.NO_TEST;

    protected boolean debug = false;
    protected static boolean staticDebug = false;

    /**
     * Default Creator
     * @param address
     */
    public StunClient() {
    }

    /**
     * Creator
     * @param address for the STUN server (dafult prot used is 3478).
     */
    public StunClient(String address) {
        this.serverAddress = address;
    }

    /**
     * Creator
     * @param address for the STUN srever.
     * @param port used to connect to the STUN server.
     */
    public StunClient(String address, int port) {
        this.serverAddress = address;
        this.serverPort = port;
    }

    /**
     *
     * @param domainAddress ex
     * @param dnsServer
     * @return an array of StunServerAddress in priotated order
     * @throws IOException
     */
    public static StunServerAddress[] discovery(String domainAddress, String dnsServer) {
        DNSResolver resolver = new DNSResolver(dnsServer);
        String query = "_stun._udp."+domainAddress;

        DResource answers[];
        try {
            DMessage message = resolver.query(query, DType.SRV, DClass.IN);
            if (message==null) return new StunServerAddress[0];
            answers = message.getAnswers();
            if (answers==null || answers.length==0) {
                message = resolver.query(domainAddress, DType.A, DClass.IN);
                answers = message.getAnswers();
                if (answers==null || answers.length==0) return new StunServerAddress[0];
            }
        } catch (IOException ex) {
            if (staticDebug)  Logger.getLogger(StunClient.class.getName()).log(Level.SEVERE, null, ex);
            return new StunServerAddress[0];
        }

        DResourceComparator comparator = new DResourceComparator();
        Arrays.sort(answers, comparator);
        
        StunServerAddress retAddresses[] = new StunServerAddress[answers.length];
        for (int i=0; i<answers.length; i++) {
            StunServerAddress sAddr = new StunServerAddress();
            if (answers[i].getDType()==DType.SRV) {
                sAddr.address = answers[i].getTarget();
                sAddr.port = answers[i].getPort();
            }
            else if (answers[i].getDType()==DType.A) {
                sAddr.address = answers[i].getIpAddress();
                sAddr.port = 3478;
            }
            retAddresses[i] = sAddr;
        }
        return retAddresses;
    }

    /**
     * Ask the STUN server for a sgared secret if pocible.
     * @return {@link SharedSecret} if the process suceed else null.
     * @throws IOException
     */
    public SharedSecret getSharedSecret() {
        SSLSocket sslSocket = null;
        MessageHeader header = null;
        SharedSecret sharedSecret = null;

        if (System.getProperty("javax.net.ssl.trustStore")==null)
            System.setProperty("javax.net.ssl.trustStore", "StunTest.jks");
        if (System.getProperty("javax.net.ssl.keyStoreType")==null)
            System.setProperty("javax.net.ssl.keyStoreType", "JKS");
        //System.setProperty("javax.net.debug", "help");
        //System.setProperty("javax.net.debug", "ssl");
        //System.setProperty("javax.net.debug", "ssl:record");
        //System.setProperty("javax.net.debug", "ssl:handshake");

        try {
            //sock = new Socket(serverAddress, serverPort);
            //sock.setSoTimeout(9500);

            SSLSocketFactory sslFactory = (SSLSocketFactory)SSLSocketFactory.getDefault();
            sslSocket = (SSLSocket)sslFactory.createSocket(serverAddress, serverPort);
            //sslSocket = (SSLSocket)sslFactory.createSocket(sock, serverAddress, serverPort, true);
            sslSocket.startHandshake();

            //Read the header
            header = new MessageHeader(MessageHeader.HeaderType.SHARED_SECRET_REQUEST);
            header.genrateTransactionId();
            header = Utils.socketSendRecive(sslSocket, header);
        } catch (IOException ex) {
            if (debug)  Logger.getLogger(StunClient.class.getName()).log(Level.SEVERE, null, ex);
            sharedSecret = new SharedSecret(700, ex.getMessage());
            return sharedSecret;
        } finally {
            if (sslSocket!=null) try{sslSocket.close();} catch (IOException ignore){}
        }

        MessageAttribute errorCode = header.getMessageAttribute(MessageAttribute.MessageAttributeType.ERROR_CODE);
        MessageAttribute usernameAttr = header.getMessageAttribute(MessageAttribute.MessageAttributeType.USERNAME);
        MessageAttribute passwordAttr = header.getMessageAttribute(MessageAttribute.MessageAttributeType.PASSWORD);
        if (errorCode!=null) {
            sharedSecret = new SharedSecret(errorCode);
        }
        if (usernameAttr==null || passwordAttr==null) {
            sharedSecret = new SharedSecret(700, "The server is sending an incomplete response (Username and Password message attributes are missing). The client should not retry.");
        }
        else {
            sharedSecret = new SharedSecret(usernameAttr.getUsername(), passwordAttr.getPassword());
        }

        return sharedSecret;
    }

    /**
     * Set the STUN server address property.
     *
     * @param arg0 server address
     */
    public void setServerAddress(String arg0) {serverAddress = arg0;}

    /**
     * Set the STUN server port property.
     *
     * @param arg0 port (default value = 3478).
     */
    public void setServerPort(int arg0) {serverPort = arg0;}

    /**
     * Do the binding process as descriped in RFC 3489:
     *  <pre> {@code
                     +--------+
                     |  Test  |
                     |   I    |
                     +--------+
                         |
                         |
                         V
                         /\              /\
                      N /  \ Y          /  \ Y             +--------+
       UDP     <-------/Resp\--------->/ IP \------------->|  Test  |
       Blocked         \ ?  /          \Same/              |   II   |
                        \  /            \? /               +--------+
                         \/              \/                     |
                                          | N                   |
                                          |                     V
                                          V                     /\
                                      +--------+   Sym.      N /  \
                                      |  Test  |   UDP    <---/Resp\
                                      |   II   |   Firewall   \ ?  /
                                      +--------+               \  /
                                          |                     \/
                                          V                      |Y
               /\                         /\                     |
Symmetric   N /  \       +--------+ N    /  \                    V
NAT     <--- / IP \<-----|  Test  |<--- /Resp\                Open
             \Same/      |   I    |     \ ?  /                Internet
              \? /       +--------+      \  /
               \/                         \/
                |                          |Y
                |                          |
                |                          V
                |                          Full
                |                          Cone
                V              /\
            +--------+        /  \ Y
            |  Test  |------>/Resp\---->Restricted
            |  III   |       \ ?  /
            +--------+        \  /
                               \/
                                |N
                                |       Port
                                +------>Restricted
     *  }</pre>
     *
     * @param sharedSecret found in the @{link getSharedSecret} method or null if no secret was found or used.
     * @return @{link DiscoveryInfo} contining the informations from the STUN server found by the process
     */
    public DiscoveryInfo binding(SharedSecret sharedSecret) {
        DiscoveryInfo discoveryInfo = new DiscoveryInfo();
        if (test1(discoveryInfo, sharedSecret, true)) {
            if (test2(discoveryInfo, sharedSecret)) {
                if (test1(discoveryInfo, sharedSecret, false)) {
                    test3(discoveryInfo, sharedSecret);
                }
            }
        }

        return discoveryInfo;
    }

    /**
     * This method will only do the first test in the binding process, and is
     * usefull if one only is intrested in finding the remote address of the
     * client, and not the senario.
     *
     * @param sharedSecret @{link SharedSecret} found in @{link getSharedSecret} method or null.
     * @return DiscoveryInfo that contain the remote address value.
     */
    public DiscoveryInfo bindForRemoteAddressOnly(SharedSecret sharedSecret) {
        DiscoveryInfo discoveryInfo = new DiscoveryInfo();
        test1(discoveryInfo, sharedSecret, true);
        return discoveryInfo;
    }

    /*
     * In test I, the client sends a STUN Binding Request to a server, without any flags set in the
     * CHANGE-REQUEST attribute, and without the RESPONSE-ADDRESS attribute.
     * This causes the server to send the response back to the address and port that the request came from.<br>
     */
    private boolean test1(DiscoveryInfo discoveryInfo, SharedSecret sharedSecret, boolean useChangedAddress) {
        MessageHeader header = new MessageHeader(MessageHeader.HeaderType.BINDING_REQUEST);
        header.genrateTransactionId();
        //byte hmac[] = setMessageAttributes(header, (byte)0, sharedSecret); // Change request = Same address and same port

        String addr = serverAddress;
        int port = serverPort;
        if (!useChangedAddress) {
        	if (changedAddress==null) {
                discoveryInfo.setError(700, "The server has send an incomplete response in an earlier call to Test1 (Changed Address message attributes was missing). The client should not retry.");
                if (debug) System.out.println("An earlier call to Test1 did not contain Changed Address message attribute.");
                return false;
        	}
            addr = changedAddress.getAddress().getHostAddress();
            port = changedAddress.getPort();
        }

        if (useChangedAddress) bindingTestDone = DoneBindingTest.TEST1_FIRST_RUN;
        else bindingTestDone = DoneBindingTest.TEST1_SECOND_RUN;

        try {
            byte buffer[] = sendReceive(header, addr, port);

            header = MessageHeader.create(buffer);
        } catch (SocketTimeoutException ex) {
            if (useChangedAddress) {
                if (debug) System.out.println("Node is not capable of UDP communication.");
                discoveryInfo.setScenario(DiscoveryInfo.ConnectionScenario.UDP_BLOCKED);
            }
            else {
                if (debug)  Logger.getLogger(StunClient.class.getName()).log(Level.SEVERE, null, ex);
            }
            return false;
        } catch (IOException ex) {
            if (debug)  Logger.getLogger(StunClient.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        }
        
        MessageAttribute mappedAddress2 = null;
        if (useChangedAddress) {
            mappedAddress = header.getMessageAttribute(MessageAttribute.MessageAttributeType.MAPPED_ADDRESS);
            changedAddress =  header.getMessageAttribute(MessageAttribute.MessageAttributeType.CHANGED_ADDRESS);
        } else {
            mappedAddress2 = header.getMessageAttribute(MessageAttribute.MessageAttributeType.MAPPED_ADDRESS);
            if (mappedAddress2==null) {
                discoveryInfo.setError(700, "The server is sending an incomplete response (Mapped Address and Changed Address message attributes are missing). The client should not retry.");
                if (debug) System.out.println("Response does not contain a Mapped Address or Changed Address message attribute.");
                return false;
            }
        }
	MessageAttribute errorCode = header.getMessageAttribute(MessageAttribute.MessageAttributeType.ERROR_CODE);
        
        if (errorCode!=null) {
            if (debug) System.out.println("Got an error code from the STUN server");
            discoveryInfo.setErrorCode(errorCode);
            return false;
        }
        //TODO: using  || ??????
        //if (mappedAddress==null || changedAddress==null) {
        if (mappedAddress==null) {
            discoveryInfo.setError(700, "The server is sending an incomplete response (Mapped Address and Changed Address message attributes are missing). The client should not retry.");
            if (debug) System.out.println("Response does not contain a Mapped Address or Changed Address message attribute.");
            return false;
        }

        if (!controlMessageIntegrity(header, sharedSecret)) {
             discoveryInfo.setError(700, "Wrong HMAC received from server, this migh be an attack response");
            return false;
        }

        if (useChangedAddress) {
            discoveryInfo.setPublicIpAddress(mappedAddress.getAddress());
            discoveryInfo.setLocalIpAddress(localAddr);
            if (mappedAddress.getPort()==localPort && mappedAddress.getAddressAsString().equals(localAddr.getHostAddress())) {
                if (debug) System.out.println("Node is not natted.");
                discoveryInfo.setNodeNated(false);
            }
            else {
                if (debug) System.out.println("Node is natted.");
                discoveryInfo.setNodeNated(true);
            }
        }
        else {
            //if (mappedAddress.getPort()!=mappedAddress2.getPort() || !mappedAddress.getAddress().equals(mappedAddress2.getAddress())) {
            if (!mappedAddress.getAddress().equals(mappedAddress2.getAddress())) {
                    if (debug) System.out.println("Node is behind a symmetric NAT.");
                    discoveryInfo.setScenario(DiscoveryInfo.ConnectionScenario.SYMMETRIC_NAT);
                    return false;
            }
        }

        return true;
    }

    /*
     * In test II, the client sends a Binding Request with both the "change IP" and "change port" flags
     * from the CHANGE-REQUEST attribute set.<br>
     */
    private boolean test2(DiscoveryInfo discoveryInfo, SharedSecret sharedSecret) {
        MessageHeader header = new MessageHeader(MessageHeader.HeaderType.BINDING_REQUEST);
        header.genrateTransactionId();
        //byte hmac[] = setMessageAttributes(header, (byte)6, sharedSecret); // Change request = Change addaress and port

        bindingTestDone = DoneBindingTest.TEST2;

        try {
            byte buffer[] = sendReceive(header, serverAddress, serverPort);

            header = MessageHeader.create(buffer);
        } catch (SocketTimeoutException ex) {
            if (discoveryInfo.isNodeNated()) {
                return true;
            } else {
                if (debug) System.out.println("Node is behind a symmetric UDP firewall.");
                discoveryInfo.setScenario(DiscoveryInfo.ConnectionScenario.SYMMETRIC_FIREWALL);
                return false;
            }

        } catch (IOException ex) {
            if (debug)  Logger.getLogger(StunClient.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        }

	MessageAttribute errorCode = header.getMessageAttribute(MessageAttribute.MessageAttributeType.ERROR_CODE);

        if (errorCode!=null) {
            if (debug) System.out.println("Got an error code from the STUN server");
            discoveryInfo.setErrorCode(errorCode);
            return false;
        }

        if (!controlMessageIntegrity(header, sharedSecret)) {
             discoveryInfo.setError(700, "Wrong HMAC received from server, this migh be an attack response");
            return false;
        }

        if (discoveryInfo.isNodeNated()) {
            discoveryInfo.setScenario(DiscoveryInfo.ConnectionScenario.FULL_CONE_NAT);
            if (debug) System.out.println("Node is behind a full-cone NAT.");
        } else {
            discoveryInfo.setScenario(DiscoveryInfo.ConnectionScenario.OPEN_INTERNET);
            if (debug) System.out.println("Node has open access to the Internet (or, at least the node is behind a full-cone NAT without translation).");
        }

        return false;
    }

    /*
     * In test III, the client sends a Binding Request with only the "change port" flag set.
     */
    private void test3(DiscoveryInfo discoveryInfo, SharedSecret sharedSecret) {
        MessageHeader header = new MessageHeader(MessageHeader.HeaderType.BINDING_REQUEST);
        header.genrateTransactionId();
        //byte hmac[] = setMessageAttributes(header, (byte)2, sharedSecret); // Change request = Change port

        bindingTestDone = DoneBindingTest.TEST3;
        
        try {
            byte buffer[] = sendReceive(header, serverAddress, serverPort);

            header = MessageHeader.create(buffer);
        } catch (SocketTimeoutException ex) {
            if (discoveryInfo.isNodeNated()) {
                if (debug) System.out.println("Node is behind a port restricted NAT.");
                discoveryInfo.setScenario(DiscoveryInfo.ConnectionScenario.RESTRICTED_PORT_NAT);
                return;
            } else {
                return;
            }

        } catch (IOException ex) {
            if (debug)  Logger.getLogger(StunClient.class.getName()).log(Level.SEVERE, null, ex);
            return;
        }

	MessageAttribute errorCode = header.getMessageAttribute(MessageAttribute.MessageAttributeType.ERROR_CODE);

        if (errorCode!=null) {
            if (debug) System.out.println("Got an error code from the STUN server");
            discoveryInfo.setErrorCode(errorCode);
            return;
        }

        if (!controlMessageIntegrity(header, sharedSecret)) {
             discoveryInfo.setError(700, "Wrong HMAC received from server, this migh be an attack response");
            return;
        }

        if (discoveryInfo.isNodeNated()) {
            discoveryInfo.setScenario(DiscoveryInfo.ConnectionScenario.RESTRICTED_CORNE_NAT);
            if (debug) System.out.println("Node is behind a restricted cone NAT.");
        }
    }

    private byte[] setMessageAttributes(MessageHeader header, byte changeRequest, SharedSecret sharedSecret) {
        MessageAttribute changeRequestAttr = MessageAttribute.create(MessageAttribute.MessageAttributeType.CHANGE_REQUEST, (int)changeRequest);
        header.addMessageAttribute(changeRequestAttr);
        byte hmac[] = null;
        if (sharedSecret!=null) {
            if (sharedSecret.getUsername()!=null) {
                MessageAttribute usernameAttr = MessageAttribute.create(MessageAttribute.MessageAttributeType.USERNAME, sharedSecret.getUsername() ,0);
                header.addMessageAttribute(usernameAttr);
            }
            if (sharedSecret.getPassword()!=null) try {
                // The message Integrity must be the last attribute in the header and use
                // The STUN message including the header, up to and including the attribute
                // preceding to this attribute as text for the HMAC.
                MessageAttribute messageIntegrityAttr = MessageAttribute.create(MessageAttribute.MessageAttributeType.MESSAGE_INTEGRITY, sharedSecret.getPassword(), header.toBytes());
                header.addMessageAttribute(messageIntegrityAttr);
                hmac = messageIntegrityAttr.getHMAC();
            } catch (IOException ex) {
                if (debug)  Logger.getLogger(StunClient.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        return hmac;
    }
    
    private boolean controlMessageIntegrity(MessageHeader header, SharedSecret sharedSecret) {
        if (sharedSecret==null) return true;
        if (header.integrityCheck(sharedSecret.getPassword())!=0) return false;

        return true;
    }

    /**
     *
     * @return the enum @{link DoneBindingTest} value for the last test passed under the {@link StunClient#binding} method.
     */
    public DoneBindingTest getBindingTestDone() {return bindingTestDone;}

    /**
     * 
     * @return a string description for the last test passed under the {@link StunClient#binding} method.
     */
    public String getBindingTestDoneAsString() {
        switch (bindingTestDone) {
            case TEST1_FIRST_RUN: return "test 1 first run";
            case TEST1_SECOND_RUN: return "test 1 second run";
            case TEST2: return "test2";
            case TEST3: return "test";
        }
        return "no test!";
    }


    private byte[] sendReceive(MessageHeader header, String address, int port) throws IOException {
        InetAddress addr =  InetAddress.getByName(address);
        DatagramSocket sock = new DatagramSocket();
        sock.setReuseAddress(true);
        int timeout = 100;
        int timeSinceFirstTransmission = 0;
        DatagramPacket retDatagramPacket = null;

        try {
            byte buffer[] = header.toBytes();
            DatagramPacket out = new DatagramPacket(buffer, buffer.length, addr, port);

            while (true) {
                sock.send(out);

                byte[] buf = new byte[0xffff+20];
                retDatagramPacket = new DatagramPacket(buf, buf.length);
                sock.setSoTimeout(timeout);
                try {
                    sock.receive(retDatagramPacket);
                } catch (SocketTimeoutException ex) {
                    if (timeout<1600) timeout = timeout*2;
                    timeSinceFirstTransmission += timeout;
                    if (timeSinceFirstTransmission > 9500) throw ex;
                    continue;
                }
                break;
            }
            //localAddr = sock.getLocalAddress();
            //localAddr = InetAddress.getLocalHost();
            localAddr = Utils.getLocalAddr();
//    System.out.println(localAddr);
//    System.out.println(localAddr.getLocalHost());
//    System.out.println(localAddr.getHostAddress());
            localPort = sock.getLocalPort();
        } finally {
            sock.close();
        }
        return retDatagramPacket.getData();
    }




}
