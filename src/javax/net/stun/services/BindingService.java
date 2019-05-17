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

package javax.net.stun.services;

import java.io.IOException;
import java.lang.Thread.UncaughtExceptionHandler;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.stun.MessageAttribute;
import javax.net.stun.MessageHeader;
import javax.net.stun.MessageHeader.HeaderType;
import javax.net.stun.Utils;

//TODO: The Binding Service is not able to answer a client with a full NAT scenario as
//there is only used one IP address. To discover a full NAT scenario there need be two
//STUN servers with different IP addresses, each server listen on two different ports.
/**
 *
 * @author Henrik Baastrup
 */
public class BindingService implements Runnable,UncaughtExceptionHandler {
    private DatagramSocket receiveSocket;
    private boolean running = false;
    private Thread thread = null;

    private SharedSecretService sharedSecretService = null;
    private InetAddress sharedSecretServiceAddress = null;
    private int sharedSecretServicePort = 3478;

    private InetAddress localAddress = null;
    private int localPort = 3478;
    private InetAddress publicAddress = null;

    private InetAddress alternateAddress = null;
    private int alternatePort = 0;

    private boolean debug = false;

    public BindingService(final InetAddress localIpAddress, final int localPort, final InetAddress alternateIpAddress, final int alternatePort) {
        localAddress = localIpAddress;
        publicAddress = localAddress;
        if (localPort!=0) this.localPort = localPort;
        alternateAddress = alternateIpAddress;
        this.alternatePort = alternatePort;
    }

    public BindingService(final InetAddress localIpAddress, final int localPort, final InetAddress alternateIpAddress, final int alternatePort, final SharedSecretService sharedSecretService) {
        this(localIpAddress, localPort, alternateIpAddress, alternatePort);
        this.sharedSecretService = sharedSecretService;
    }

    public BindingService(final InetAddress localIpAddress, final int localPort, final InetAddress alternateIpAddress, final int alternatePort, final InetAddress sharedSecretServiceAddress, final int sharedSecretServicePort) {
        this(localIpAddress, localPort, alternateIpAddress, alternatePort);
        this.sharedSecretServiceAddress = sharedSecretServiceAddress;
        this.sharedSecretServicePort = sharedSecretServicePort;
    }

    public boolean isRunning() {return running;}

    public void start() {
        if (running) return;
        thread = new Thread(this, "Binding Service Thread");
        thread.setUncaughtExceptionHandler(this);
        try {
            receiveSocket = new DatagramSocket(localPort, localAddress);
            receiveSocket.setSoTimeout(1000);
        } catch (SocketException ex) {
             Logger.getLogger(BindingService.class.getName()).log(Level.SEVERE, null, ex);
             return;
        }
        thread.start();
    }

    public void stop() {
        running = false;
        thread.interrupt();
        synchronized (receiveSocket) {
            receiveSocket.notifyAll();
        }
    }

    public void run() {
        if (debug) {
        	StringBuilder logStr = new StringBuilder("\nBinding-Service starts with following parameters:");
        	logStr.append("\n- Servic address: "+localAddress+":"+localPort);
        	logStr.append("\n- Public address: "+publicAddress.getHostAddress());
        	logStr.append("\n- Alternative servic address: "+alternateAddress+":"+alternatePort);
            if (sharedSecretService!=null) {
            	logStr.append("\n- Using Shared Secret by argument");
            }
            if (sharedSecretServiceAddress!=null) {
            	logStr.append("\n- Using Shared Secret with address: "+sharedSecretServiceAddress);
            }
            Logger.getLogger(BindingService.class.getName()).log(Level.INFO, logStr.toString());
        }
        byte[] buf = new byte[0xffff+20];
        DatagramPacket recDatagramPacket = new DatagramPacket(buf, buf.length);

        running = true;
        while (running) {
            try {
                try {
                    receiveSocket.receive(recDatagramPacket);
                } catch (SocketTimeoutException ignore) {
                    continue;
                } catch (IOException ex) {
                    Logger.getLogger(BindingService.class.getName()).log(Level.SEVERE, null, ex);
                    break;
                }
                if (!running) break;

                response(receiveSocket, recDatagramPacket);
            } catch (RuntimeException ex) {
                 Logger.getLogger(BindingService.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        receiveSocket.close();
        running = false;
        if (debug) {
            Logger.getLogger(BindingService.class.getName()).log(Level.INFO, "Service thread stopped");
        }
    }

    private void response(DatagramSocket socket, DatagramPacket receivedDatagramPacket) {
        InetAddress clientAddr = receivedDatagramPacket.getAddress();
        int clientPort = receivedDatagramPacket.getPort();
        
        DatagramSocket alternativePortSocket = null;

        try {
            MessageHeader receivedHeader = MessageHeader.create(receivedDatagramPacket.getData());
            if (debug) Logger.getLogger(BindingService.class.getName()).log(Level.INFO, "Received request from "+clientAddr+":"+clientPort+" => "+receivedHeader);
            
            MessageHeader returnHeader;
            if (receivedHeader.getType()!=HeaderType.BINDING_RESPONSE) { // This message there has been forwarded to us, send it back to the client!
            	returnHeader = receivedHeader;
            	returnHeader.setChangeAddress(false); //Make sure we do not loop this message, but sent it back to the client
            	MessageAttribute mappedAddress = receivedHeader.getMessageAttribute(MessageAttribute.MessageAttributeType.MAPPED_ADDRESS);
            	if (mappedAddress==null) return; // We do not know to who to response
            	clientAddr = mappedAddress.getAddress();
            	clientPort = mappedAddress.getPort();
            }
            else if (receivedHeader.getType()==HeaderType.BINDING_REQUEST) {
                returnHeader = createResponse(receivedHeader, clientAddr, clientPort);
            }
            else return; //If not Binding Request I will not response

            //MessageAttribute changeRequest = receivedHeader.getMessageAttribute(MessageAttribute.MessageAttributeType.CHANGE_REQUEST);
            //if (changeRequest==null) return; //If not a Change Request I will not response!

            //Create return header.
            if (returnHeader==null) return; //We will not response
            
            byte buffer[];
            
            if (returnHeader.changeAddress()) {
            	if (alternateAddress==null || alternatePort==0) {
            		StringBuilder msg = new StringBuilder("A change address request was received");
            		msg.append("\nAlternated address or port is not set => "+alternateAddress+":"+alternatePort);
            		msg.append("\nThis server will wrongly response on the NIC and address the message was resived on.");
            		Logger.getLogger(BindingService.class.getName()).log(Level.SEVERE, msg.toString());
            	}
            	else {
	            	//TODO: to be tested
	            	MessageAttribute responseAddress = receivedHeader.getMessageAttribute(MessageAttribute.MessageAttributeType.RESPONSE_ADDRESS);
	            	if (responseAddress!=null) 
	            		returnHeader.addMessageAttribute(responseAddress); //We need to have this with us for the forwarder even it is no applicable in a binding response
	            	buffer = returnHeader.toBytes();
	            	
	            	DatagramPacket out = new DatagramPacket(buffer, buffer.length, alternateAddress, alternatePort);
	                alternativePortSocket = new DatagramSocket();
	                alternativePortSocket.send(out);
	                return;
            	}
            }
            buffer = returnHeader.toBytes();

            //Does the client want the response on a different address or port?
            InetAddress returnAddr = clientAddr;
            int returnPort = clientPort;
            MessageAttribute responseAddress = receivedHeader.getMessageAttribute(MessageAttribute.MessageAttributeType.RESPONSE_ADDRESS);
            if (responseAddress!=null) {
                returnAddr = responseAddress.getAddress();
                returnPort = responseAddress.getPort();
            }
            if (debug) Logger.getLogger(BindingService.class.getName()).log(Level.INFO, "Responding to "+returnAddr+":"+returnPort+" with => "+returnHeader);
            DatagramPacket out = new DatagramPacket(buffer, buffer.length, returnAddr, returnPort);
            if (returnHeader.changePort()) {
                //Create a new socket to change origin port
                alternativePortSocket = new DatagramSocket();
                alternativePortSocket.send(out);
            }
            else {
                //Use the same port we received on
                socket.send(out);
            }
        } catch (IOException ex) {
            Logger.getLogger(BindingService.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            if (alternativePortSocket!=null) alternativePortSocket.close();
        }
    }

    private MessageHeader createResponse(MessageHeader receivedHeader, InetAddress clientAddr, int clientPort) {
        MessageHeader returnHeader = new MessageHeader();
        byte password[] = controllMessageIntegrity(receivedHeader, returnHeader);
        if (returnHeader.getType()!=MessageHeader.HeaderType.NOT_KNOWN) return returnHeader; //Failed Message Integrity check and contain an error response!

        returnHeader = new MessageHeader(MessageHeader.HeaderType.BINDING_RESPONSE);
        returnHeader.setTransactionId(receivedHeader.getTransactionId());

        //Mapped Address attribute
        MessageAttribute attr = MessageAttribute.create(MessageAttribute.MessageAttributeType.MAPPED_ADDRESS, clientAddr, clientPort);
        returnHeader.addMessageAttribute(attr);

        if (receivedHeader.getMessageAttribute(MessageAttribute.MessageAttributeType.RESPONSE_ADDRESS)!=null) {
            //Reflected from attribute
            attr = MessageAttribute.create(MessageAttribute.MessageAttributeType.REFLECTED_FROM, clientAddr, clientPort);
            returnHeader.addMessageAttribute(attr);
        }

        //Change Address attribute
        if (alternateAddress!=null) {
            attr = MessageAttribute.create(MessageAttribute.MessageAttributeType.CHANGED_ADDRESS, alternateAddress, alternatePort);
        }
        else {
            attr = MessageAttribute.create(MessageAttribute.MessageAttributeType.CHANGED_ADDRESS, publicAddress, localPort);
        }
        returnHeader.addMessageAttribute(attr);

        //Source Address attribute
        MessageAttribute changeRequest = receivedHeader.getMessageAttribute(MessageAttribute.MessageAttributeType.CHANGE_REQUEST);
        InetAddress respAddr;
        int respPort;
        if (changeRequest!=null) {
            if (changeRequest.changeAddress()) {
                if (alternateAddress==null) respAddr = publicAddress;
                else respAddr = alternateAddress;
                returnHeader.setChangeAddress(true);
            }
            else respAddr = publicAddress;
            if (changeRequest.changePort()) {
                if (alternatePort==0) respPort = localPort;
                else respPort = alternatePort;
                returnHeader.setChangePort(true);
            }
            else respPort = localPort;
        }
        else {
            respAddr = publicAddress;
            respPort = localPort;
        }
        attr = MessageAttribute.create(MessageAttribute.MessageAttributeType.SOURCE_ADDRESS, respAddr, respPort);
        returnHeader.addMessageAttribute(attr);
        
        if (password!=null) {
            try {
                MessageAttribute messageIntegrityAttr = MessageAttribute.create(MessageAttribute.MessageAttributeType.MESSAGE_INTEGRITY, password, returnHeader.toBytes());
                returnHeader.addMessageAttribute(messageIntegrityAttr);
            } catch (IOException ex) {
                Logger.getLogger(BindingService.class.getName()).log(Level.SEVERE, null, ex);
                MessageAttribute errorCode = MessageAttribute.create(MessageAttribute.MessageAttributeType.ERROR_CODE, Utils.createErrorString(500), 500);
                returnHeader = new MessageHeader(MessageHeader.HeaderType.BINDING_ERROR_RESPONSE);
                returnHeader.addMessageAttribute(errorCode);
                returnHeader.setTransactionId(receivedHeader.getTransactionId());
            }
        }

        return returnHeader;
    }

    /**
     * Will set the address use in a Change Request. The default value is the local address
     * set in the creator. This is usefull if the server is behind a NAT.
     * @param address
     */
    public void setPublicAddress(InetAddress address) {publicAddress = address;}

    public void setDebug(boolean on) {debug = on;}






    private byte[] controllMessageIntegrity(MessageHeader receivedHeader, MessageHeader returnHeader) {
        byte password[] = null;
        if (sharedSecretService!=null) {
            int errorInt = sharedSecretService.controllMessageIntegrity(receivedHeader);
            if (errorInt!=0) {
                returnHeader.setType(MessageHeader.HeaderType.BINDING_ERROR_RESPONSE);
                MessageAttribute errorCode = MessageAttribute.create(MessageAttribute.MessageAttributeType.ERROR_CODE, Utils.createErrorString(errorInt), errorInt);
                returnHeader.addMessageAttribute(errorCode);
                returnHeader.setTransactionId(receivedHeader.getTransactionId());
                return null;
            }
            password = sharedSecretService.getPassword(receivedHeader);
        }
        else if (sharedSecretServiceAddress!=null) {
            SSLSocket sslSocket = null;
            try {
                SSLSocketFactory sslFactory = (SSLSocketFactory)SSLSocketFactory.getDefault();
                sslSocket = (SSLSocket)sslFactory.createSocket(sharedSecretServiceAddress, sharedSecretServicePort);
                sslSocket.startHandshake();

                MessageHeader head = new MessageHeader(receivedHeader);
                head.setType(MessageHeader.HeaderType.SHARED_SECRET_VERIFY_REQUEST);
                head = Utils.socketSendRecive(sslSocket, head);
                MessageAttribute errorCode = head.getMessageAttribute(MessageAttribute.MessageAttributeType.ERROR_CODE);
                MessageAttribute passwordAttr = head.getMessageAttribute(MessageAttribute.MessageAttributeType.PASSWORD);

                if (passwordAttr==null && errorCode==null) {
                    errorCode = MessageAttribute.create(MessageAttribute.MessageAttributeType.ERROR_CODE, Utils.createErrorString(600), 600);
                }

                if (errorCode!=null) {
                    returnHeader.setType(MessageHeader.HeaderType.BINDING_ERROR_RESPONSE);
                    returnHeader.addMessageAttribute(errorCode);
                    returnHeader.setTransactionId(receivedHeader.getTransactionId());
                    return null;
                }

                password = passwordAttr.getPassword();
            } catch (IOException ex) {
                Logger.getLogger(BindingService.class.getName()).log(Level.SEVERE, null, ex);
            } finally {
                if (sslSocket!=null) try{sslSocket.close();}catch(IOException ignore){}
            }
        }
        return password;
    }


    public void uncaughtException(Thread t, Throwable e) {
        System.err.println("Uncaught exception in thread: "+t.getName()+". The thread will die");
         Logger.getLogger(BindingService.class.getName()).log(Level.SEVERE, null, e);
    }
}
