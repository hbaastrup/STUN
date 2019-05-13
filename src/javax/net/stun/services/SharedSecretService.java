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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.Thread.UncaughtExceptionHandler;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.stun.MessageAttribute;
import javax.net.stun.MessageHeader;
import javax.net.stun.Utils;

/**
 *
 * @author Henrik Baastrup
 */
public class SharedSecretService implements Runnable,UncaughtExceptionHandler {
    private boolean running = false;
    private SSLServerSocket serverSocket = null;
    private Thread thread = null;

    private InetAddress address = null;
    private int port = 3478;

    private File keyStoreFile = null;
    private char keyStorePassword[] = null;
    private char keyPassword[] = null;

    private ArrayList<UserHolder> users = new ArrayList<UserHolder>();

    private boolean debug = false;

    public SharedSecretService() {

    }

    public SharedSecretService(final int port) {
        if (port!=0) this.port = port;
    }

    public SharedSecretService(final InetAddress localAddress, final int port) {
        this(port);
        this.address = localAddress;
    }

    @Override
    protected void finalize() throws Throwable {
        stopThread();
        super.finalize();
    }
    
    public List<UserHolder> getUsers() {
        synchronized (users) {
            return new ArrayList<UserHolder>(users);
        }
    }

    public InetAddress getAddress() {return address;}

    public int getPort() {return port;}

    /**
     * Set the keystore to use for TLS. A call to this method will override
     * the javax.net.ssl.trustStore, javax.net.ssl.trustStoreType and
     * javax.net.ssl.trustStorePassword System properties,
     * javax.net.ssl.trustStore property is set to the abeolute path of
     * the file passed, the javax.net.ssl.keyStoreType is set to JKS and
     * the javax.net.ssl.trustStorePassword is set to the given password.<br>
     * Use this method if you use a private keystore conting the certificate for
     * the TLS sessions. Default keystores are:<br>
     * {java.home}/lib/security/jssecacerts.<br>
     * [java.home]/lib/security/cacerts<br>
     *
     * @param arg0 Filepath to keystore file
     * @param arg1 password for keystore
     * @param arg2 password for key
     */
    public void setKeyStore(File arg0, char arg1[], char arg2[]) {
        keyStoreFile = arg0;
        keyStorePassword = new char[arg1.length];
        for (int i=0; i<arg1.length; i++) keyStorePassword[i] = arg1[i];
        keyPassword = new char[arg2.length];
        for (int i=0; i<arg2.length; i++) keyPassword[i] = arg2[i];
    }

    /**
     *
     * @return true if the local thread is running and the service is listin to a socket.
     */
    public boolean isRunning() {return running;}

    public void startThread() {
        if (running) return;
        thread = new Thread(this, "Shared Secret Service Thread");
        thread.setUncaughtExceptionHandler(this);
        thread.start();
    }

    public void stopThread() {
        running = false;
        if (serverSocket!=null) {
            synchronized (serverSocket) {
                serverSocket.notifyAll();
            }
        }
        thread = null;
    }

    public void run() {
        if (debug) {
            Logger.getLogger(SharedSecretService.class.getName()).log(Level.INFO, "Service thread start with following parameters:");
            Logger.getLogger(SharedSecretService.class.getName()).log(Level.INFO, "  Listein on port: "+port);
            if (keyStoreFile!=null) {
                Logger.getLogger(SharedSecretService.class.getName()).log(Level.INFO, "  Using the key-store file: "+keyStoreFile.getAbsolutePath());
            }
            else {
                Logger.getLogger(SharedSecretService.class.getName()).log(Level.INFO, "  With no key-store file!");
            }
        }
        running = true;
        SSLContext sslContext = null;
        FileInputStream keyStoreIn = null;
        try {
            if (address==null) address = Utils.getLocalAddr();

            if (keyStoreFile!=null) {
                KeyStore keyStore = KeyStore.getInstance("JKS");
                keyStoreIn = new FileInputStream(keyStoreFile);
                keyStore.load(keyStoreIn, keyStorePassword);
                keyStoreIn.close();
                keyStoreIn = null;
                KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                kmf.init(keyStore, keyPassword);
                sslContext = SSLContext.getInstance("SSLv3");
                sslContext.init(kmf.getKeyManagers(), null, null);
            }

            SSLServerSocketFactory sslFactory;
            if (sslContext != null) {
                sslFactory = sslContext.getServerSocketFactory();
            }
            else {
                sslFactory = (SSLServerSocketFactory)SSLServerSocketFactory.getDefault();
            }
            serverSocket = (SSLServerSocket)sslFactory.createServerSocket(port, 10, address);
            serverSocket.setSoTimeout(30000);
//            String cipherSuites[] = {"TLS_RSA_WITH_AES_128_CBC_SHA","TLS_DHE_RSA_WITH_AES_128_CBC_SHA","TLS_DHE_DSS_WITH_AES_128_CBC_SHA"}; //Only TLS Cipher Suites
//            serverSocket.setEnabledCipherSuites(cipherSuites);
            
            while (running) {
                try {
                    Socket sock;
                    try {
                        sock = serverSocket.accept();
                        if (!running) break;
                        read(sock);
                    } catch (SocketTimeoutException ex) {
                        cleanUpUsers();
                        continue;
                    }
                } catch (RuntimeException ex) {
                    Logger.getLogger(SharedSecretService.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        } catch (GeneralSecurityException ex) {
            Logger.getLogger(SharedSecretService.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(SharedSecretService.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            if (keyStoreIn!=null) try{keyStoreIn.close();}catch(IOException ignore){}
            if (serverSocket!=null) try{serverSocket.close();}catch(IOException ignore){}
        }
        running = false;
    }

    public void setDebug(boolean arg0) {debug = arg0;}



    public int controllMessageIntegrity(MessageHeader receivedHeader) {
        MessageAttribute username = receivedHeader.getMessageAttribute(MessageAttribute.MessageAttributeType.USERNAME);
        MessageAttribute messageIntegrity = receivedHeader.getMessageAttribute(MessageAttribute.MessageAttributeType.MESSAGE_INTEGRITY);
        byte password[] = getPassword(receivedHeader);

        if (username==null) {
            return 432;
        }
        else if (messageIntegrity==null) {
            return 401;
        }
        else if (password==null) {
            return 430;
        }
        
        int errorInt = receivedHeader.integrityCheck(password);
        return errorInt;
    }

    public byte[] getPassword(MessageHeader header) {
        MessageAttribute username = header.getMessageAttribute(MessageAttribute.MessageAttributeType.USERNAME);

        if (username==null) return null;

        UserHolder userHolder = null;
        List<UserHolder> userList = getUsers();
        for (UserHolder uh: userList) {
            if (uh.username.equals(username.getUsername())) {
                userHolder = uh;
                break;
            }
        }
        if (userHolder==null) return null;

        return userHolder.password;
    }





    private void read(Socket sock) {
        if (debug) {
            InetAddress clientAddr = sock.getInetAddress();
            Logger.getLogger(SharedSecretService.class.getName()).log(Level.INFO, "Recived a connect from: "+clientAddr);
        }
        InputStream in = null;
        OutputStream out = null;
        try {
            in = sock.getInputStream();
            out = sock.getOutputStream();

            byte head[] = new byte[20];
            int bytesRead = 0;
            while (bytesRead<20) {
                int r = in.read(head, 0, 20);
                if (r < 0) return;
                bytesRead += r;
            }
            int length = (0x000000FF & ((int)head[2]))<<8;
            length += (0x000000FF & ((int)head[3]));

            byte buffer[] = new byte[length];
            int read = 0;
            while (read<length) {
                int r = in.read(buffer, read, length);
                read += r;
            }

            byte headBuffer[] = new byte[length+20];
            for (int i=0; i<20; i++) headBuffer[i] = head[i];
            for (int i=0; i<length; i++) headBuffer[i+20] = buffer[i];

            MessageHeader recHeader = MessageHeader.create(headBuffer);
            MessageHeader retHeader;
            if (recHeader.getType()!=MessageHeader.HeaderType.SHARED_SECRET_REQUEST && recHeader.getType()!=MessageHeader.HeaderType.SHARED_SECRET_VERIFY_REQUEST) {
                retHeader = new MessageHeader(MessageHeader.HeaderType.SHARED_SECRET_ERROR_RESPONSE);
                retHeader.setTransactionId(recHeader.getTransactionId());
                MessageAttribute errorCode = MessageAttribute.create(MessageAttribute.MessageAttributeType.ERROR_CODE, Utils.createErrorString(400), 400);
                retHeader.addMessageAttribute(errorCode);
                out.write(retHeader.toBytes());
                return;
            }

            UserHolder userHolder = UserHolder.create();
            synchronized (users) {
                users.add(userHolder);
            }

            if (recHeader.getType()==MessageHeader.HeaderType.SHARED_SECRET_VERIFY_REQUEST) {
                //This is a message integrity veryfy request!
                int errCod = controllMessageIntegrity(recHeader);
                if (errCod!=0) {
                    retHeader = new MessageHeader(MessageHeader.HeaderType.SHARED_SECRET_ERROR_RESPONSE);
                    MessageAttribute errorCode = MessageAttribute.create(MessageAttribute.MessageAttributeType.ERROR_CODE, Utils.createErrorString(errCod), errCod);
                    retHeader.addMessageAttribute(errorCode);
                }
                else {
                    byte passwd[] = getPassword(recHeader);
                    if (passwd==null) {
                        retHeader = new MessageHeader(MessageHeader.HeaderType.SHARED_SECRET_ERROR_RESPONSE);
                        MessageAttribute errorCode = MessageAttribute.create(MessageAttribute.MessageAttributeType.ERROR_CODE, Utils.createErrorString(430), 430);
                        retHeader.addMessageAttribute(errorCode);
                    }
                    else {
                        //If all is OK we response with a password attribute so the requesting server
                        //can construct a Integrity message
                        retHeader = new MessageHeader(MessageHeader.HeaderType.SHARED_SECRET_RESPONSE);
                        MessageAttribute attr = MessageAttribute.create(MessageAttribute.MessageAttributeType.PASSWORD, passwd, 0);
                        retHeader.addMessageAttribute(attr);
                    }
                }
            }
            else {
                //Default response: A shared secret response with Username and
                //Password attributes.
                retHeader = new MessageHeader(MessageHeader.HeaderType.SHARED_SECRET_RESPONSE);
                MessageAttribute attr = MessageAttribute.create(MessageAttribute.MessageAttributeType.USERNAME, userHolder.username, 0);
                retHeader.addMessageAttribute(attr);
                attr = MessageAttribute.create(MessageAttribute.MessageAttributeType.PASSWORD, userHolder.password, 0);
                retHeader.addMessageAttribute(attr);
            }
            out.write(retHeader.toBytes());
        } catch (IOException ex) {
            Logger.getLogger(SharedSecretService.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            if (in!=null) try {in.close();}catch(IOException ignore){}
            if (out!=null) try{out.close();}catch(IOException ignore){}
            try{sock.close();}catch(IOException ignore){}
        }
    }

    private void cleanUpUsers() {
        long now = System.currentTimeMillis();
        synchronized (users) {
            ArrayList<UserHolder> usersToDelete = new ArrayList<UserHolder>();
            for (UserHolder uh: users) {
                if ((now - uh.created)>600000) usersToDelete.add(uh);
            }
            for (UserHolder uh: usersToDelete) users.remove(uh);
        }
    }

    public void uncaughtException(Thread t, Throwable e) {
        System.err.println("Uncaught exception in thread: "+t.getName()+". The thread will die");
        Logger.getLogger(SharedSecretService.class.getName()).log(Level.SEVERE, null, e);
    }
}
