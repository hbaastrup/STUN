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

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.stun.services.BindingService;
import javax.net.stun.services.SharedSecretService;

/**
 *
 * @author Henrik Baastrup
 */
public class Main {
    public static final int DEFAULT_STUN_PORT = 3478;

    enum RunMode {
        CLIENT,
        SERVER,
        FORWARDER
    }

    private static void help() {
        System.out.println("java -jar stun.jar [options]");
        System.out.println("Options:");
        System.out.println("  -S: run as STUN server.");
        System.out.println("  -server host: set the STUN server to query (default stun.l.google.com).");
        System.out.println("  -port number: set the port for the STUN serve (default 19302).");
        System.out.println("  -remoteserver host: set the remote Shared Secret server address.");
        System.out.println("  -remoteport number: set the port for used by the Shared Secret serve (default 3478).");
        System.out.println("  -dns ip: use DNS descovery. The server argument contains the domain.");
        System.out.println("  -serveraddr host: set the services address (default localhost)");
        System.out.println("  -keystore file: path to key-store. If used the client will request a");
        System.out.println("                  Shared Secret. In server mode the Shared Secre service");
        System.out.println("                  is activated.");
        System.out.println("  -keystorepw password: password for key-store.");
        System.out.println("  -alternateaddr IP address: will start a server using the given IP address.");
        System.out.println("  -alternateport port: port to use with the alternate address.");
        System.out.println("  -debug: turn debug information on.");
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        int stunPort = DEFAULT_STUN_PORT;
        //String stunAddr = "stun1.voiceeclipse.net";
        String stunAddr = "stun.mit.de";
        //String stunAddr = "localhost";
    	//int stunPort = 19302;
        //String stunAddr = "stun1.l.google.com";
        String remoteServerAddr = null;
        int remoteServerPort = DEFAULT_STUN_PORT;
        String dnsServer = null;
        File keyStoreFile = null;
        String keyStorePassword = "henrikkp";
        String alternateAddr = null;
        String serverAddr = "localhost";
        int alternatePort = 0;
        RunMode runAs = RunMode.CLIENT;
        boolean debug = false;

        for (int i=0; i<args.length; i++) {
            if ("-h".equals(args[i])) {
                help();
                return;
            }
            else if ("-S".equals(args[i])) runAs = RunMode.SERVER;
            else if ("-F".equals(args[i])) runAs = RunMode.FORWARDER;
            else if ("-server".equals(args[i])) {
                i++;
                stunAddr = args[i];
            }
            else if("-port".equals(args[i])) {
                i++;
                stunPort = Integer.parseInt(args[i]);
            }
            else if ("-remoteserver".equals(args[i])) {
                i++;
                remoteServerAddr = args[i];
            }
            else if ("-remoteport".equals(args[i])) {
                i++;
                remoteServerPort = Integer.parseInt(args[i]);
            }
            else if ("-alternateaddr".equals(args[i])) {
                i++;
                alternateAddr = args[i];
            }
            else if("-alternateport".equals(args[i])) {
                i++;
                alternatePort = Integer.parseInt(args[i]);
            }
            else if("-serveraddr".equals(args[i])) {
                i++;
                serverAddr = args[i];
            }
            else if ("-dns".equals(args[i])) {
                i++;
                dnsServer = args[i];
            }
            else if ("-keystore".equals(args[i])) {
                i++;
                keyStoreFile = new File(args[i]);
            }
            else if("-keystorepw".equals(args[i])) {
                i++;
                keyStorePassword = args[i];
            }
            else if ("-debug".equals(args[i])) {
                debug = true;
            }
            else {
                System.out.println("ERROR: Wrong argument: "+args[i]+". Try to use the -h argument");
            }
        }

        if (runAs==RunMode.CLIENT) {
        	System.out.println("STUN client by Henrik Baastrup Copyrigth (C) 2010");
            StunServerAddress stunServers[];
            if (dnsServer!=null) {
                stunServers = StunClient.discovery(stunAddr, dnsServer);
            }
            else {
                stunServers = new StunServerAddress[1];
                stunServers[0] = new StunServerAddress();
                stunServers[0].address = stunAddr;
                stunServers[0].port = stunPort;
            }
            for (int i=0; i<stunServers.length; i++) {
                StunClient client = new StunClient(stunServers[i].address, stunServers[i].port);
                client.debug = debug;

                SharedSecret secret = null;
                if (keyStoreFile!=null) {
                    System.setProperty("javax.net.ssl.keyStore", keyStoreFile.getAbsolutePath());
                    System.setProperty("javax.net.ssl.keyStoreType", "JKS");
                    System.setProperty("javax.net.ssl.keyStorePassword", keyStorePassword);
                    secret = client.requestSharedSecret();
                    if (secret!=null) {
	                    if (secret.hasError()) {
	                    	System.out.println("The client tried to obtain a Shared Secret form server but failed: ");
	                    	System.out.println("- "+ secret);
	                    	System.out.println("The client will continue without Shared Secret");
	                    }
	                    else
	                    	System.out.println(secret.toString());
                    }
                }
                
                DiscoveryInfo info = client.binding(secret);
                System.out.println("Last test was: "+client.getBindingTestDoneAsString());
                System.out.println(info);
            }
        }
        else if (runAs==RunMode.SERVER) {
        	System.out.println("STUN server by Henrik Baastrup Copyrigth (C) 2010");
            BindingService bService = null;
            SharedSecretService ssService = null;

            try {
                //InetAddress localhost = Utils.getLocalAddress();
                InetAddress localhost = InetAddress.getByName(serverAddr);
                
                //If we have a key-store file we will support the Shared Secret services
                if (keyStoreFile!=null) {
                    ssService = new SharedSecretService(localhost, stunPort);
                    ssService.setDebug(debug);
                    ssService.setKeyStore(keyStoreFile, keyStorePassword.toCharArray(), keyStorePassword.toCharArray());
                    ssService.start();
                }

                //If we are behind a NAT firewall we have to find our own public address first
                StunClient client = new StunClient(stunAddr, stunPort);
                DiscoveryInfo info = client.bindForRemoteAddressOnly(null);
                if (info.getErrorCode()!=0) {
                    System.out.println(info);
                    return;
                }
                byte[] remoteAddrBytes = info.getPublicIpAddressAsBytes();
                InetAddress remoteAddr = null;
                if (remoteAddrBytes!=null)
                	remoteAddr = InetAddress.getByAddress(remoteAddrBytes);

                InetAddress alternateAddress = null;
                if (alternateAddr!=null) {
                    alternateAddress = InetAddress.getByName(alternateAddr);
                }
                
                if (remoteServerAddr!=null) {
                    InetAddress ssAddr = InetAddress.getByName(remoteServerAddr);
                    bService = new BindingService(localhost, stunPort, alternateAddress, alternatePort, ssAddr, remoteServerPort);
                }
                else
                    bService = new BindingService(localhost, stunPort, alternateAddress, alternatePort, ssService);
                bService.setDebug(debug);
                if (remoteAddr!=null) bService.setPublicAddress(remoteAddr);
                bService.start();

                //Wait for our services to start
                boolean proceedOk = false;
                while (!proceedOk) {
                    Thread.sleep(1000);
                    proceedOk = bService.isRunning();
                    if (ssService!=null) proceedOk = proceedOk && ssService.isRunning();
                }

                //Wait for ever
                proceedOk = true;
                while (proceedOk) {
                    Thread.sleep(1000);
                    proceedOk = bService.isRunning();
                    if (ssService!=null) proceedOk = proceedOk && ssService.isRunning();
                }

            } catch (IOException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InterruptedException ex) {
            } finally {
                if (ssService!=null) ssService.stop();
                if (bService!=null) bService.stop();
            }
        }
    }

}
