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
import java.net.InetAddress;
import javax.net.stun.DiscoveryInfo;
import javax.net.stun.SharedSecret;
import javax.net.stun.StunClient;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Henrik Baastrup
 */
public class BindingServiceTest {

    public BindingServiceTest() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * 
     */
    @Test
    public void testBinding() throws Exception {
        byte addr[] = {127,0,0,1};
        InetAddress host = InetAddress.getByAddress(addr);
        DiscoveryInfo info = doBinding(host);
        assertNotNull("Null info was returned", info);
        assertTrue("Binder retorned error: "+info.getErrorCode()+" ["+info.getErrorMessage()+"]", info.getErrorCode()==0);
        assertTrue("Binder returned wrong public address : "+info.getPublicIpAddress(), "127.0.0.1".equals(info.getPublicIpAddress()));
        System.out.println(info);

        host = InetAddress.getLocalHost();
        info = doBinding(host);
        assertNotNull("Null info was returned", info);
        assertTrue("Binder returned error: "+info.getErrorCode()+" ["+info.getErrorMessage()+"]", info.getErrorCode()==0);
        assertTrue("Binder returned wrong public address -> info host: "+info.getPublicIpAddress()+" called host: "+host.getHostAddress(), host.getHostAddress().equals(info.getPublicIpAddress()));
        System.out.println(info);
   }

    @Test
    public void testBindingWithSharedSecret1() throws Exception {
        File keyStoreFile = new File("StunTest.jks");
        System.setProperty("javax.net.ssl.trustStore", keyStoreFile.getAbsolutePath());
        System.setProperty("javax.net.ssl.trustStoreType", "JKS");

        SharedSecretService ssService = new SharedSecretService();
        ssService.setKeyStore(keyStoreFile, "henriksp".toCharArray(), "henrikkp".toCharArray());

        InetAddress host = InetAddress.getLocalHost();
        BindingService bService = new BindingService(host, 0, null, 0, ssService);

        try {
            ssService.start();
            System.out.println("Wait for the Shared Secret Service thread to start");
            int count = 0;
            while (!ssService.isRunning()) {
                Thread.sleep(1000);
                count++;
                if (count>10) fail("The thraed failed to start");
            }
            System.out.println("Shared Secret Service thread started!");

            bService.start();
            System.out.println("Wait for the Binding Service thread to start");
            count = 0;
            while (!bService.isRunning()) {
                Thread.sleep(1000);
                count++;
                if (count>10) fail("The thraed failed to start");
            }
            System.out.println("Binding Service thread started!");

            System.out.println("Set-up the client");
            String addr = host.getCanonicalHostName();
            StunClient client = new StunClient(addr);

            System.out.println("Get secret");
            SharedSecret secret = client.requestSharedSecret();
            assertNotNull("No secret was shared",secret);
            assertTrue("The secret return error: "+secret.getErrorCode()+" ["+secret.getErrorMessage()+"]", secret.getErrorCode()==0);

            System.out.println("Try to do a bind with secret");
            DiscoveryInfo info = client.bindForRemoteAddressOnly(secret);
            assertNotNull("Null info was returned", info);
            assertTrue("Binder returned error: "+info.getErrorCode()+" ["+info.getErrorMessage()+"]", info.getErrorCode()==0);
            assertTrue("Binder returned wrong public address -> info host: "+info.getPublicIpAddress()+" called host: "+host.getHostAddress(), host.getHostAddress().equals(info.getPublicIpAddress()));

            System.out.println("Try to do a bind without a secret (this should return an error)");
            info = client.bindForRemoteAddressOnly(null);
            assertNotNull("Null info was returned", info);
            assertTrue("Binder did not return an error code", info.getErrorCode()!=0);
            System.out.println(info);



            bService.stop();
            Thread.sleep(1000);
            System.out.println("Stopped binding thread");

            bService = new BindingService(host, 0, null, 0, ssService.getAddress(), ssService.getPort());
            bService.start();
            System.out.println("Wait for the Binding Service thread to re-start");
            count = 0;
            while (!bService.isRunning()) {
                Thread.sleep(1000);
                count++;
                if (count>10) fail("The thraed failed to re-start");
            }

            System.out.println("Binding Service thread re-started!");
            System.out.println("Try to do a bind with secret");
            info = client.bindForRemoteAddressOnly(secret);
            assertNotNull("Null info was returned", info);
            assertTrue("Binder returned error: "+info.getErrorCode()+" ["+info.getErrorMessage()+"]", info.getErrorCode()==0);
            assertTrue("Binder returned wrong public address -> info host: "+info.getPublicIpAddress()+" called host: "+host.getHostAddress(), host.getHostAddress().equals(info.getPublicIpAddress()));

            System.out.println("Try to do a bind without a secret (this should return an error)");
            info = client.bindForRemoteAddressOnly(null);
            assertNotNull("Null info was returned", info);
            assertTrue("Binder did not return an error code", info.getErrorCode()!=0);
            System.out.println(info);
        }
        finally {
            ssService.stop();
            bService.stop();
        }
    }

    public DiscoveryInfo doBinding(InetAddress serverAddr) throws Exception {
        BindingService instance = new BindingService(serverAddr, 0, null, 0);
        instance.setDebug(true);
        instance.start();
        try {
            System.out.println("Wait for the servcie thread to start");
            int count = 0;
            while (!instance.isRunning()) {
                Thread.sleep(1000);
                count++;
                if (count>10) fail("The thraed failed to start");
            }
            System.out.println("Servcie thread started!");
            Thread.sleep(1000);

            String addr = serverAddr.getCanonicalHostName();
            StunClient client = new StunClient(addr);
            return client.bindForRemoteAddressOnly(null);
        }
        finally {
            instance.stop();
            Thread.sleep(1000);
        }
    }


}