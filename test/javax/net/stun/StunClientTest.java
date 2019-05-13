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
public class StunClientTest {
    //String testDnsServer = "8.8.8.8";
    //String testDomainAddress = "google.com";
    String testDnsServer = "64.69.76.5";
    String testDomainAddress = "xten.net";
    SharedSecret sharedSecret = null;
    boolean debugInfoOn = true;

//    String stunAddr = "stun.sipgate.net"; //OK double address
//    int stunPort = 10000;

    int stunPort = 3478;
//    String stunAddr = "jstun.javawi.de"; //OK double address
    String stunAddr = "stun1.voiceeclipse.net"; //OK double address
//    String stunAddr = "iphone-stun.freenet.de"; //OK double address
//    String stunAddr = "larry.gloo.net"; //Does not response
//    String stunAddr = "stun.xten.net"; //No double address (should not be able to detect Symmetric NAT)
//    String stunAddr = "stun.counterpath.com"; //same address as above!
//    String stunAddr = "72.14.234.104"; //google.com
/*
provserver.televolution.net
sip1.lakedestiny.cordiaip.com
stun1.voiceeclipse.net
stun01.sipphone.com
stun.callwithus.com
stun.counterpath.net
stun.endigovoip.com
stun.ekiga.net (alias for stun01.sipphone.com)
stun.ideasip.com (no XOR_MAPPED_ADDRESS support)
stun.internetcalls.com
stun.ipns.com
stun.noc.ams-ix.net
stun.phonepower.com
stun.phoneserve.com
stun.rnktel.com
stun.softjoys.com (no DNS SRV record) (no XOR_MAPPED_ADDRESS support)
stunserver.org see their usage policy
stun.sipgate.net
stun.sipgate.net:10000
stun.stunprotocol.org
stun.voip.aebc.com
stun.voipbuster.com (no DNS SRV record) (no XOR_MAPPED_ADDRESS support)
stun.voxalot.com
stun.voxgratia.org (no DNS SRV record) (no XOR_MAPPED_ADDRESS support)
stun.xten.com
numb.viagenie.ca (http://numb.viagenie.ca) (XOR_MAPPED_ADDRESS only with rfc3489bis magic number in transaction ID)
stun.ipshka.com inside UA-IX zone russsian explanation at http://www.ipshka.com/main/help/hlp_stun.php
*/

    public StunClientTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }


    @Test
    public void testDiscovery() throws Exception {
        System.out.println("\nTest discovery");
        StunClient.staticDebug = debugInfoOn;
        StunServerAddress resoult[] = StunClient.discovery(testDomainAddress, testDnsServer);

        assertNotNull("Returned null resoult",resoult);
        assertTrue("returned a zerror length resoult", resoult.length>0);

        for (int i=0; i<resoult.length; i++) {
            System.out.println(resoult[i]);
        }
    }

//    @Test
//    public void testGetSharedSecret() {
//        System.out.println("\nTest getSharedSecret");
//        StunClient instance = new StunClient(stunAddr, stunPort);
//        instance.debug = debugInfoOn;
//        sharedSecret = instance.getSharedSecret();
//
//        assertNotNull("No shared secret was found", sharedSecret);
//        assertTrue("Returned error code: "+sharedSecret.getErrorCode()+" ["+sharedSecret.getErrorMessage()+"]", sharedSecret.getErrorCode()==0);
//
////        List expResult = null;
////        List result = instance.getSharedSecret();
////        assertEquals(expResult, result);
////        // TODO review the generated test code and remove the default call to fail.
////        fail("The test case is a prototype.");
//    }

    @Test
    public void testBindForRemoteAddressOnly() {
        System.out.println("\nTest Bind For Remote Address  Only");
        StunClient instance = new StunClient(stunAddr, stunPort);
        instance.debug = debugInfoOn;
        DiscoveryInfo result = instance.bindForRemoteAddressOnly(sharedSecret);
        System.out.println(result);
    }

    @Test
    public void testBinding() {
        System.out.println("\nTest binding");
        StunClient instance = new StunClient(stunAddr, stunPort);
        instance.debug = debugInfoOn;
        DiscoveryInfo result = instance.binding(sharedSecret);
        System.out.println("Last test was: "+instance.getBindingTestDoneAsString());
        System.out.println(result.toString(true));
    }
}