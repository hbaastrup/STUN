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
public class SharedSecretServiceTest {

    public SharedSecretServiceTest() {
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
    public void testSharedSecret() throws Exception {
        File keyStoreFile = new File("StunTest.jks");
        System.setProperty("javax.net.ssl.trustStore", keyStoreFile.getAbsolutePath());
        System.setProperty("javax.net.ssl.trustStoreType", "JKS");
        
        SharedSecretService instance = new SharedSecretService();
        instance.setKeyStore(keyStoreFile, "henriksp".toCharArray(), "henrikkp".toCharArray());
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
            Thread.sleep(5000);

            StunClient client = new StunClient("127.0.0.1");
            SharedSecret secret = client.getSharedSecret();
            assertNotNull("No secret was shared",secret);
            assertTrue("The secret return error: "+secret.getErrorCode()+" ["+secret.getErrorMessage()+"]", secret.getErrorCode()==0);
        }
        finally {
            instance.stop();
        }
    }
}