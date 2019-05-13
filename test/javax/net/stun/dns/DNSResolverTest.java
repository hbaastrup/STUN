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

package javax.net.stun.dns;

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
public class DNSResolverTest {

    public DNSResolverTest() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }


    /**
     * Test of buildQuestion method, of class DNSResolver.
     */
    @Test
    public void testBuildQuestion() {
        byte expResult[] = {
            (byte)0x00,(byte)0x02,(byte)0x01,(byte)0x00,(byte)0x00,(byte)0x01,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x04,(byte)0x70,(byte)0x6F,(byte)0x70,(byte)0x64,(byte)0x02,(byte)0x69,(byte)0x78,(byte)0x06,(byte)0x6E,(byte)0x65,(byte)0x74,(byte)0x63,(byte)0x6F,(byte)0x6D,(byte)0x03,(byte)0x63,(byte)0x6F,(byte)0x6D,(byte)0x00,(byte)0x00,(byte)0x01,(byte)0x00,(byte)0x01
        };

        DNSResolver instance = new DNSResolver("");
        byte resoult[] = instance.buildQuestion("popd.ix.netcom.com", DType.A, DClass.IN);
        assertNotNull("Returned null",resoult);
        assertTrue("Length of resoult is not as excpted",(expResult.length-12)==resoult.length);
        for (int i=0; i<resoult.length; i++) {
            assertTrue("The resoult does not contain excepted data",expResult[12+i]==resoult[i]);
        }
    }

    /**
     * Test of query method, of class DNSResolver.
     */
    @Test
    public void testQuery() throws Exception {
        //DNSResolver instance = new DNSResolver("8.8.8.8"); //Google's public DNS
        //DNSResolver instance = new DNSResolver("192.168.224.251"); //Accanto Systems DNS
        //DNSResolver instance = new DNSResolver("194.97.3.1"); //freenet.de DNS
        //DNSResolver instance = new DNSResolver("64.69.76.4"); //xten.net DNS 1
        DNSResolver instance = new DNSResolver("64.69.76.5"); //xten.net DNS 2
        //Message resoult = instance.query("www.google.com", DType.A, DClass.IN);
        //DMessage resoult = instance.query("google.com", DType.A, DClass.IN);
        //DMessage resoult = instance.query("_stun._udp.google.com", DType.SRV, DClass.IN);
        //DMessage resoult = instance.query("_ldap._tcp.sunriseitaly.sunrisetelecom.com", DType.SRV, DClass.IN);
        //DMessage resoult = instance.query("_stun._udp.freenet.de", DType.SRV, DClass.IN);
        DMessage resoult = instance.query("_stun._udp.xten.net", DType.SRV, DClass.IN);

        DResource questions[] = resoult.getQuestions();
        DResource answers[] = resoult.getAnswers();

        assertNotNull(questions);
        assertNotNull(answers);
        assertTrue("No questions returned.",questions.length>=1);
        assertTrue("No answers returned.", answers.length>=1);

        for (int i=0; i<answers.length; i++) {
            System.out.print(answers[i].getName());
            System.out.print(":   rdata: "+answers[i].getRDataAsString());
            System.out.println("   type: "+answers[i].getDType());
        }

    }
}