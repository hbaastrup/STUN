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

import javax.net.stun.Utils;
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
public class UtilsTest {

    public UtilsTest() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    @Test
    public void testHmac() throws Exception {
        System.out.println("Test hmac");
        byte expResult1[] = {(byte)0x4f,(byte)0x4c,(byte)0xa3,(byte)0xd5,(byte)0xd6,(byte)0x8b,(byte)0xa7,(byte)0xcc,(byte)0x0a,(byte)0x12,(byte)0x08,(byte)0xc9,(byte)0xc6,(byte)0x1e,(byte)0x9c,(byte)0x5d,(byte)0xa0,(byte)0x40,(byte)0x3c,(byte)0x0a};
        byte expResult2[] = {(byte)0x09,(byte)0x22,(byte)0xd3,(byte)0x40,(byte)0x5f,(byte)0xaa,(byte)0x3d,(byte)0x19,(byte)0x4f,(byte)0x82,(byte)0xa4,(byte)0x58,(byte)0x30,(byte)0x73,(byte)0x7d,(byte)0x5c,(byte)0xc6,(byte)0xc7,(byte)0x5d,(byte)0x24};
        byte expResult3[] = {(byte)0xbc,(byte)0xf4,(byte)0x1e,(byte)0xab,(byte)0x8b,(byte)0xb2,(byte)0xd8,(byte)0x02,(byte)0xf3,(byte)0xd0,(byte)0x5c,(byte)0xaf,(byte)0x7c,(byte)0xb0,(byte)0x92,(byte)0xec,(byte)0xf8,(byte)0xd1,(byte)0xa3,(byte)0xaa};

        byte key[] = new byte[64];
        for (int i=0; i<64; i++) key[i] = (byte)i;
        String text = "Sample #1";
        byte hmac[] = Utils.hmac(key, text.getBytes());
        assertTrue(hmac!=null);
        assertTrue(hmac.length==20);
        assertArrayEquals(expResult1, hmac);

        key = new byte[20];
        for (int i=0; i<20; i++) key[i] = (byte)(0x30+i);
        text = "Sample #2";
        hmac = Utils.hmac(key, text.getBytes());
        assertTrue(hmac!=null);
        assertTrue(hmac.length==20);
        assertArrayEquals(expResult2, hmac);

        key = new byte[100];
        for (int i=0; i<100; i++) key[i] = (byte)(0x50+i);
        text = "Sample #3";
        hmac = Utils.hmac(key, text.getBytes());
        assertTrue(hmac!=null);
        assertTrue(hmac.length==20);
        assertArrayEquals(expResult3, hmac);

        System.out.println("Done");
    }

}