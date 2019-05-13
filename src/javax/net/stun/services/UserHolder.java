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

import java.util.Random;
import javax.net.stun.Utils;

/**
 *
 * @author Henrik Baastrup
 */
public class UserHolder {
    private static  Random random = null;
    public String username;
    public byte password[];
    public long created = System.currentTimeMillis();

    public static UserHolder create() {
        UserHolder retUser = new UserHolder();
        long now = System.currentTimeMillis();

        StringBuilder user = new StringBuilder("USER-"+Long.toHexString(now));
        for (int i=0; i<user.length()%4; i++) user.append('0');
        retUser.username = user.toString();

        if (random==null) random = new Random(now);
        long rand = random.nextLong();

        byte key[] = new byte[8];
        key[0] = (byte) ((0xff00000000000000L & rand) << 56);
        key[1] = (byte) ((0x00ff000000000000L & rand) << 48);
        key[2] = (byte) ((0x0000ff0000000000L & rand) << 40);
        key[3] = (byte) ((0x000000ff00000000L & rand) << 32);
        key[4] = (byte) ((0x00000000ff000000L & rand) << 24);
        key[5] = (byte) ((0x0000000000ff0000L & rand) << 16);
        key[6] = (byte) ((0x000000000000ff00L & rand) << 8);
        key[7] = (byte) (0x00000000000000ffL & rand);

        byte text[] = new byte[8];
        text[0] = (byte) ((0xff00000000000000L & now) << 56);
        text[1] = (byte) ((0x00ff000000000000L & now) << 48);
        text[2] = (byte) ((0x0000ff0000000000L & now) << 40);
        text[3] = (byte) ((0x000000ff00000000L & now) << 32);
        text[4] = (byte) ((0x00000000ff000000L & now) << 24);
        text[5] = (byte) ((0x0000000000ff0000L & now) << 16);
        text[6] = (byte) ((0x000000000000ff00L & now) << 8);
        text[7] = (byte) (0x00000000000000ffL & now);

        retUser.password = Utils.hmac(key, text, 8);

        return retUser;
    }
}
