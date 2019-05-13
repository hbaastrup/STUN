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

/**
 * Constants and functions relating to DNS classes.
 *
 * @author Henrik Baastrup
 */
public class DClass {
    /** Internet */
    public static final int IN = 1;

    /** Chaos network (MIT) */
    public static final int CH = 3;

    /** Chaos network (MIT, alternate name) */
    public static final int CHAOS = 3;

    /** Hesiod name server (MIT) */
    public static final int HS = 4;

    /** Hesiod name server (MIT, alternate name) */
    public static final int HESIOD = 4;

    /** Special value used in dynamic update messages */
    public static final int NONE = 254;

    /** Matches any class */
    public static final int ANY = 255;

}
