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

import java.io.Serializable;
import java.util.Comparator;

/**
 *
 * @author Henrik Baastrup
 */
public class DResourceComparator implements Comparator<DResource>, Serializable {

    public int compare(DResource o1, DResource o2) {
        if (o1.getPriority() < o2.getPriority()) return -1;
        else if (o1.getPriority() > o2.getPriority()) return 1;
        else if (o1.getWeight() < o2.getWeight()) return -1;
        else if (o1.getWeight() > o2.getWeight()) return 1;
        return 0;
    }

}
