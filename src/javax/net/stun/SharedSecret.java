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

import java.io.UnsupportedEncodingException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Shared Secret optained from the STUN server by the @{linkStunClient#getSharedSecret} method.
 * 
 * @author Henrik Baastrup
 */
public class SharedSecret {
    private String username = null;
    private byte password[] = null;
    private int errorCode = 0;
    private String errorMessage = null;

    /**
     * Cerator used with sucessfuly response from the STUN server.
     * @param username
     * @param password
     */
    public SharedSecret(final String username, final byte password[]) {
        this.username = username;
        this.password = new byte[password.length];
        for (int i=0; i<password.length; i++) this.password[i] = password[i];
    }

    /**
     * Creator used with error response from the STUN server.
     * @param code
     * @param message
     */
    public SharedSecret(final int code, final String message) {
        this.errorCode = code;
        this.errorMessage = message;
    }

    /**
     * Creator used with error response from the STUN server.
     * @param code
     * @param message
     */
    public SharedSecret(final MessageAttribute attribute) {
        if (attribute.getType()!=MessageAttribute.MessageAttributeType.ERROR_CODE) return;
        final byte value[] = attribute.getValue();
        if (value.length < 4) return;
        errorCode = value[2] << 8;
        errorCode += value[3];
        if (value.length > 4) {
            try {
                errorMessage = new String(value, 4, value.length - 4, "UTF8");
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(SharedSecret.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    public String getUsername() {return username;}

    public byte[] getPassword() {
        byte retArr[] = new byte[password.length];
        for (int i=0; i<password.length; i++) retArr[i] = password[i];
        return retArr;
    }

    public int getErrorCode() {return errorCode;}

    public String getErrorMessage() {return errorMessage;}
}
