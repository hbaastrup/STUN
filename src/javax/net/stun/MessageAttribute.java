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
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Used internaly by the @{link StunClient}
 * 
 * @author Henrik Baastrup
 */
public class MessageAttribute {
    public enum MessageAttributeType {
        MAPPED_ADDRESS,
        RESPONSE_ADDRESS,
        CHANGE_REQUEST,
        SOURCE_ADDRESS,
        CHANGED_ADDRESS,
        USERNAME,
        PASSWORD,
        MESSAGE_INTEGRITY,
        ERROR_CODE,
        UNKNOWN_ATTRIBUTES,
        REFLECTED_FROM
    };

    public static final int MAPPED_ADDRESS = 0x0001;
    public static final int RESPONSE_ADDRESS = 0x0002;
    public static final int CHANGE_REQUEST = 0x0003;
    public static final int SOURCE_ADDRESS = 0x0004;
    public static final int CHANGED_ADDRESS = 0x0005;
    public static final int USERNAME = 0x0006;
    public static final int PASSWORD = 0x0007;
    public static final int MESSAGE_INTEGRITY = 0x0008;
    public static final int ERROR_CODE = 0x0009;
    public static final int UNKNOWN_ATTRIBUTES = 0x000a;
    public static final int REFLECTED_FROM = 0x000b;


    private MessageAttributeType type = MessageAttributeType.UNKNOWN_ATTRIBUTES;
    private byte value[];

    public MessageAttribute(final MessageAttributeType type, final byte value[]) {
        this.type = type;
        if (value==null) this.value = new byte[0];
        else {
            setValue(value);
        }
    }

    public MessageAttribute(final int type, final byte value[]) {
        setType(type);
        if (value==null) this.value = new byte[0];
        else {
            setValue(value);
        }
     }

    public MessageAttribute(MessageAttribute attr) {
        this(attr.type, attr.value);
    }

    public MessageAttributeType getType() {return type;}
    public byte[] getValue() {
        if (value==null) return null;
        byte retArr[] = new byte[value.length];
        for (int i=0; i<value.length; i++) retArr[i] = value[i];
        return retArr;
    }
    public void setValue(byte arg0[]) {
        this.value = new byte[arg0.length];
        for (int i=0; i<arg0.length; i++) this.value[i] = arg0[i];
    }
    public String getValueAsString() { return new String(value);}
    public int getValueLength() {return value.length;}


    public InetAddress getAddress() {
        if (type==MessageAttributeType.MAPPED_ADDRESS || type==MessageAttributeType.CHANGED_ADDRESS) {
            if (value.length<8) return null;
            byte addrBuf[] = new byte[4];
            for (int i=0; i<4; i++) addrBuf[i] = value[i+4];
            InetAddress addr = null;
            try {
                addr = InetAddress.getByAddress(addrBuf);
            } catch (UnknownHostException ex) {
                return null;
            }
            return addr;
        }
        return null;
    }

    public String getAddressAsString() {
        if (type==MessageAttributeType.MAPPED_ADDRESS || type==MessageAttributeType.CHANGED_ADDRESS) {
            if (value.length<8) return null;
            byte addrBuf[] = new byte[4];
            for (int i=0; i<4; i++) addrBuf[i] = value[i+4];
            String retStr = String.valueOf((0x0FF & ((int)addrBuf[0])))+"."+String.valueOf((0x0FF & ((int)addrBuf[1])))+"."+String.valueOf((0x0FF & ((int)addrBuf[2])))+"."+String.valueOf((0x0FF & ((int)addrBuf[3])));
            return retStr;
        }
        return null;
    }

    public int getPort() {
        if (type==MessageAttributeType.MAPPED_ADDRESS || type==MessageAttributeType.CHANGED_ADDRESS) {
            if (value.length < 4) return 0;
            int p = (0x000000FF & ((int)value[2])) << 8;
            p += (0x000000FF & ((int)value[3]));
            return p;
        }
        return 0;
    }

    public String getUsername() {
        if (type==MessageAttributeType.USERNAME) {
            if (value.length<1) return null;
            String str = null;
            try {
                str = new String(value, "UTF-8");
            } catch (UnsupportedEncodingException ex) {
               ex.printStackTrace();
            }
            return str;
        }
        return null;
    }

    public byte[] getPassword() {
        if (type==MessageAttributeType.PASSWORD) {
            if (value.length<1) return null;
            return getValue();
        }
        return null;
    }

    public byte[] getHMAC() {
        if (type==MessageAttributeType.MESSAGE_INTEGRITY) {
            return getValue();
        }
        return null;
    }

    public void setHMAC(byte arg0[]) {
        if (type==MessageAttributeType.MESSAGE_INTEGRITY) {
            value = new byte[arg0.length];
            for (int i=0; i<arg0.length; i++) value[i] = arg0[i];
        }
    }

    public boolean isNothingChanged() {
        if (type==MessageAttributeType.CHANGE_REQUEST) {
            if (value.length<4) return false;
            if (value[3]==0) return true;
        }
        return true;
    }

    public boolean isPortChanged() {
        if (type==MessageAttributeType.CHANGE_REQUEST) {
            if (value.length<4) return false;
            if ((value[3] & 2)==2) return true;
        }
        return false;
    }

    public boolean isAddressChanged() {
        if (type==MessageAttributeType.CHANGE_REQUEST) {
            if (value.length<4) return false;
            if ((value[3] & 4)==4) return true;
        }
        return false;
    }

    public final void setType(final int arg0) {
        switch (arg0) {
            case MAPPED_ADDRESS:
                type = MessageAttributeType.MAPPED_ADDRESS;
                break;
            case RESPONSE_ADDRESS:
                type = MessageAttributeType.RESPONSE_ADDRESS;
                break;
            case CHANGE_REQUEST:
                type = MessageAttributeType.CHANGE_REQUEST;
                break;
            case SOURCE_ADDRESS:
                type = MessageAttributeType.SOURCE_ADDRESS;
                break;
            case CHANGED_ADDRESS:
                type = MessageAttributeType.CHANGED_ADDRESS;
                break;
            case USERNAME:
                type = MessageAttributeType.USERNAME;
                break;
            case PASSWORD:
                type = MessageAttributeType.PASSWORD;
                break;
            case MESSAGE_INTEGRITY:
                type = MessageAttributeType.MESSAGE_INTEGRITY;
                break;
            case ERROR_CODE:
                type = MessageAttributeType.ERROR_CODE;
                break;
            case UNKNOWN_ATTRIBUTES:
                type = MessageAttributeType.UNKNOWN_ATTRIBUTES;
                break;
            case REFLECTED_FROM:
                type = MessageAttributeType.REFLECTED_FROM;
                break;
        }
    }

    public int getTypeAsInt() {
        switch (type) {
            case MAPPED_ADDRESS: return MAPPED_ADDRESS;
            case RESPONSE_ADDRESS: return RESPONSE_ADDRESS;
            case CHANGE_REQUEST: return CHANGE_REQUEST;
            case SOURCE_ADDRESS: return SOURCE_ADDRESS;
            case CHANGED_ADDRESS: return CHANGED_ADDRESS;
            case USERNAME: return USERNAME;
            case PASSWORD: return PASSWORD;
            case MESSAGE_INTEGRITY: return MESSAGE_INTEGRITY;
            case ERROR_CODE: return ERROR_CODE;
            case UNKNOWN_ATTRIBUTES: return UNKNOWN_ATTRIBUTES;
            case REFLECTED_FROM: return REFLECTED_FROM;
        }
        return 0;
    }

    public byte[] toBytes() {
        byte retBytes[] = new byte[value.length+4];

        int intType = getTypeAsInt();
        retBytes[0] = (byte) ((0xff00 & intType) >> 8);
        retBytes[1] = (byte) (0x00ff & intType);

        retBytes[2] = (byte) ((0xff00 & value.length) >> 8);
        retBytes[3] = (byte) (0x00ff & value.length);

        for (int i=0; i<value.length; i++) retBytes[i+4] = value[i];

        return retBytes;
    }


    public static MessageAttribute create(MessageAttributeType type, int arg0) {
        byte value[];
        switch (type) {
            case CHANGE_REQUEST:
                value = new byte[4];
                value[0] = 0;
                value[1] = 0;
                value[2] = 0;
                value[3] = (byte)(arg0 & 0x06);
                break;

            default:
                return null;
        }
        return new MessageAttribute(type, value);
    }

    public static MessageAttribute create(MessageAttributeType type, Object arg0, int arg1) {
        byte value[];
        switch (type) {
            case ERROR_CODE:
                StringBuilder errMesg = new StringBuilder((String)arg0);
                for (int i=0; i<(errMesg.length()%4); i++) errMesg.append(' ');

                byte errMesgBytes[] = errMesg.toString().getBytes();
                value = new byte[errMesgBytes.length+4];
                value[0] = 0;
                value[1] = 0;
                value[2] = (byte)(arg1/100);
                value[3] = (byte)(arg1%100);
                for (int i=0; i<errMesgBytes.length; i++) value[i+4] = errMesgBytes[i];
                break;

            case MAPPED_ADDRESS:
            case RESPONSE_ADDRESS:
            case CHANGED_ADDRESS:
            case SOURCE_ADDRESS:
            case REFLECTED_FROM:
                value = new byte[8];
                value[0] = 0; //Empty
                value[1] = 0x01; //Family
                value[2] = (byte) ((arg1 & 0xff00) >> 8);
                value[3] = (byte) (arg1 & 0x00ff);
                byte clientIp[] = ((InetAddress)arg0).getAddress();
                for (int i=0; i<4; i++) value[4+i] = clientIp[i];
                break;

            case CHANGE_REQUEST:
                return create(type, arg1);

            case USERNAME:
                StringBuilder user = new StringBuilder((String)arg0);
                for (int i=0; i<(user.length()%4); i++) user.append(' ');
                value = user.toString().getBytes();
                break;

            case PASSWORD:
                byte password[] = (byte[])arg0;
                value = new byte[password.length + password.length%4];
                for (int i=0; i<password.length; i++) value[i] = password[i];
                for (int i=password.length; i<(password.length + password.length%4); i++) value[i] = 0;
                break;

            default:
                return null;

        }
        return new MessageAttribute(type, value);
    }

    public static MessageAttribute create(MessageAttributeType type, Object arg0, Object arg1) {
        byte value[];
        switch (type) {
            case MESSAGE_INTEGRITY:
                byte password[] = (byte[])arg0;
                byte body[] = (byte[])arg1;
                // We are going to patch the header length as we are going to
                // add the Integrity attribute later on
                int len = (0x000000FF & ((int)body[2])) << 8;
                len += (0x000000FF & ((int)body[3]));
                len += 24; //Length of Integrity attribute
                body[2] = (byte) ((len & 0xff00) >> 8);
                body[3] = (byte) (len & 0xff);

                value = Utils.hmac(password, body);
                break;

            default:
                return null;

        }
        return new MessageAttribute(type, value);
    }
}
