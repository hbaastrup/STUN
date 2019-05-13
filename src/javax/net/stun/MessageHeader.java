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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Used internaly by the @{link StunClient}
 * 
 * @author Henrik Baastrup
 */
public class MessageHeader {
    public enum HeaderType {
        NOT_KNOWN,
        BINDING_REQUEST,
        BINDING_RESPONSE,
        BINDING_ERROR_RESPONSE,
        SHARED_SECRET_REQUEST,
        SHARED_SECRET_RESPONSE,
        SHARED_SECRET_ERROR_RESPONSE,
        SHARED_SECRET_VERIFY_REQUEST
    };

    public static final int BINDING_REQUEST = 0x0001;
    public static final int BINDING_RESPONSE = 0x0101;
    public static final int BINDING_ERROR_RESPONSE = 0x0111;
    public static final int SHARED_SECRET_REQUEST = 0x0002;
    public static final int SHARED_SECRET_RESPONSE = 0x0102;
    public static final int SHARED_SECRET_ERROR_RESPONSE = 0x0112;
    public static final int SHARED_SECRET_VERIFY_REQUEST = 0x8102;

    private HeaderType type = HeaderType.NOT_KNOWN;
    byte[] tansactionId = new byte[16];
    ArrayList<MessageAttribute> messageAttributes = new ArrayList<MessageAttribute>();
    private boolean changePort = false;
    private boolean changeAddress = false;

    public MessageHeader() {}

    public MessageHeader(final HeaderType type) {
        this.type = type;
    }

    public MessageHeader(final int type) {
        setType(type);
    }

    public MessageHeader(MessageHeader head) {
        this(head.type);
        this.tansactionId = new byte[head.tansactionId.length];
        for (int i=0; i<head.tansactionId.length; i++) this.tansactionId[i] = head.tansactionId[i];
        for (MessageAttribute attr: head.messageAttributes) {
            MessageAttribute ma = new MessageAttribute(attr);
            this.addMessageAttribute(ma);
        }
    }

    public void setType(HeaderType arg0) {type = arg0;}
    public HeaderType getType() {return type;}

    public void setType(int arg0) {
        switch (arg0) {
            case BINDING_REQUEST:
                type = HeaderType.BINDING_REQUEST;
                break;
            case BINDING_RESPONSE:
                type = HeaderType.BINDING_RESPONSE;
                break;
            case BINDING_ERROR_RESPONSE:
                type = HeaderType.BINDING_ERROR_RESPONSE;
                break;
            case SHARED_SECRET_REQUEST:
                type = HeaderType.SHARED_SECRET_REQUEST;
                break;
            case SHARED_SECRET_RESPONSE:
                type = HeaderType.SHARED_SECRET_RESPONSE;
                break;
            case SHARED_SECRET_ERROR_RESPONSE:
                type = HeaderType.SHARED_SECRET_ERROR_RESPONSE;
                break;
            case SHARED_SECRET_VERIFY_REQUEST:
                type = HeaderType.SHARED_SECRET_VERIFY_REQUEST;
                break;
        }
    }
    public int getTypeAsInt() {
        switch (type) {
            case BINDING_REQUEST: return BINDING_REQUEST;
            case BINDING_RESPONSE: return BINDING_RESPONSE;
            case BINDING_ERROR_RESPONSE: return BINDING_ERROR_RESPONSE;
            case SHARED_SECRET_REQUEST: return SHARED_SECRET_REQUEST;
            case SHARED_SECRET_RESPONSE: return SHARED_SECRET_RESPONSE;
            case SHARED_SECRET_ERROR_RESPONSE: return SHARED_SECRET_ERROR_RESPONSE;
            case SHARED_SECRET_VERIFY_REQUEST: return SHARED_SECRET_VERIFY_REQUEST;
        }
        return 0;
    }

    public List<MessageAttribute> getMessageAttributes() {return messageAttributes;}

    public MessageAttribute getMessageAttribute(MessageAttribute.MessageAttributeType type) {
        for (MessageAttribute attr : messageAttributes) {
            if (attr.getType()==type) return attr;
        }
        return null;
    }

    public void addMessageAttribute(MessageAttribute attribute) {
        messageAttributes.add(attribute);
    }

    public void deleteMessageAttribute(MessageAttribute attribute) {
        messageAttributes.remove(attribute);
    }

    public void clearMessageAttributes() {
        messageAttributes.clear();
    }

    public void genrateTransactionId() {
        long now = System.currentTimeMillis();
        Random rand = new Random();
        int r1 = rand.nextInt();
//        int r2 = rand.nextInt();

//        tansactionId[0] = (byte) ((0xff000000 & r2) >> 24);
//        tansactionId[1] = (byte) ((0x00ff0000 & r2) >> 16);
//        tansactionId[2] = (byte) ((0x0000ff00 & r2) >> 8);
//        tansactionId[3] = (byte) (0x000000ff & r2);
        //To not conflict with RFC-5389 we set the first fields to zerro
        tansactionId[0] = 0;
        tansactionId[1] = 0;
        tansactionId[2] = 0;
        tansactionId[3] = 0;
//        //RFC-5389 magic cookie
//        tansactionId[0] = 0x21;
//        tansactionId[1] = 0x12;
//        tansactionId[2] = (byte)0xa4;
//        tansactionId[3] = 0x42;

        tansactionId[4] = (byte) ((0xff00000000000000L & now) >> 60);
        tansactionId[5] = (byte) ((0x00ff000000000000L & now) >> 52);
        tansactionId[6] = (byte) ((0x0000ff0000000000L & now) >> 44);
        tansactionId[7] = (byte) ((0x000000ff00000000L & now) >> 34);
        tansactionId[8] = (byte) ((0x00000000ff000000L & now) >> 24);
        tansactionId[9] = (byte) ((0x0000000000ff0000L & now) >> 16);
        tansactionId[10] = (byte) ((0x000000000000ff00L & now) >> 8);
        tansactionId[11] = (byte) (0x00000000000000ffL & now);

        tansactionId[12] = (byte) ((0xff000000 & r1) >> 24);
        tansactionId[13] = (byte) ((0x00ff0000 & r1) >> 16);
        tansactionId[14] = (byte) ((0x0000ff00 & r1) >> 8);
        tansactionId[15] = (byte) (0x000000ff & r1);
    }

    public byte[] getTransactionId() {
        byte retArr[] = new byte[tansactionId.length];
        for (int i=0; i<tansactionId.length; i++) retArr[i] = tansactionId[i];
        return retArr;
    }
    public void setTransactionId(byte arg0[]) {
        int len = 16;
        if (arg0.length < 16) len = arg0.length;
        for (int i=0; i<len; i++) tansactionId[i] = arg0[i];
        for (int i=len; i<16; i++) tansactionId[i] = 0;
    }

    public void setChangePort(boolean arg0) {changePort = arg0;}
    public boolean getChangePort() {return changePort;}

    public void setChangeAddress(boolean arg0) {changeAddress = arg0;}
    public boolean getChangeAddress() {return changeAddress;}

    public byte[] toBytes() throws IOException {
        return toBytesExcept(null);
    }

    public byte[] toBytesExcept(MessageAttribute.MessageAttributeType attributeType) throws IOException {
        int len = 0;
        for (MessageAttribute attr : messageAttributes) len += attr.getValueLength()+4;
        if (len > 0xffff) throw new IOException("To many attributes. Message length to long.");

        byte retBytes[] = new byte[len+20];
        for (int i=0; i<retBytes.length; i++) retBytes[i] = 0;

        int intType = getTypeAsInt();
        retBytes[0] = (byte) ((0xff00 & intType) >> 8);
        retBytes[1] = (byte) (0x00ff & intType);

        retBytes[2] = (byte) ((0xff00 & len) >> 8);
        retBytes[3] = (byte) (0x00ff & len);

        for (int i=0; i<16; i++) retBytes[i+4] = tansactionId[i];

        int i = 20;
        for (MessageAttribute attr : messageAttributes) {
            if (attr.getType()==attributeType) continue;
            byte value[] = attr.toBytes();
            for (int j=0; j<value.length; j++) retBytes[i++] = value[j];
        }

        return retBytes;

    }

    public static MessageHeader create(byte buffer[]) throws IOException {
        if (buffer.length < 20) throw new IOException("Buffer to short to be a message.");
        int intType = (0x000000FF & ((int)buffer[0])) << 8;
        intType += (0x000000FF & ((int)buffer[1]));
        MessageHeader header = new MessageHeader(intType);

        byte transId[] = new byte[16];
        for (int i=0; i<16; i++) transId[i] = buffer[4+i];
        header.setTransactionId(transId);

        int length = (0x000000FF & ((int)buffer[2])) << 8;
        length += (0x000000FF & ((int)buffer[3]));

        int i = 20;
        while ((i-20) < (length)) {
            int t = (0x000000FF & ((int)buffer[i++])) << 8;
            t += (0x000000FF & ((int)buffer[i++]));

            int l = (0x000000FF & ((int)buffer[i++])) << 8;
            l += (0x000000FF & ((int)buffer[i++]));
            byte b[] = new byte[l];
            for (int j=0; j<l; j++) b[j] = buffer[i++];
            header.addMessageAttribute(new MessageAttribute(t, b));
        }

        return header;
    }

    public int integrityCheck(byte password[]) {
        MessageAttribute messageIntegrity = getMessageAttribute(MessageAttribute.MessageAttributeType.MESSAGE_INTEGRITY);
        if (messageIntegrity==null) return 401;

        byte headerBytes[];
        try {
            headerBytes = toBytes();
        } catch (IOException ex) {
            return 400;
        }

        if (type==HeaderType.SHARED_SECRET_VERIFY_REQUEST) {
            //The origin was a Bindeing request
            headerBytes[0] = 0;
            headerBytes[1] = 1;
        }

        byte recievedHmac[] = messageIntegrity.toBytes();
        //To calculate hmac we need the whole message except the MESSAGE-INTEGRITY attribute
        byte hmacHeaderPart[] = new byte[headerBytes.length-recievedHmac.length];
        for (int i=0; i<hmacHeaderPart.length; i++) hmacHeaderPart[i] = headerBytes[i];
        byte hmacCalc[] = Utils.hmac(password, hmacHeaderPart);
        if (hmacCalc.length+4 != recievedHmac.length) return 431;
        for (int i=0; i<hmacCalc.length; i++) if (hmacCalc[i]!=recievedHmac[i+4]) return 431;
        return 0;
    }
}
