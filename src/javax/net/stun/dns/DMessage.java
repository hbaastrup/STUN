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
 *
 * @author Henrik Baastrup
 */
public class DMessage {
    public static final int MAXLENGTH = 65535;
    private byte message[] = new byte[MAXLENGTH];
    private int mLength = 12;

    /*
     * specifies whether this message is a query (false), or a response (true).
     */
    private boolean useQR = false;
    /*
     * Authoritative Answer - this bit is valid in responses,
     * and specifies that the responding name server is an
     * authority for the domain name in question section.
     */
    private boolean useAA = false;
    /*
     * TrunCation - specifies that this message was truncated
     * due to length greater than that permitted on the
     * transmission channel.
     */
    private boolean useTC = false;
    /*
     * Recursion Desired - this bit may be set in a query and
     * is copied into the response. If RD is set, it directs
     * the name server to pursue the query recursively.
     * Recursive query support is optional.
     */
    private boolean useRD = false;
    /*
     * Recursion Available - this be is set or cleared in a
     * response, and denotes whether recursive query support is
     * available in the name server.
     */
    private boolean useRA = false;
    /*
     * Specifies kind of query in this message. This value
     * is set by the originator of a query and copied into
     * the response. The values are:
     *   0 a standard query (QUERY)
     *   1 an inverse query (IQUERY)
     *   2 a server status request (STATUS)
     */
    private int opcode = 0;
    /*
     * Response code - this 4 bit field is set as part of
     * responses. The values have the following
     * interpretation:
     *  0 No error condition
     *  1 Format error - The name server was
     *    unable to interpret the query.
     *  2 Server failure - The name server was
     *    unable to process this query due to a
     *    problem with the name server.
     *  3 Name Error - Meaningful only for
     *    responses from an authoritative name
     *    server, this code signifies that the
     *    domain name referenced in the query does
     *    not exist.
     *  4 Not Implemented - The name server does
     *    not support the requested kind of query.
     *  5 Refused - The name server refuses to
     *    perform the specified operation for
     *    policy reasons. For example, a name
     *    server may not wish to provide the
     *    information to the particular requester,
     *    or a name server may not wish to perform
     *    a particular operation (e.g., zone
     *    transfer) for particular data.
     */
    private int rcode = 0;
    
    private int qdCount = 0;
    private int anCount = 0;
    private int nsCount = 0;
    private int asCount = 0;

    DResource questions[] = new DResource[0];
    DResource answers[] = new DResource[0];
    DResource authorities[] = new DResource[0];
    DResource additionals[] = new DResource[0];

    public void resetMessage() {
        for (int i=0; i<MAXLENGTH; i++) message[i] = 0;
        mLength = 12;
    }

    public void createHeader() {
        long id = System.currentTimeMillis();
        createHeader((int)id);
    }

    public void createHeader(int id) {
        for (int i= 0; i<12; i++) message[i] = 0;
        
        message[0] = (byte) ((id & 0xff00) >> 8);
        message[1] = (byte) (id & 0x00ff);

        message[2] = (byte) ((opcode & 0x0f) << 3);
        if (useQR) message[2] |= 0x80;
        if (useAA) message[2] |= 0x04;
        if (useTC)  message[2] |= 0x02;
        if (useRD)  message[2] |= 0x01;

        message[3] = (byte) (rcode & 0x0f);
        if (useRA) message[3] |= 0x80;
    }

    public void setAA(boolean arg0) {useAA = arg0;}
    public void setTC(boolean arg0) {useTC = arg0;}
    public void setRA(boolean arg0) {useRA = arg0;}

    public void appendQuestion(byte[] buffer) {
        append(buffer);
        qdCount++;
        message[4] = (byte) ((qdCount & 0xff00) >> 8);
        message[5] = (byte) (qdCount & 0x00ff);
    }

    public void appendAnswer(byte[] buffer) {
        append(buffer);
        anCount++;
        message[6] = (byte) ((anCount & 0xff00) >> 8);
        message[7] = (byte) (anCount & 0x00ff);
    }

    public void appendAuthority(byte[] buffer) {
        append(buffer);
        nsCount++;
        message[8] = (byte) ((nsCount & 0xff00) >> 8);
        message[9] = (byte) (nsCount & 0x00ff);
    }

    public void appendAdditional(byte[] buffer) {
        append(buffer);
        asCount++;
        message[10] = (byte) ((asCount & 0xff00) >> 8);
        message[11] = (byte) (asCount & 0x00ff);
    }

    public void append(byte[] buffer) {
        for (int i=0; i<buffer.length; i++) message[mLength++] = buffer[i];
    }

    public byte[] toBytes() {return message;}

    public int length() {return mLength;}

    public DResource[] getQuestions() {return questions;}
    public DResource[] getAnswers() {return answers;}
    public DResource[] getAuthorities() {return authorities;}
    public DResource[] getAdditionals() {return additionals;}

    public static DMessage create(byte buffer[], int length) {
        DMessage retVal = new DMessage();
        retVal.message = new byte[length];
        retVal.mLength = length;
        for (int i=0; i<length; i++) retVal.message[i] = buffer[i];

        //Build Header cetion
        retVal.opcode = (buffer[2] >> 3) & 0x0f;
        retVal.rcode = buffer[3] & 0x0f;

        if ((buffer[2] & 0x80)==0x80) retVal.useQR = true;
        if ((buffer[2] & 0x04)==0x04) retVal.useAA = true;
        if ((buffer[2] & 0x02)==0x02) retVal.useTC = true;
        if ((buffer[2] & 0x01)==0x01) retVal.useRD = true;
        if ((buffer[3] & 0x80)==0x80) retVal.useRA = true;

        retVal.qdCount = ((buffer[4] << 8) + (buffer[5] & 0xFF));
        retVal.anCount = ((buffer[6] << 8) + (buffer[7] & 0xFF));
        retVal.nsCount = ((buffer[8] << 8) + (buffer[9] & 0xFF));
        retVal.asCount = ((buffer[10] << 8) + (buffer[11] & 0xFF));

        //Build Question section
        int idx = 12;
        retVal.questions = new DResource[retVal.qdCount];
        for (int i=0; i<retVal.qdCount; i++) {
            DResource resource = new DResource();
            idx = fillResource(resource, buffer, idx, true);
            retVal.questions[i] = resource;
        }

        //Build Answer section
        retVal.answers = new DResource[retVal.anCount];
        for (int i=0; i<retVal.anCount; i++) {
            DResource resource = new DResource();
            idx = fillResource(resource, buffer, idx, false);
            retVal.answers[i] = resource;
        }

        // Build Authority section
        retVal.authorities = new DResource[retVal.nsCount];
        for (int i=0; i<retVal.nsCount; i++) {
            DResource resource = new DResource();
            idx = fillResource(resource, buffer, idx, false);
            retVal.authorities[i] = resource;
        }

        //Build Additional section
        retVal.additionals = new DResource[retVal.asCount];
        for (int i=0; i<retVal.asCount; i++) {
            DResource resource = new DResource();
            idx = fillResource(resource, buffer, idx, false);
            retVal.additionals[i] = resource;
        }

        return retVal;
    }

    private static int fillResource(DResource resource,  byte buffer[], int start, boolean questionRes) {
        int idx = start;
        int dType = 0;
        int dClass = 0;
        int ttl = 0;
        byte rdata[] = new byte[0];
        String name = "";

        if ((buffer[idx] & 0xc0)==0xc0) { //Name is offseted
            int iName = ((buffer[idx] & 0x3f) << 8) + (buffer[idx+1] & 0xFF);
            idx += 2;
            name = createName(buffer, iName);
        }
        else {
            name =  createName(buffer, idx);
            while (buffer[idx]!=0) idx++;
            idx++;
        }

        dType =((buffer[idx] << 8) + (buffer[idx+1] & 0xFF));
        idx += 2;
        dClass =((buffer[idx] << 8) +(buffer[idx+1] & 0xFF));
        idx += 2;
        if (!questionRes) {
            ttl = (buffer[idx] << 24) + (buffer[idx+1] << 16) + (buffer[idx+2] << 8) + (buffer[idx+3] & 0xFF);
            idx += 4;
            int rdataLen = (((buffer[idx] & 0x3f) << 8) + (buffer[idx+1] & 0xFF));
            rdata = createINRdata(buffer, idx, dType);
            idx += rdataLen+2;
        }

        if (resource!=null) {
            resource.setName(name);
            resource.setDType(dType);
            resource.setDClass(dClass);
            resource.setTTL(ttl);
            resource.setRData(rdata);
        }
        return idx;
    }

    public static String createName(byte buffer[], int start) {
        int idx = start;
        StringBuilder str = new StringBuilder();
        boolean firstRun = true;
        while (idx<buffer.length && buffer[idx]!=0) {
            if ((buffer[idx] & 0xc0)==0xc0) {
                int next = ((buffer[idx] & 0x3f) << 8) + (buffer[idx+1] & 0xFF);
                idx = next;
                continue;
            }

            int len = buffer[idx++];
            char buf[] = new char[len];
            for (int i=0; i<len; i++) buf[i] = (char)buffer[idx++];
            if (firstRun) {
                str.append(buf);
                firstRun = false;
            }
            else {
                str.append('.');
                str.append(buf);
            }
        }
        return str.toString();
    }

    private static byte[] createINRdata(byte buffer[], int start, int dtype) {
        int idx = start;
        boolean bufIsBinary = true;
        switch (dtype) {
            case DType.SRV:
            case DType.A:
                bufIsBinary = true;
                break;

            case DType.NS:
            case DType.CNAME:
                bufIsBinary = false;
                break;
                
            default:
                return new byte[0];
        }

        if (bufIsBinary) {
            int len = ((buffer[idx] << 8) + (buffer[idx+1] & 0xFF));
            idx +=2;

            byte retBuf[] = new byte[len];
            for(int i=0; i<len; i++) retBuf[i] = buffer[idx++];
            return retBuf;
        }

        byte buf[] = new byte[MAXLENGTH/4]; //2 firts bit in length feilds are used for description.
        int bufLen = 0;
        idx += 2;
        while (buffer[idx]!=0) {
            if ((buffer[idx] & 0xc0)==0xc0) {
                int next = ((buffer[idx] & 0x3f) << 8) + (buffer[idx+1] & 0xFF);
                idx = next;
                continue;
            }
            int len = buffer[idx];
            for (int i=0; i<len+1; i++) buf[bufLen++] = buffer[idx++];
       }
       buf[bufLen++] = buffer[idx++];
       byte retBuf[] = new byte[bufLen];
       for (int i=0; i<bufLen; i++) retBuf[i] = buf[i];

       return retBuf;
    }
}
