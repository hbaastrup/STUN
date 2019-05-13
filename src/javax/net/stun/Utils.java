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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;

/**
 *
 * @author Henrik Baastrup
 */
public class Utils {
    /**
     * Internal used.
     * @param key
     * @param text
     * @return
     */
    public static byte[] hmac(byte key[], byte text[]) {
        return hmac(key, text, 64);
    }

    /**
     * Internal used.
     * @param key
     * @param text
     * @param blockSize
     * @return
     */
    public static byte[] hmac(byte key[], byte text[], int blockSize) {
        byte key0[];
        if (key.length==blockSize) key0 = key;
        else if (key.length < blockSize) {
            key0 = new byte[blockSize];
            for (int i=0; i<key.length; i++) key0[i] = key[i];
            for (int i=key.length; i<blockSize; i++) key0[i] = 0;
        }
        else {
            byte h[] = hash(key);
            key0 = new byte[blockSize];
            int len = blockSize;
            if (h.length<blockSize) len = h.length;
            for (int i=0; i< len; i++) key0[i] = h[i];
            for (int i=len; i<blockSize; i++) key0[i] = 0;
        }

        byte ipad[] = new byte[key0.length];
        for (int i=0; i<key0.length; i++) ipad[i] = (byte) (key0[i] ^ 0x36);

        byte res[] = new byte[ipad.length + text.length];
        for (int i=0; i<ipad.length; i++) res[i] = ipad[i];
        for (int i=0; i<text.length; i++) res[i+ipad.length] = text[i];
        byte h[] = hash(res);

        byte opad[] = new byte[key0.length];
        for (int i=0; i<key0.length; i++) opad[i] = (byte) (key0[i] ^ 0x5c);

        res = new byte[opad.length+h.length];
        for (int i=0; i<opad.length; i++) res[i] = opad[i];
        for (int i=0; i<h.length; i++) res[i+opad.length] = h[i];

        h = hash(res);

//        System.out.print("hmac: ");
//        for (int i=0; i<h.length; i++) System.out.print(Integer.toString( ( h[i] & 0xff ) + 0x100, 16).substring( 1 ));
//        System.out.println("");
//        System.out.print("key: ");
//        for (int i=0; i<key.length; i++) System.out.print(Integer.toString( ( key[i] & 0xff ) + 0x100, 16).substring( 1 ));
//        System.out.println("");
//        System.out.print("text: ");
//        for (int i=0; i<text.length; i++) System.out.print(Integer.toString( ( text[i] & 0xff ) + 0x100, 16).substring( 1 ));
//        System.out.println("");

        return h;
    }

    private static byte[] hash(byte input[]) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            return null;
        }

        md.update(input);
        byte digest[] = md.digest();
        return digest;
    }

    /**
     * Internal used.
     * @param errorCode
     * @return
     */
    public static String createErrorString(int errorCode) {
        switch (errorCode) {
            case 0:
                return "";
            case 401:
                return "(Unauthorized): The Binding Request did not contain a MESSAGEINTEGRITY attribute.";
            case 420:
                return "(Unknown Attribute): The server did not understand a mandatory attribute in the request.";
            case 430:
                return "(Stale Credentials): The Binding Request did contain a MESSAGEINTEGRITY attribute, but it used a shared secret that has expired. The client should obtain a new shared secret and try again.";
            case 431:
                return "(Integrity Check Failure): The Binding Request contained a MESSAGE-INTEGRITY attribute, but the HMAC failed verification. This could be a sign of a potential attack, or client implementation error.";
            case 432:
                return "(Missing Username): The Binding Request contained a MESSAGEINTEGRITY attribute, but not a USERNAME attribute. Both must be present for integrity checks.";
            case 433:
                return "(Use TLS): The Shared Secret request has to be sent over TLS, but was not received over TLS.";
            case 500:
                return "(Server Error): The server has suffered a temporary error. The client should try again.";
            case 600:
                return "(Global Failure:) The server is refusing to fulfill the request. The client should not retry.";
            case 400:
            default:
                return "(Bad Request): The request was malformed. The client should not retry the request without modification from the previous attempt.";
        }
    }

    /**
     * Will try to find the local IP V4 address there is not the loopback address
     * @return
     * @throws SocketException local IPV4 address.
     */
    public static InetAddress getLocalAddr() throws SocketException {
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
        while (interfaces.hasMoreElements()) {
            NetworkInterface dev=interfaces.nextElement();
            String devName = dev.getDisplayName();
            Enumeration<InetAddress> addresses = dev.getInetAddresses();
            while (addresses.hasMoreElements()) {
                InetAddress addr=addresses.nextElement();
                if (addr instanceof Inet6Address) continue; //STUN might not be intresting with an IP V6 address
                String addrStr = addr.getHostAddress();
                if (addrStr.startsWith("127."))continue;
                return addr;
            }
        }
        return null;
    }

    public static MessageHeader socketSendRecive(Socket sock, MessageHeader header) throws IOException {
        OutputStream outStream = null;
        InputStream inStream = null;
        byte message[] = null;

        try {
            inStream = sock.getInputStream();
            outStream = sock.getOutputStream();

            outStream.write(header.toBytes());

            //get the message headder
            byte headerBuf[] = new byte[20];
            int bufLen = 20;
            int read = 0;
            while (read<20) {
                int r = inStream.read(headerBuf, read, bufLen);
                if (r < 0) break;
                bufLen -= r;
                read += r;
            }

            //find message length
            if (headerBuf.length<4) throw new IOException("The header is not long enof to extract the Message Length");
            int mesgLength = (0x000000FF & ((int)headerBuf[2])) << 8;
            mesgLength +=(0x000000FF & ((int) headerBuf[3]));

            //get the message body
            message = new byte[mesgLength+20];
            bufLen = mesgLength;
            read = 20;
            while (read<mesgLength) {
                int r = inStream.read(message, read, bufLen);
                if (r < 0) break;
                bufLen -= r;
                read += r;
            }
            for (int i=0; i<20; i++) message[i] = headerBuf[i];

        } finally {
            if (inStream!=null) inStream.close();
            if (outStream!=null) outStream.close();
        }
        return MessageHeader.create(message);
    }
}
