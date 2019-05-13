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

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;

/**
 *
 * @author Henrik Baastrup
 */
public class DNSResolver {
    private static final int MAX_UDP_MESSAGE_LENGTH = 512;

    private String serverAddress;
    private int serverPort = 53;

    private int requestTimeout = 10000;

    public DNSResolver(final String dnsIpAddress) {
        serverAddress =  dnsIpAddress;
    }

    public DMessage query(String domain, int dtype, int dclass) throws IOException {
        DMessage message = new DMessage();
        message.resetMessage();
        message.setRA(true);
        message.createHeader();

        message.appendQuestion(buildQuestion(domain, dtype, dclass));

        if (message.length()>MAX_UDP_MESSAGE_LENGTH) {
            //TODO send by TCP
        }

        DatagramSocket sock = null;
        try {
            InetAddress addr =  InetAddress.getByName(serverAddress);
            sock = new DatagramSocket();
            sock.setReuseAddress(true);
            DatagramPacket out = new DatagramPacket(message.toBytes(), message.length(), addr, serverPort);
            sock.send(out);

            byte buffer[] = new byte[DMessage.MAXLENGTH];
            DatagramPacket in = new DatagramPacket(buffer, buffer.length);
            sock.setSoTimeout(requestTimeout);
            try {
                sock.receive(in);
            } catch (SocketTimeoutException ex) {
                return null;
            }

            int len = in.getLength();
            message = DMessage.create(in.getData(), len);
        } finally {
            if (sock!=null) sock.close();
        }
        return message;
    }

    public byte[] buildQuestion(String domain, int dtype, int dclass) {
        String labels[] = domain.split("\\.");
        byte question[] = new byte[domain.length()+2+4];
        int qPtr = 0;
        for (int i=0; i<labels.length; i++) {
            question[qPtr++] = (byte)labels[i].length();
            byte labelBytes[] = labels[i].getBytes();
            for (int j=0; j<labelBytes.length; j++) question[qPtr++] = labelBytes[j];
        }
        question[qPtr++] = 0;

        question[qPtr++] = (byte)((dtype & 0xff00) >> 8);
        question[qPtr++] = (byte)(dtype & 0x00ff);

        question[qPtr++] = (byte)((dclass & 0xff00) >> 8);
        question[qPtr++] = (byte)(dclass & 0x00ff);

        return question;
    }
}
