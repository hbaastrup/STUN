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
public class DResource {
    private String name = null;
    private int dtype = 0;
    private int dclass = 0;
    private int ttl = 0;
    private byte rdata[] = null;

    public void setName(String arg0) {name = arg0;}
    public String getName(){return name;}
    
    public void setDType(int arg0) {dtype = arg0;}
    public int getDType() {return dtype;}

    public void setDClass(int arg0) {dclass = arg0;}
    public int getDClass() {return dclass;}

    public void setTTL(int arg0) {ttl = arg0;}
    public int getTTL() {return ttl;}

    public void setRData(byte arg0[]) {
        rdata = new byte[arg0.length];
        for (int i=0; i<arg0.length; i++) rdata[i] = arg0[i];
    }
    public byte[] getRaDta() {
        byte retArr[] = new byte[rdata.length];
        for (int i=0; i<rdata.length; i++) retArr[i] = rdata[i];
        return retArr;
    }

    public String getIpAddress() {
        if (dtype!=DType.A) return "";
        StringBuilder str = new StringBuilder();
        boolean firstRun = true;
        for (int i=0; i<rdata.length; i++) {
            if (firstRun) firstRun = false;
            else str.append('.');
            str.append(Integer.toString(rdata[i] & 0xFF));
        }
        return str.toString();
    }

    public int getPriority() {
        if (dtype!=DType.SRV) return -1;
        return ((rdata[0] & 0xFF) << 8) + (rdata[1] & 0xFF);
    }

    public int getWeight() {
        if (dtype!=DType.SRV) return -1;
        return ((rdata[2] & 0xFF) << 8) + (rdata[3] & 0xFF);
    }

    public int getPort() {
        if (dtype!=DType.SRV) return -1;
        return ((rdata[4] & 0xFF) << 8) + (rdata[5] & 0xFF);
    }

    public String getTarget() {
        if (dtype!=DType.SRV) return "";
        return DMessage.createName(rdata, 6);
    }

    public String getRDataAsString() {
        if (rdata==null) return "";

        switch (dtype) {
            case DType.A:
                return getIpAddress();

            case DType.NS:
            case DType.CNAME:
                return DMessage.createName(rdata, 0);

            case DType.SRV:
                int priority = getPriority();
                int weight = getWeight();
                int port = getPort();
                String target = getTarget();
                return "Priority:"+priority+"   Weight:"+weight+"   Port:"+port+"   Target:"+target;

            default:
                return "";
        }
    }

}
