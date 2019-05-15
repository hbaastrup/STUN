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
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Contain the information that the client discovered from the {@link StunClient#binding} method.
 *
 * @author Henrik Baastrup
 */
public class DiscoveryInfo {
    /**
     * Description of the found scenario.
     */
    public enum ConnectionScenario {
        NOT_KNOWN,
        UDP_BLOCKED,
        SYMMETRIC_FIREWALL,
        OPEN_INTERNET,
        FULL_CONE_NAT,
        SYMMETRIC_NAT,
        RESTRICTED_PORT_NAT,
        RESTRICTED_CORNE_NAT
    }

    private ConnectionScenario scenario = ConnectionScenario.NOT_KNOWN;
    private String publicIpAddress = "";
    private byte publicIpAddressAsBytes[];
    private List<String> localIpAddresses = null;
    private boolean nodeNatted = false;
    private int errorCode = 0;
    private String errorMessage = null;

    public void setScenario(final ConnectionScenario arg0) {scenario = arg0;}
    public ConnectionScenario getScenarioState() {return scenario;}

    public void setPublicIpAddress(final InetAddress arg0) {
        publicIpAddress = arg0.getHostAddress();
        publicIpAddressAsBytes = arg0.getAddress();
    }
    public String getPublicIpAddress() {return publicIpAddress;}
    public byte[] getPublicIpAddressAsBytes() {
        byte retArr[] = new byte[publicIpAddressAsBytes.length];
        for (int i=0; i<publicIpAddressAsBytes.length; i++) retArr[i] = publicIpAddressAsBytes[i];
        return retArr;
    }
    
    public void setLocalIpAddresses(List<InetAddress> arg0) {
    	if (arg0==null) return;
    	if (localIpAddresses==null) localIpAddresses = new ArrayList<>();
    	for(InetAddress addr : arg0)
    		localIpAddresses.add(addr.getHostAddress());
    }
    public List<String> getLocalIpAddresses() {return localIpAddresses;}
    
    public void setNodeNated(final boolean arg0) {nodeNatted = arg0;}
    public boolean isNodeNated() {return nodeNatted;}

    public void setErrorCode(final MessageAttribute arg0) {
        if (arg0.getType()!=MessageAttribute.MessageAttributeType.ERROR_CODE) return;
        final byte value[] = arg0.getValue();
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

    public void setError(final int code, final String message) {
        errorCode = code;
        errorMessage = message;
    }

    public int getErrorCode() {return errorCode;}
    public String getErrorMessage() {return errorMessage;}

    @Override
    public String toString() {
        return toString(false);
    }

    // To the explanation below see also http://en.wikipedia.org/wiki/NAT
    public String toString(boolean details) {
        final StringBuilder str = new StringBuilder();

        if (errorCode > 0) {
            return "ERROR: Code: "+errorCode+" ["+errorMessage+"]";
        }

        if (nodeNatted) str.append("Noded natted:\n");
        else str.append("Node not natted:\n");
        switch (scenario) {
            case NOT_KNOWN:
                str.append("  Scenario could not be detected\n");
                break;
            case UDP_BLOCKED:
                str.append("  UDP trafic is blocked\n");
                return str.toString();
            case SYMMETRIC_FIREWALL:
                str.append("  Node is behind a Symmetric Firewall\n");
                if (details) {
                    str.append("   - Each request from the same internal IP address and port to a specific destination IP address\n");
                    str.append("     and port is mapped to a unique external source IP address and port, if the same internal host\n");
                    str.append("     sends a packet even with the same source address and port but to a different destination, a\n");
                    str.append("     different mapping is used.");
                    str.append("   - Only an external host that receives a packet from an internal host can send a packet back.\n");
                }
                break;
            case OPEN_INTERNET:
                str.append("  Node is connected to the open Internet\n");
                break;
            case FULL_CONE_NAT:
                str.append("  Node is behind a Full Cone NAT\n");
                if (details) {
                    str.append("   - Once an internal address (iAddr:iPort) is mapped to an external address (eAddr:ePort), any packets\n");
                    str.append("     from iAddr:iPort will be sent through eAddr:ePort.\n");
                    str.append("   - Any external host can send packets to iAddr:iPort by sending packets to eAddr:ePort.\n");
                }
                break;
            case SYMMETRIC_NAT:
                str.append("  Node is behind a Symmetric NAT\n");
                if (details) {
                    str.append("   - Each request from the same internal IP address and port to a specific destination IP address and port\n");
                    str.append("     is mapped to a unique external source IP address and port, if the same internal host sends a packet even\n");
                    str.append("     with the same source address and port but to a different destination, a different mapping is used.\n");
                    str.append("   - Only an external host that receives a packet from an internal host can send a packet back.\n");
                }
                break;
            case RESTRICTED_PORT_NAT:
                str.append("  Node is behind a Restricted Port NAT\n");
                if (details) {
                    str.append("   - Once an internal address (iAddr:iPort) is mapped to an external address (eAddr:ePort), any packets from\n");
                    str.append("     iAddr:iPort will be sent through eAddr:ePort.\n");
                    str.append("   - An external host (hAddr:hPort) can send packets to iAddr:iPort by sending packets to eAddr:ePort\n");
                    str.append("     only if iAddr:iPort has previously sent a packet to hAddr:hPort..\n");
                }
                break;
            case RESTRICTED_CORNE_NAT:
                str.append("  Node is behind a Restricted Cone NAT\n");
                if (details) {
                    str.append("   - Once an internal address (iAddr:iPort) is mapped to an external address (eAddr:ePort), any packets from\n");
                    str.append("     iAddr:iPort will be sent through eAddr:ePort.\n");
                    str.append("   - An external host (hAddr:any) can send packets to iAddr:iPort by sending packets to eAddr:ePort only if\n");
                    str.append("     iAddr:iPort has previously sent a packet to hAddr:any. \"Any\" means the port number doesn't matter.\n");
                }
               break;
        }
        str.append("  with public IP address: "+publicIpAddress+"\n");
        if (localIpAddresses!=null) {
        	str.append("  and local IP addresses: \n");
        	for (String addr : localIpAddresses)
        		str.append("  - "+addr+"\n");
        }

        return str.toString();
    }
}
