import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.Ethernet;



public class PacketMap {

	private	Ethernet ether;
	private Iface inIface;
	private Iface outIface;

	public PacketMap(Ethernet ether, Iface inIface, Iface outIface) {
		this.ether = ether;
		this.inIface = inIface;
		this.outIface = outIface;
	}

	public Ethernet getPacket() {
		return this.ether;
	}
	
	public Iface getIn() {
		return this.inIface;
	}

	public Iface getOut() {
		return this.outIface;
	}
}
 
