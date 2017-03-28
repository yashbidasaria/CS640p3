package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import java.nio.ByteBuffer;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.*;
import java.util.*;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;
//import edu.wisc.cs.sdn.vnet.PacketMap;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	private Timer timer;
	private Timer timer2;
	/** ARP cache for the router */
	private ArpCache arpCache;
	private int BROADCAST_RIP_IP;
	private byte[] BROADCAST;
	private Map<Integer, RIPNodeEntry> ripNodeMap;
	private ConcurrentHashMap<Integer, List<PacketMap>> arpInfo;	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		this.arpInfo = new ConcurrentHashMap<Integer, List<PacketMap>>();
		this.timer = new Timer();
		this.BROADCAST = new byte[6];
		this.BROADCAST_RIP_IP = IPv4.toIPv4Address("224.0.0.9");
		Arrays.fill(this.BROADCAST, (byte)0xFF);
		this.ripNodeMap = new ConcurrentHashMap<Integer, RIPNodeEntry>();
		this.timer2 = new Timer();
	}
	class RIPNodeEntry {
		public int unit;
		public long time;
		public RIPNodeEntry(int unit, long time){
			this.unit = unit;
			this.time = time;	
		}
	}
class PacketMap {

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


	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}

	/**
	* start RIP. 
	* ASSIGNMENT 3
	**/
	public void startRIP() 
	{
		for (Iface iface : this.interfaces.values()) {
        		int ip = iface.getIpAddress();
			int mask = iface.getSubnetMask();
			int network_addr = mask & ip;
			routeTable.insert(network_addr, 0, mask, iface);
			//send RIP RequestRIPv2.COMMAND_REQUEST
			Ethernet enet = createRIPPacket(iface, BROADCAST_RIP_IP, BROADCAST, RIPv2.COMMAND_REQUEST);
			sendPacket(enet, iface);
		}
		TimerTask task = new RIP_10();
		timer2.schedule(task, 0, 10*1000);

	}
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}



	/**
	* Handle an Ethernet Packet with an ARP Request
	* PART 3A
	**/
	private void generateARPReplies(Ethernet etherPacket, Iface inIface)
	{
		ARP arpPac = (ARP)etherPacket.getPayload();
		// Check if request
		if(arpPac.getOpCode() == ARP.OP_REQUEST) {
			int targetIp = ByteBuffer.wrap(arpPac.getTargetProtocolAddress()).getInt();
			if(targetIp == inIface.getIpAddress()) {
				Ethernet enet = createARPPacket(etherPacket, etherPacket.getSourceMACAddress(), ARP.OP_REPLY, arpPac.getSenderHardwareAddress(), arpPac.getTargetProtocolAddress(), inIface);	
				sendPacket(enet,inIface);
			}
			return;
		}
	}

	private Ethernet createRIPPacket(Iface iface, int destIP, byte[] destMAC, byte rip_type) {
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		UDP udp = new UDP();
		RIPv2 ripv2 = RIPv2create(rip_type, iface);		
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(iface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(destMAC);
		ip.setSourceAddress(iface.getIpAddress());
		ip.setDestinationAddress(destIP);
		ip.setTtl((byte)16);
		ip.setProtocol(IPv4.PROTOCOL_UDP);
		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);
		udp.setPayload(ripv2);
		ip.setPayload(udp);
		ether.setPayload(ip);
		return ether;	
	
	}

	
	private RIPv2 RIPv2create(byte rip_type, Iface iface) {
		RIPv2 rip = new RIPv2();
		rip.setCommand(rip_type);
		if(rip_type == RIPv2.COMMAND_RESPONSE) {
			synchronized(routeTable.getentries()){
				for(RouteEntry entry : routeTable.getentries()) {
					int ip = entry.getDestinationAddress();
					int mask = entry.getMaskAddress();
					RIPv2Entry riPv2Entry = new RIPv2Entry(ip, mask,
							ripNodeMap.get(ip).unit);
					riPv2Entry.setNextHopAddress(iface.getIpAddress());
					rip.addEntry(riPv2Entry);
				}
			}
		}

		return rip;

	}
	/**
	* Create ARP packet and return the Ethernet packet
	**/
	private Ethernet createARPPacket(Ethernet etherPacket, byte[] destMAC, short OP_CODE, byte[] targetHardware, byte[] targetProtocol, Iface inIface) {
		ARP arp = new ARP();
                Ethernet enet = new Ethernet();
                enet.setEtherType(Ethernet.TYPE_ARP);
                enet.setSourceMACAddress(inIface.getMacAddress().toBytes());
                enet.setDestinationMACAddress(destMAC);
                arp.setHardwareType((byte)ARP.HW_TYPE_ETHERNET);
                arp.setProtocolType(ARP.PROTO_TYPE_IP);
                arp.setHardwareAddressLength((byte)Ethernet.DATALAYER_ADDRESS_LENGTH);
                arp.setProtocolAddressLength((byte)4);
                arp.setOpCode(OP_CODE);
                arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
                arp.setSenderProtocolAddress(inIface.getIpAddress());
                arp.setTargetHardwareAddress(targetHardware);
                arp.setTargetProtocolAddress(targetProtocol);
                enet.setPayload(arp);
		System.out.println("ARP Packet created");
		return enet;
	}
	
	/**
	* Handle an ARP Reply. Add the new info to the arpCache, then send the remaining 
	* packets to respective ip address.
	**/
	private void handleARPReply(Ethernet ether) {
		
                ARP arp = (ARP) ether.getPayload();
		byte[] ip = arp.getSenderProtocolAddress();
		byte[] mac = arp.getSenderHardwareAddress();
		arpCache.insert(new MACAddress(mac), IPv4.toIPv4Address(ip));		
		System.out.println("sending RESTT");	
		sendRest(arp);
		

	}

	/**
	* Send the packets with respective the a particular ip address. 
	* After sending the queue from the map created, remove the ip address.
	**/
	private void sendRest(ARP arp) {

		int ip = IPv4.toIPv4Address(arp.getSenderProtocolAddress());
		byte[] mac = arp.getSenderHardwareAddress();
		if(arpInfo.containsKey(ip)) {
			List<PacketMap> queue = arpInfo.get(ip);
			for(PacketMap temp : queue) {
				Ethernet ether = temp.getPacket();
				ether.setDestinationMACAddress(mac);
				sendPacket(ether, temp.getOut());
			}
		arpInfo.remove(ip);
		}
		System.out.println("sending the remaining packets");
				

	}
	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		
		switch(etherPacket.getEtherType())
		{
		case Ethernet.TYPE_IPv4:
			if (!isRIPPacket(etherPacket)){
				this.handleIpPacket(etherPacket, inIface);
				break;
			}
			else{
				handleRIPPacket(etherPacket, inIface);
			}
		case Ethernet.TYPE_ARP:
			this.handleARPPacket(etherPacket, inIface);
		// Ignore all other packet types, for now
		}
		
		/********************************************************************/
	}

	private boolean isRIPPacket(Ethernet ether){
		if (ether.getEtherType() != Ethernet.TYPE_IPv4) {
			return false;
		}
		IPv4 ip = (IPv4) ether.getPayload();
		if (!(ip.getPayload() instanceof UDP)){
			return false;
		}
		UDP udp = (UDP) ip.getPayload();
		if (udp.getDestinationPort() != UDP.RIP_PORT){
			return false;
		}
		return true;
	}
	
	/**
	* Check if ARP packet for reply or request.
	* Call the particular method later.
	**/
	private void handleARPPacket(Ethernet ether, Iface inIface){
		System.out.println("ARP PACKET RECEIVED");
		switch (((ARP) ether.getPayload()).getOpCode()) {
		case ARP.OP_REPLY:
			handleARPReply(ether);
			System.out.println("ARPOPREPLY");
			break;
		case ARP.OP_REQUEST:
			generateARPReplies(ether, inIface);
		}

	}
	private void handleRIPPacket(Ethernet ether, Iface inIface){
		IPv4 ip = (IPv4) ether.getPayload();
		UDP udp = (UDP) ip.getPayload();
		RIPv2 rip = (RIPv2) udp.getPayload();
		if (rip.getCommand() == RIPv2.COMMAND_REQUEST) {
			operateRIPRequest(ip.getSourceAddress(), inIface, ether);
		}
		else if (rip.getCommand() == RIPv2.COMMAND_RESPONSE) {
			operateRIPResponse(rip, inIface, ether);
		}

	}

	private void operateRIPRequest(int sourceAddress, Iface inIface, Ethernet ethernet) {
		Ethernet ether = createRIPPacket(inIface, sourceAddress, BROADCAST, RIPv2.COMMAND_RESPONSE);
		
		byte[] destMAC = getDstMAC(sourceAddress);
		if(destMAC == null) {
			sendARPRequests(ethernet, sourceAddress, inIface, inIface);
		} 
		sendPacket(ether, inIface);
	}

	private void operateRIPResponse(RIPv2 rip, Iface inIface, Ethernet ether){
		int changed = 0;
		for(RIPv2Entry entry : rip.getEntries()) {
			int metric = entry.getMetric();
			int subnetMask = entry.getSubnetMask();
			int address = entry.getAddress();
			int nextHop = entry.getNextHopAddress();
			if (ripNodeMap.containsKey(address)) {
				RIPNodeEntry p = ripNodeMap.get(address);
				if(p.unit > metric + 1) {
					ripNodeMap.remove(address);
					RIPNodeEntry t = new RIPNodeEntry(metric + 1, System.nanoTime());
					ripNodeMap.put(address, t);
					routeTable.update(address, subnetMask, nextHop, inIface);
					changed = -1;
				} 
			}
			else {
				routeTable.insert(address, nextHop, subnetMask, inIface);
				RIPNodeEntry p = new RIPNodeEntry(metric, System.nanoTime());
				ripNodeMap.put(address, p);
			}
		}
		if (changed < 0) {
			for(Iface iface : this.interfaces.values()) {
				Ethernet enet = createRIPPacket(iface, BROADCAST_RIP_IP, BROADCAST,RIPv2.COMMAND_RESPONSE);
			}
		}	
	
	}
	
	/**
	* send ARP requests if the arpCache doesn't contain the respective entry.
	* the request is sent three times, then all the packets with respect to 
	* the ip address are dropped
	**/
	private void sendARPRequests(Ethernet etherPacket, int nextHop, Iface inIface, Iface outIface) {
		int attempts = 3;
		if(arpInfo.containsKey(nextHop)) {
			List<PacketMap> queue = arpInfo.get(nextHop);
			PacketMap temp = new PacketMap(etherPacket, inIface, outIface);
			queue.add(temp);
			arpInfo.remove(nextHop);
			arpInfo.put(nextHop, queue);
		}
		else {
			List<PacketMap> queue = new ArrayList<PacketMap>();
			PacketMap temp = new PacketMap(etherPacket, inIface, outIface);
			queue.add(temp);
			arpInfo.put(nextHop, queue);

		}
		byte[] mac = {0,0,0,0,0,0};
		byte[] ip = IPv4.toIPv4AddressBytes(nextHop);
		Ethernet enet = createARPPacket(etherPacket,BROADCAST, ARP.OP_REQUEST, mac, ip , inIface);
		sendPacket(enet, inIface);
		TimerTask request = new ArpReq(nextHop, outIface, etherPacket);
		timer.schedule(request, 1, 1000);
	}

	/**
	* Drop packets if the corresponding arp reply doesn't come in within the designated time.
	**/
	private void dropARP(int ip) {
		
		if(arpInfo.contains(ip)) {
			List<PacketMap> queue = arpInfo.get(ip);
			for(PacketMap temp : queue) {
				createICMPPacket(temp.getPacket(), temp.getIn(), (byte) 3, (byte) 1);
			}
			arpInfo.remove(ip);
		}

	}
	/**
	* Create an ICMP packet and send it to the interface
	* Different for echo reply.
	**/
	private void createICMPPacket(Ethernet etherPacket, Iface inIface, byte type, byte code){
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        	ipPacket.resetChecksum();
		ipPacket.serialize();		
		Ethernet ether = new Ethernet();
                ether.setEtherType(Ethernet.TYPE_IPv4);
                ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
                int dstAddr = ipPacket.getDestinationAddress();
                RouteEntry bestMatch = this.routeTable.lookup(dstAddr);
                Iface outIface = bestMatch.getInterface();
                ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());
                //IPv4 Header   
                IPv4 ip = new IPv4();
                ip.setTtl((byte)64);
                ip.setProtocol(IPv4.PROTOCOL_ICMP);
                ip.setSourceAddress(inIface.getIpAddress());
                ip.setDestinationAddress(ipPacket.getSourceAddress());
                //ICMP Header
                ICMP icmp = new ICMP();
                icmp.setIcmpType(type);
                icmp.setIcmpCode(code);
		int payloadSize = 4 + ipPacket.getHeaderLength() * 4 + 8;
        	byte [] icmpPayload = new byte [payloadSize];
        	byte [] ipPayload = ipPacket.getPayload().serialize();
		byte[] ip_whole = ipPacket.serialize();
        	icmpPayload[0] = 0;
        	icmpPayload[1] = 0; 
        	icmpPayload[2] = 0; 
        	icmpPayload[3] = 0;
        	
        	for (int i = 0; i < ipPacket.getHeaderLength()*4 + 8; i++){
				icmpPayload[4+i] = ip_whole[i];
        		}
			
		Data data = new Data();
        	data.serialize();
        	data.setData(icmpPayload);
		//Data data = new Data(ar);
                ether.setPayload(ip);
                ip.setPayload(icmp);
                icmp.setPayload(data);
		icmp.setChecksum((short)0);
		icmp.serialize();
			
		sendPacket(ether, inIface);
	//	this.forwardIpPacket(ether, inIface);
	}

	private byte[] getDstMAC(int dstAddr) {
		RouteEntry entry = routeTable.lookup(dstAddr);
		if(entry == null) {
			return null;
		}
		else {
			int nextHop = entry.getGatewayAddress();
			if (nextHop == 0) {
				nextHop = dstAddr;
			}
			ArpEntry arpEntry = this.arpCache.lookup(nextHop);
			if (arpEntry == null) {
				return null;
			}
			return arpEntry.getMac().toBytes();
		}


	}


	/**
	* Send echo reply. 
	**/
	private void createEchoReply(Ethernet etherPacket, Iface inIface) {
	 	IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		ipPacket.resetChecksum();
		ipPacket.serialize();
		Ethernet ether = new Ethernet();
                ether.setEtherType(Ethernet.TYPE_IPv4);
                ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
                int dstAddr = ipPacket.getDestinationAddress();
                //IPv4 Header   
                IPv4 ip = new IPv4();
                ip.setTtl((byte)64);
                ip.setProtocol(IPv4.PROTOCOL_ICMP);
                ip.setSourceAddress(ipPacket.getDestinationAddress());
                ip.setDestinationAddress(ipPacket.getSourceAddress());
                //ICMP Header
                ICMP icmp = new ICMP();
                icmp.setIcmpType((byte)0);
                icmp.setIcmpCode((byte)0);
                Data data = new Data();
		ICMP orig_icmp = (ICMP)ipPacket.getPayload();
                byte[] ar = orig_icmp.serialize();
                data.setData(ar);
                ether.setPayload(ip);
                ip.setPayload(icmp);
                icmp.setPayload(data);
		//ether.setDestinationMACAddress(mac);
		
		sendPacket(ether, inIface);
	}



	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        System.out.println("Handle IP packet");

        // Verify checksum
        short origCksum = ipPacket.getChecksum();
        ipPacket.resetChecksum();
        byte[] serialized = ipPacket.serialize();
        ipPacket.deserialize(serialized, 0, serialized.length);
        short calcCksum = ipPacket.getChecksum();
        if (origCksum != calcCksum)
        { return; }
        
        // Check TTL
	// ASSIGNMENT 3 TIME EXCEEDED
        ipPacket.setTtl((byte)(ipPacket.getTtl()-1));
        if (0 == ipPacket.getTtl())
        {
		createICMPPacket(etherPacket, inIface, (byte)11, (byte)0);
		return; 
	}
        
        // Reset checksum now that TTL is decremented
        ipPacket.resetChecksum();
        
        // Check if packet is destined for one of router's interfaces
        for (Iface iface : this.interfaces.values())
        {
        	if (ipPacket.getDestinationAddress() == iface.getIpAddress())
        	{ 
			byte pac_protocol = ipPacket.getProtocol();
			if(pac_protocol == IPv4.PROTOCOL_UDP || pac_protocol == IPv4.PROTOCOL_TCP) {
				createICMPPacket(etherPacket, inIface, (byte) 3, (byte) 3);
				return;
			}
			else if(pac_protocol == IPv4.PROTOCOL_ICMP) {
				ICMP icmp = (ICMP)ipPacket.getPayload();
				if(icmp.getIcmpType() == 8) {
                                        createEchoReply(etherPacket, inIface);
				}

			} 
		}
        }
		
        // Do route lookup and forward
        this.forwardIpPacket(etherPacket, inIface);
	}


    private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
    {
        // Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
        System.out.println("Forward IP packet");
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        int dstAddr = ipPacket.getDestinationAddress();

        // Find matching route table entry 
        RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

        // If no entry matched, do nothing
	// ASSIGNMENT 3 DESTINATION NET UNREACHABLE
        if (null == bestMatch)
        {
		createICMPPacket(etherPacket, inIface, (byte) 3, (byte) 0);
		return; 
	}

        // Make sure we don't sent a packet back out the interface it came in
        Iface outIface = bestMatch.getInterface();
        if (outIface == inIface)
        { return; }

        // Set source MAC address in Ethernet header
        etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

        // If no gateway, then nextHop is IP destination
        int nextHop = bestMatch.getGatewayAddress();
        if (0 == nextHop)
        { nextHop = dstAddr; }

        // Set destination MAC address in Ethernet header
	// ASSIGNMENT 3 DESTINATION HOST UNREACHABLE
        ArpEntry arpEntry = this.arpCache.lookup(nextHop);
	
        if (null == arpEntry)
        {	
		if(arpInfo.containsKey(nextHop)) {
			List<PacketMap> list = arpInfo.get(nextHop);
			list.add(new PacketMap(etherPacket, inIface, outIface));
			arpInfo.remove(nextHop);
			arpInfo.put(nextHop, list);
			return;
			
		}
		sendARPRequests(etherPacket, nextHop, inIface, outIface);
		return;

	}
	System.out.println("NO NEED FOR ARP");
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        this.sendPacket(etherPacket, outIface);
    }


class ArpReq extends TimerTask {

	int attempts;
	Iface outIface;
	int ip;
	Ethernet etherPacket;

	public ArpReq(int ip, Iface outIface, Ethernet etherPacket) {
		this.attempts = 2;
		this.ip = ip;
		this.outIface = outIface;
		this.etherPacket = etherPacket;
	}

	@Override
	public void run() {
		System.out.println("Waiting for arp reply");
		byte[] broadcast = new byte[6];
		Arrays.fill(broadcast, (byte)0xFF);
		ArpEntry entry = null;
		entry = arpCache.lookup(ip);
		if (entry != null ) {
			System.out.println("got arp reply " + attempts);
			}
		else {
			if (attempts >= 1){
				System.out.println("send another" + attempts);
				//drop Packets
				dropARP(ip);
				cancel();
				byte mac [] = {0,0,0,0,0,0};
				byte[] ar = IPv4.toIPv4AddressBytes(ip);
				Ethernet enet = createARPPacket(etherPacket,broadcast, ARP.OP_REQUEST, mac, ar, outIface);
				sendPacket(enet, outIface);
				attempts--;
				}
			else {
				dropARP(ip);
				cancel();
				}
			}
				
	}

}

class RIP_10 extends TimerTask {


	@Override
	public void run() {
		for (Iface iface : interfaces.values()) {
			//send RIP RequestRIPv2.COMMAND_REQUEST
			Ethernet enet = createRIPPacket(iface, BROADCAST_RIP_IP, BROADCAST, RIPv2.COMMAND_RESPONSE);
			sendPacket(enet, iface);
		}
	}



}

}

